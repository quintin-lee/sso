/*
 * server_mhd.c — Embedded HTTP management server using libmicrohttpd.
 *
 * This is an alternative to server.c that uses GNU libmicrohttpd instead
 * of raw POSIX sockets and a custom thread pool.  Compiled instead of
 * server.c when microhttpd.h is detected by the build system.
 *
 * The public API surface (server.h) is identical.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <microhttpd.h>

#include "sso.h"
#include "storage.h"
#include "arena.h"
#include "server.h"
#include "logger.h"
#include "token.h"
#include "config.h"

/* ========================================================================
 * Per-connection state for the MHD access handler callback
 *
 * MHD invokes the handler in phases:
 *   1. First call  (*req_cls == NULL) — allocate state
 *   2. Body calls  (*upload_data_size > 0) — accumulate body
 *   3. Final call  (*upload_data_size == 0) — process the request
 *   4. Completion  (MHD_OPTION_NOTIFY_COMPLETED) — free state
 * ======================================================================== */
typedef struct {
	arena_t arena; /* Arena memory pool for request-scoped allocations */
	char*	body;
	size_t	body_size;
	size_t	body_capacity;
	char**	query_params; /* owned, freed in completion callback */
	void*	userdata;	  /* auth_context_t, freed in completion   */

	/*
	 * Unique Trace ID for this request.
	 * CRITICAL: This ID is temporarily bound to the thread-local storage (`_Thread_local` in logger.c)
	 * during phase 3 (final call) to ensure all deep nested functions (like permission checks)
	 * automatically include this ID in their JSON logs without altering function signatures.
	 */
	char request_id[64];
} mhd_conn_state_t;

/* ========================================================================
 * Shutdown coordination
 * ======================================================================== */
static volatile sig_atomic_t g_shutdown = 0;

static _Thread_local arena_t t_arena;
static _Thread_local bool	 t_arena_init	 = false;
static volatile sig_atomic_t g_reload_config = 0;

/*
 * Global lock-free counter for unique request ID generation.
 * Combined with a high-resolution timestamp, this atomic_fetch_add() approach
 * guarantees collision-free Trace IDs across thousands of concurrent threads
 * without the context-switch overhead of traditional mutexes.
 */
static atomic_ullong g_request_counter = 0;

static void sigint_handler(int sig) {
	(void)sig;
	g_shutdown = 1;
}

static void sighup_handler(int sig) {
	(void)sig;
	g_reload_config = 1;
}

/* ========================================================================
 * Helpers
 * ======================================================================== */

static http_method_t parse_method(const char* method) {
	if (strcmp(method, "GET") == 0)
		return HTTP_GET;
	if (strcmp(method, "POST") == 0)
		return HTTP_POST;
	if (strcmp(method, "PUT") == 0)
		return HTTP_PUT;
	if (strcmp(method, "DELETE") == 0)
		return HTTP_DELETE;
	if (strcmp(method, "PATCH") == 0)
		return HTTP_PATCH;
	if (strcmp(method, "OPTIONS") == 0)
		return HTTP_OPTIONS;
	return HTTP_GET;
}

static void get_client_ip(struct MHD_Connection* connection, char* ip, size_t ip_size) {
	const union MHD_ConnectionInfo* ci = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
	if (ci && ci->client_addr) {
		struct sockaddr_in* addr = (struct sockaddr_in*)ci->client_addr;
		inet_ntop(AF_INET, &addr->sin_addr, ip, (socklen_t)ip_size);
	} else {
		snprintf(ip, ip_size, "unknown");
	}
}

/* Read an entire file into a malloc'd buffer (caller must free). */
static char* read_file_contents(const char* path) {
	FILE* f = fopen(path, "rb");
	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	if (len < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	char* buf = (char*)malloc((size_t)len + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	size_t n = fread(buf, 1, (size_t)len, f);
	buf[n]	 = '\0';
	fclose(f);
	return buf;
}

/* Parse extra_headers ("Key: Value\r\n...") into MHD response headers. */
static void apply_extra_headers(struct MHD_Response* resp, const char* extra) {
	if (!extra || extra[0] == '\0')
		return;
	char* copy = strdup(extra);
	if (!copy)
		return;

	char* line = copy;
	while (line && *line) {
		char* nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		char* cr = strchr(line, '\r');
		if (cr)
			*cr = '\0';

		if (*line) {
			char* sep = strchr(line, ':');
			if (sep) {
				*sep			= '\0';
				const char* val = sep + 1;
				while (*val == ' ')
					val++;
				MHD_add_response_header(resp, line, val);
			}
		}
		line = nl ? nl + 1 : NULL;
	}
	free(copy);
}

static enum MHD_Result query_param_iterator(void* cls, enum MHD_ValueKind kind, const char* key, const char* value) {
	(void)kind;
	mhd_conn_state_t* state = (mhd_conn_state_t*)cls;
	size_t			  count = 0;
	if (state->query_params) {
		while (state->query_params[count])
			count++;
	}
	char** new_params = (char**)arena_realloc(&state->arena, state->query_params, count * sizeof(char*),
											  (count + 2) * sizeof(char*));
	if (!new_params)
		return MHD_NO;
	state->query_params = new_params;

	if (value) {
		size_t len				   = strlen(key) + strlen(value) + 2;
		state->query_params[count] = (char*)arena_alloc(&state->arena, len);
		if (!state->query_params[count])
			return MHD_NO;
		snprintf(state->query_params[count], len, "%s=%s", key, value);
	} else {
		state->query_params[count] = arena_strdup(&state->arena, key);
		if (!state->query_params[count])
			return MHD_NO;
	}
	state->query_params[count + 1] = NULL;
	return MHD_YES;
}

#include "storage.h"

/* ========================================================================
 * Multi-Tenancy Context Registry
 * ======================================================================== */
#define MAX_TENANTS 64
typedef struct {
	char		   tenant_id[128];
	sso_context_t* ctx;
} tenant_context_t;

static tenant_context_t g_tenants[MAX_TENANTS];
static int				g_tenant_count = 0;
static pthread_mutex_t	g_tenant_lock  = PTHREAD_MUTEX_INITIALIZER;

static sso_context_t* get_tenant_context(sso_server_t* server, const char* host) {
	if (!host || host[0] == '\0')
		return server->sso_ctx;

	char		tenant_id[128] = "default";
	const char* dot			   = strchr(host, '.');
	if (dot) {
		size_t len = dot - host;
		if (len >= sizeof(tenant_id))
			len = sizeof(tenant_id) - 1;
		sso_strlcpy(tenant_id, host, len + 1);
	} else {
		sso_strlcpy(tenant_id, host, sizeof(tenant_id));
		char* colon = strchr(tenant_id, ':');
		if (colon)
			*colon = '\0';
	}

	if (strcmp(tenant_id, "localhost") == 0 || strcmp(tenant_id, "127") == 0 || strcmp(tenant_id, "default") == 0) {
		return server->sso_ctx;
	}

	pthread_mutex_lock(&g_tenant_lock);
	for (int i = 0; i < g_tenant_count; i++) {
		if (strcmp(g_tenants[i].tenant_id, tenant_id) == 0) {
			pthread_mutex_unlock(&g_tenant_lock);
			return g_tenants[i].ctx;
		}
	}

	if (g_tenant_count >= MAX_TENANTS) {
		pthread_mutex_unlock(&g_tenant_lock);
		return server->sso_ctx;
	}

	LOG_INFO("[tenant] Provisioning new sandbox context for tenant: %s", tenant_id);

	sso_context_t* new_ctx	   = (sso_context_t*)calloc(1, sizeof(sso_context_t));
	sso_config_t*  base_config = (sso_config_t*)sso_get_config(server->sso_ctx);
	sso_config_t   new_config;
	memcpy(&new_config, base_config, sizeof(new_config));

	char new_db_url[SSO_MAX_PATH * 2];
	if (strstr(new_config.database_url, ".db")) {
		char* ext		 = strstr(new_config.database_url, ".db");
		int	  prefix_len = ext - new_config.database_url;
		snprintf(new_db_url, sizeof(new_db_url), "%.*s_%s.db", prefix_len, new_config.database_url, tenant_id);
	} else {
		snprintf(new_db_url, sizeof(new_db_url), "%s_%s", new_config.database_url, tenant_id);
	}
	sso_strlcpy(new_config.database_url, new_db_url, sizeof(new_config.database_url));

	storage_backend_t* new_storage = NULL;
	if (new_config.use_memory) {
		storage_memory_create(&new_storage);
	} else if (strncmp(new_config.database_url, "postgres://", 11) == 0) {
		storage_postgres_create(&new_storage);
	} else if (strncmp(new_config.database_url, "redis://", 8) == 0 ||
			   strncmp(new_config.database_url, "redis-sentinel://", 17) == 0) {
		storage_redis_create(&new_storage);
	} else {
		storage_sqlite_create(&new_storage);
	}

	sso_error_t err = sso_init(new_ctx, new_storage, &new_config);
	if (err != SSO_OK) {
		LOG_ERROR("[tenant] Failed to boot sandbox for %s: %s", tenant_id, sso_strerror(err));
		free(new_ctx);
		if (new_storage && new_storage->close)
			new_storage->close(new_storage);
		pthread_mutex_unlock(&g_tenant_lock);
		return server->sso_ctx;
	}

	sso_strlcpy(g_tenants[g_tenant_count].tenant_id, tenant_id, sizeof(g_tenants[0].tenant_id));
	g_tenants[g_tenant_count].ctx = new_ctx;
	g_tenant_count++;

	pthread_mutex_unlock(&g_tenant_lock);
	return new_ctx;
}

/* ========================================================================
 * MHD access handler callback
 * ======================================================================== */
static enum MHD_Result mhd_access_handler(void* cls, struct MHD_Connection* connection, const char* url,
										  const char* method, const char* version, const char* upload_data,
										  size_t* upload_data_size, void** req_cls) {
	(void)version;
	sso_server_t*	  server = (sso_server_t*)cls;
	mhd_conn_state_t* state	 = (mhd_conn_state_t*)*req_cls;

	/* ---- Phase 1: allocate per-connection state ---- */
	if (state == NULL) {
		state = (mhd_conn_state_t*)calloc(1, sizeof(mhd_conn_state_t));
		if (!state)
			return MHD_NO;
		if (!t_arena_init) {
			arena_init(&t_arena, 4096);
			t_arena_init = true;
		}
		state->arena = t_arena;

		unsigned long long req_num = atomic_fetch_add(&g_request_counter, 1);
		snprintf(state->request_id, sizeof(state->request_id), "req-%lx-%08llx", (unsigned long)time(NULL), req_num);

		*req_cls = state;
		atomic_fetch_add(&g_metric_active_connections, 1);
		return MHD_YES;
	}

	/* ---- Phase 2: accumulate request body ---- */
	if (*upload_data_size > 0) {
		size_t new_size = state->body_size + *upload_data_size;
		char*  new_body = (char*)arena_realloc(&state->arena, state->body, state->body_size + 1, new_size + 1);
		if (!new_body) {
			return MHD_NO;
		}
		memcpy(new_body + state->body_size, upload_data, *upload_data_size);
		state->body			  = new_body;
		state->body_size	  = new_size;
		state->body[new_size] = '\0';
		*upload_data_size	  = 0;
		return MHD_YES;
	}

	/* ---- Phase 3: body complete — process the request ---- */
	http_request_t	req;
	http_response_t resp;
	enum MHD_Result ret;

	memset(&req, 0, sizeof(req));
	sso_strlcpy(req.request_id, state->request_id, sizeof(req.request_id));
	log_set_request_id(req.request_id);

	const char* host_hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Host");
	if (host_hdr)
		sso_strlcpy(req.host, host_hdr, sizeof(req.host));

	sso_context_t*	   active_ctx = get_tenant_context(server, req.host);
	storage_backend_t* sb		  = (storage_backend_t*)active_ctx->storage_backend;
	if (sb && sb->thread_init) {
		sb->thread_init(sb);
	}
	req.method	 = parse_method(method);
	req.body	 = state->body;
	req.body_len = state->body_size;

	/* URL → path */
	sso_strlcpy(req.path, url, sizeof(req.path));
	req.path[sizeof(req.path) - 1] = '\0';

	/* Extract query parameters using MHD API */
	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, query_param_iterator, state);
	req.query_params = state->query_params;

	/* Client IP */
	get_client_ip(connection, req.client_ip, sizeof(req.client_ip));

	/* Request headers */
	const char* auth_hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
	if (auth_hdr) {
		if (strncasecmp(auth_hdr, "Bearer ", 7) == 0) {
			sso_strlcpy(req.auth_token, auth_hdr + 7, sizeof(req.auth_token));
		} else if (strncasecmp(auth_hdr, "DPoP ", 5) == 0) {
			sso_strlcpy(req.auth_token, auth_hdr + 5, sizeof(req.auth_token));
		}
	}

	const char* dpop_hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "DPoP");
	if (dpop_hdr) {
		sso_strlcpy(req.dpop_proof, dpop_hdr, sizeof(req.dpop_proof));
	}

	const char* origin = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Origin");
	if (origin) {
		sso_strlcpy(req.origin, origin, sizeof(req.origin));
	}

	/* ---- Build response ---- */
	memset(&resp, 0, sizeof(resp));
	resp.body	  = NULL;
	resp.body_len = 0;
	strcpy(resp.content_type, "application/json");
	if (req.origin[0]) {
		snprintf(resp.cors_origin, sizeof(resp.cors_origin), "%s", req.origin);
	}

	/* CORS preflight */
	if (req.method == HTTP_OPTIONS) {
		snprintf(resp.extra_headers, sizeof(resp.extra_headers),
				 "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
				 "Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With\r\n"
				 "Access-Control-Max-Age: 86400\r\n");
		resp.body	  = strdup("");
		resp.body_len = 0;
		goto send_response;
	}

	/* Route matching via method index */
	route_t*  matched = NULL;
	route_t** mr	  = server->method_routes[req.method];
	size_t	  mc	  = server->method_route_count[req.method];
	for (size_t i = 0; i < mc; i++) {
		if (match_route(mr[i]->path_pattern, req.path, NULL)) {
			matched = mr[i];
			break;
		}
	}

	if (!matched) {
		sso_response_error(&resp, 404, "Not found");
		goto send_response;
	}

	/* Authentication middleware */
	req.userdata = NULL;
	if (matched->require_auth) {
		auth_context_t* auth = (auth_context_t*)arena_alloc(&state->arena, sizeof(auth_context_t));
		if (!auth) {
			sso_response_error(&resp, 500, "Internal server error");
			goto send_response;
		}
		sso_error_t aerr = authenticate_request(server, &req, &auth->user, &auth->token);
		if (aerr != SSO_OK) {
			const char* msg = "Authentication failed";
			if (aerr == SSO_ERR_TOKEN_EXPIRED)
				msg = "Token expired";
			sso_response_error(&resp, 401, msg);
			goto send_response;
		}
		req.userdata	= auth;
		state->userdata = auth; /* transfer ownership for cleanup */
	}

	/* Call handler */
	sso_error_t err = matched->handler(active_ctx, &req, &resp);
	if (err != SSO_OK && resp.body == NULL) {
		sso_response_error(&resp, 500, sso_strerror(err));
	}

send_response:
	/* Build MHD response from http_response_t */
	{ /* block isolates local decl after label */
		struct MHD_Response* mhd_resp;

		if (resp.body) {
			if (resp.body_len > 0) {
				mhd_resp = MHD_create_response_from_buffer(resp.body_len, resp.body, MHD_RESPMEM_MUST_COPY);
			} else {
				mhd_resp = MHD_create_response_from_buffer(0, (void*)"", MHD_RESPMEM_PERSISTENT);
			}
			if (!arena_contains(&state->arena, resp.body)) {
				free(resp.body);
			}
		} else {
			mhd_resp = MHD_create_response_from_buffer(0, (void*)"", MHD_RESPMEM_PERSISTENT);
		}

		if (!mhd_resp) {
			/* Can't create response — serious failure. Free what we can. */
			if (resp.body && !arena_contains(&state->arena, resp.body)) {
				free(resp.body);
			}
			log_set_request_id(NULL);
			return MHD_NO;
		}

		/* Content-Type */
		MHD_add_response_header(mhd_resp, "Content-Type", resp.content_type);

		/* CORS */
		const char* cors_origin = resp.cors_origin[0] ? resp.cors_origin : "*";
		MHD_add_response_header(mhd_resp, "Access-Control-Allow-Origin", cors_origin);
		MHD_add_response_header(mhd_resp, "Access-Control-Allow-Credentials", "true");
		MHD_add_response_header(mhd_resp, "Access-Control-Allow-Headers", "Content-Type, Authorization");
		MHD_add_response_header(mhd_resp, "Access-Control-Expose-Headers",
								"X-SSO-User, X-SSO-Access-Token, X-SSO-Refresh-Token");

		/* Security headers */
		MHD_add_response_header(mhd_resp, "X-Content-Type-Options", "nosniff");
		MHD_add_response_header(mhd_resp, "X-Frame-Options", "SAMEORIGIN");
		MHD_add_response_header(mhd_resp, "X-Request-Id", req.request_id);
		MHD_add_response_header(mhd_resp, "Permissions-Policy", "geolocation=(), microphone=(), camera=()");
		MHD_add_response_header(mhd_resp, "Content-Security-Policy",
								"default-src 'self'; style-src 'self' 'unsafe-inline'; "
								"script-src 'self' 'unsafe-inline'");
		MHD_add_response_header(mhd_resp, "Cache-Control", "no-cache, no-store, must-revalidate");
		MHD_add_response_header(mhd_resp, "Pragma", "no-cache");

		/* HSTS: only when TLS is enabled */
		sso_config_t* cfg = (sso_config_t*)sso_get_config(server->sso_ctx);
		if (cfg && cfg->tls_enabled) {
			MHD_add_response_header(mhd_resp, "Strict-Transport-Security", "max-age=31536000; includeSubDomains");
		}

		/* Vary: Origin when origin-aware CORS is active */
		if (resp.cors_origin[0]) {
			MHD_add_response_header(mhd_resp, "Vary", "Origin");
		}

		/* Extra headers (CORS preflight, etc.) */
		if (resp.extra_headers[0]) {
			apply_extra_headers(mhd_resp, resp.extra_headers);
		}

		/* Queue and send */
		ret = MHD_queue_response(connection, (unsigned int)resp.status_code, mhd_resp);
		MHD_destroy_response(mhd_resp);

		log_set_request_id(NULL);
		return ret;
	}
}

/* ========================================================================
 * Connection completion callback — frees per-connection state
 * ======================================================================== */
static void mhd_completed_cb(void* cls, struct MHD_Connection* connection, void** req_cls,
							 enum MHD_RequestTerminationCode toe) {
	sso_server_t* server = (sso_server_t*)cls;
	(void)connection;
	(void)toe;
	storage_backend_t* sb = server ? (storage_backend_t*)server->sso_ctx->storage_backend : NULL;
	if (sb && sb->thread_cleanup) {
		sb->thread_cleanup(sb);
	}

	mhd_conn_state_t* state = (mhd_conn_state_t*)*req_cls;
	if (!state)
		return;

	atomic_fetch_sub(&g_metric_active_connections, 1);

	/* Free token's inner role_ids/group_ids arrays if allocated */
	if (state->userdata) {
		token_destroy(&((auth_context_t*)state->userdata)->token);
	}

	/* Sync back and reset the thread-local arena */
	if (t_arena_init) {
		t_arena = state->arena;
		arena_reset(&t_arena);
	} else {
		arena_destroy(&state->arena);
	}

	free(state);
	*req_cls = NULL;
}

/* ========================================================================
 * Server lifecycle
 * ======================================================================== */

sso_error_t sso_server_init(sso_server_t* server, sso_context_t* ctx, const char* host, int port, const route_t* routes,
							size_t route_count) {
	if (!server || !ctx)
		return SSO_ERR_INVALID_PARAM;

	memset(server, 0, sizeof(*server));
	server->sso_ctx = ctx;
	sso_strlcpy(server->host, host ? host : "0.0.0.0", sizeof(server->host));
	server->port		= port;
	server->routes		= (route_t*)routes;
	server->route_count = route_count;
	server->server_data = NULL;
	server->ssl_ctx		= NULL;

	/* Build per-method route index for O(count_per_method) dispatch */
	for (size_t i = 0; i < route_count; i++) {
		http_method_t m = routes[i].method;
		server->method_route_count[m]++;
	}
	for (http_method_t m = HTTP_GET; m <= HTTP_OPTIONS; m++) {
		if (server->method_route_count[m] > 0) {
			server->method_routes[m] = (route_t**)malloc(server->method_route_count[m] * sizeof(route_t*));
			if (!server->method_routes[m]) {
				for (http_method_t j = HTTP_GET; j < m; j++) {
					free(server->method_routes[j]);
					server->method_routes[j] = NULL;
				}
				return SSO_ERR_OUT_OF_MEMORY;
			}
			size_t idx = 0;
			for (size_t i = 0; i < route_count; i++) {
				if (routes[i].method == m) {
					server->method_routes[m][idx++] = (route_t*)&routes[i];
				}
			}
		}
	}

	return SSO_OK;
}

void sso_server_stop(sso_server_t* server) {
	if (!server)
		return;
	g_shutdown = 1;
}

sso_error_t sso_server_start(sso_server_t* server) {
	if (!server)
		return SSO_ERR_INVALID_PARAM;

	g_shutdown = 0;

	/* Register signal handlers */
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGHUP, sighup_handler);
	signal(SIGPIPE, SIG_IGN);

	sso_config_t* cfg		   = (sso_config_t*)sso_get_config(server->sso_ctx);
	int			  thread_count = cfg ? cfg->thread_pool_size : 8;
	if (thread_count < 1)
		thread_count = 1;
	if (thread_count > 256)
		thread_count = 256;

	/* Build MHD option list dynamically.
	 * We start with known options + thread pool + completion callback,
	 * then append TLS options if enabled. */
#define MHD_MAX_OPTIONS 16
	struct MHD_OptionItem opts[MHD_MAX_OPTIONS];
	int					  opt_idx = 0;

	opts[opt_idx].option	= MHD_OPTION_THREAD_POOL_SIZE;
	opts[opt_idx].value		= (intptr_t)(unsigned int)thread_count;
	opts[opt_idx].ptr_value = NULL;
	opt_idx++;

	opts[opt_idx].option = MHD_OPTION_NOTIFY_COMPLETED;
	{ /* C-compliant: function pointer stored via intptr_t */
		void (*fn)(void*, struct MHD_Connection*, void**, enum MHD_RequestTerminationCode) = mhd_completed_cb;
		intptr_t tmp;
		memcpy(&tmp, &fn, sizeof(tmp));
		opts[opt_idx].value = tmp;
	}
	opts[opt_idx].ptr_value = NULL;
	opt_idx++;

	/* TLS support */
	char* cert_pem = NULL;
	char* key_pem  = NULL;

	if (cfg && cfg->tls_enabled) {
		cert_pem = read_file_contents(cfg->tls_cert_file);
		key_pem	 = read_file_contents(cfg->tls_key_file);

		if (!cert_pem || !key_pem) {
			LOG_ERROR("Failed to read TLS cert/key (%s / %s)", cfg->tls_cert_file, cfg->tls_key_file);
			free(cert_pem);
			free(key_pem);
			return SSO_ERR_INIT;
		}

		opts[opt_idx].option	= MHD_OPTION_HTTPS_MEM_CERT;
		opts[opt_idx].value		= 0;
		opts[opt_idx].ptr_value = cert_pem;
		opt_idx++;

		opts[opt_idx].option	= MHD_OPTION_HTTPS_MEM_KEY;
		opts[opt_idx].value		= 0;
		opts[opt_idx].ptr_value = key_pem;
		opt_idx++;
	}

	opts[opt_idx].option	= MHD_OPTION_END;
	opts[opt_idx].value		= 0;
	opts[opt_idx].ptr_value = NULL;

	/* Start the daemon */
	unsigned int flags = MHD_USE_INTERNAL_POLLING_THREAD;
	if (cfg && cfg->tls_enabled) {
#if defined(MHD_USE_TLS)
		flags |= MHD_USE_TLS;
#else
		flags |= MHD_USE_SSL;
#endif
	}

	struct MHD_Daemon* daemon = MHD_start_daemon(flags, (uint16_t)server->port, NULL, NULL, /* accept policy */
												 &mhd_access_handler, (void*)server,		/* handler + cls */
												 MHD_OPTION_ARRAY, (intptr_t)(void*)opts, MHD_OPTION_END);

	/* Free TLS PEMs now — MHD made copies */
	free(cert_pem);
	free(key_pem);

	if (!daemon) {
		LOG_ERROR("MHD_start_daemon failed on port %d", server->port);
		return SSO_ERR_SOCKET;
	}

	server->server_data = (void*)daemon;

	LOG_INFO("SSO management API listening on http%s://%s:%d (MHD, %d threads)", (cfg && cfg->tls_enabled) ? "s" : "",
			 server->host, server->port, thread_count);

	/* Block until shutdown signal */
	while (!g_shutdown) {
		/* SIGHUP: hot-reload config */
		if (g_reload_config) {
			g_reload_config = 0;
			if (server->config_path[0]) {
				sso_config_t* new_cfg = (sso_config_t*)malloc(sizeof(sso_config_t));
				if (new_cfg) {
					sso_config_t* old_cfg = (sso_config_t*)sso_get_config(server->sso_ctx);
					memcpy(new_cfg, old_cfg, sizeof(sso_config_t));
					if (sso_config_load(server->config_path, new_cfg) == SSO_OK) {
						sso_config_apply_env(new_cfg);
						__atomic_store_n(&server->sso_ctx->config, new_cfg, __ATOMIC_RELEASE);
						log_set_level((log_level_t)new_cfg->log_level);
						log_set_format((log_format_t)new_cfg->log_format);
						LOG_INFO("Configuration reloaded via SIGHUP");
						sleep(2);
						free(old_cfg);
					} else {
						free(new_cfg);
						LOG_WARN("SIGHUP config reload failed: could not load config file");
					}
				} else {
					LOG_ERROR("SIGHUP config reload failed: OOM allocating new config");
				}
			} else {
				LOG_WARN("SIGHUP config reload failed (no config path set)");
			}
		}
		sleep(1);
	}

	/* Stop the daemon */
	MHD_stop_daemon(daemon);
	server->server_data = NULL;

	LOG_INFO("SSO management API stopped.");

	/* Reset shutdown state so server can be restarted */
	g_shutdown = 0;

	return SSO_OK;
}
