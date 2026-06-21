#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "sso.h"
#include "server.h"
#include "logger.h"
#include "user.h"
#include "token.h"
#include "config.h"
#include "cJSON.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static sso_server_t*		 g_server		 = NULL;
static volatile sig_atomic_t g_reload_config = 0;

static _Thread_local arena_t t_arena;
static _Thread_local bool	 t_arena_init = false;

/*
 * Global lock-free counter for unique request ID generation.
 * Combined with a high-resolution timestamp, this atomic_fetch_add() approach
 * guarantees collision-free Trace IDs across thousands of concurrent threads
 * without the context-switch overhead of traditional mutexes.
 */
static atomic_ullong g_request_counter = 0;

/* ========================================================================
 * Connection wrapper (raw fd or TLS)
 * ======================================================================== */
typedef struct {
	int	 fd;
	SSL* ssl;
} conn_t;

static ssize_t conn_read(conn_t* c, void* buf, size_t n) {
	if (c->ssl)
		return SSL_read(c->ssl, buf, (int)n);
	return read(c->fd, buf, n);
}

static ssize_t conn_write(conn_t* c, const void* buf, size_t n) {
	if (c->ssl)
		return SSL_write(c->ssl, buf, (int)n);
	return write(c->fd, buf, n);
}

static void conn_close(conn_t* c) {
	if (c->ssl) {
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
		c->ssl = NULL;
	}
	if (c->fd >= 0) {
		close(c->fd);
		c->fd = -1;
	}
}

/* ========================================================================
 * Buffered reader
 * ======================================================================== */
#define BUF_READER_SIZE 4096

typedef struct {
	conn_t* conn;
	char	buf[BUF_READER_SIZE];
	size_t	pos;
	size_t	end;
} buf_reader_t;

static void br_init(buf_reader_t* br, conn_t* conn) {
	br->conn = conn;
	br->pos	 = 0;
	br->end	 = 0;
}

static ssize_t br_read_line(buf_reader_t* br, char* out, size_t max) {
	size_t oi = 0;
	while (oi < max - 1) {
		if (br->pos >= br->end) {
			ssize_t n = conn_read(br->conn, br->buf, sizeof(br->buf));
			if (n <= 0)
				break;
			br->pos = 0;
			br->end = (size_t)n;
		}
		char c = br->buf[br->pos++];
		if (c == '\r')
			continue;
		if (c == '\n')
			break;
		out[oi++] = c;
	}
	out[oi] = '\0';
	return (ssize_t)oi;
}

static ssize_t br_read(buf_reader_t* br, void* buf, size_t n) {
	size_t total = 0;
	while (total < n) {
		if (br->pos >= br->end) {
			ssize_t r = conn_read(br->conn, (char*)buf + total, n - total);
			if (r <= 0)
				break;
			total += (size_t)r;
		} else {
			size_t avail   = br->end - br->pos;
			size_t to_copy = (n - total < avail) ? n - total : avail;
			memcpy((char*)buf + total, br->buf + br->pos, to_copy);
			br->pos += to_copy;
			total += to_copy;
		}
	}
	return (ssize_t)total;
}

/* ========================================================================
 * Thread Pool for HTTP Server (dynamically sized from config)
 * ======================================================================== */

typedef struct {
	conn_t conn;
	char   client_ip[64];
} task_t;

typedef struct {
	pthread_t*		threads;
	task_t*			queue;
	int				pool_size;
	int				queue_size;
	int				head;
	int				tail;
	int				count;
	pthread_mutex_t lock;
	pthread_cond_t	notify;
	bool			stop;
	sso_server_t*	server;
} thread_pool_t;

static thread_pool_t g_pool;

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
		/* also strip port if it exists without dot, e.g. localhost:18080 */
		char* colon = strchr(tenant_id, ':');
		if (colon)
			*colon = '\0';
	}

	/* Ignore generic hosts */
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

	/* Cold Start: Auto-provision a new tenant sandbox */
	LOG_INFO("[tenant] Provisioning new sandbox context for tenant: %s", tenant_id);

	sso_context_t* new_ctx	   = (sso_context_t*)calloc(1, sizeof(sso_context_t));
	sso_config_t*  base_config = (sso_config_t*)sso_get_config(server->sso_ctx);
	sso_config_t   new_config;
	memcpy(&new_config, base_config, sizeof(new_config));

	/* Inject tenant isolation to DB URL */
	char new_db_url[2048];
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
		return server->sso_ctx; /* fallback to default */
	}

	sso_strlcpy(g_tenants[g_tenant_count].tenant_id, tenant_id, sizeof(g_tenants[0].tenant_id));
	g_tenants[g_tenant_count].ctx = new_ctx;
	g_tenant_count++;

	pthread_mutex_unlock(&g_tenant_lock);
	return new_ctx;
}

static void handle_client(sso_server_t* server, conn_t* conn, const char* client_ip);

static void* worker_thread(void* arg) {
	(void)arg;
	while (1) {
		pthread_mutex_lock(&g_pool.lock);
		while (g_pool.count == 0 && !g_pool.stop) {
			pthread_cond_wait(&g_pool.notify, &g_pool.lock);
		}
		if (g_pool.stop && g_pool.count == 0) {
			pthread_mutex_unlock(&g_pool.lock);
			break;
		}

		task_t task = g_pool.queue[g_pool.head];
		g_pool.head = (g_pool.head + 1) % g_pool.queue_size;
		g_pool.count--;
		pthread_mutex_unlock(&g_pool.lock);

		if (!t_arena_init) {
			arena_init(&t_arena, 4096);
			t_arena_init = true;
		}

		atomic_fetch_add(&g_metric_active_connections, 1);
		handle_client(g_pool.server, &task.conn, task.client_ip);
		atomic_fetch_sub(&g_metric_active_connections, 1);
	}
	if (t_arena_init) {
		arena_destroy(&t_arena);
		t_arena_init = false;
	}
	return NULL;
}

static void pool_init(sso_server_t* server) {
	sso_config_t* cfg		 = (sso_config_t*)sso_get_config(server->sso_ctx);
	int			  pool_size	 = cfg ? cfg->thread_pool_size : 8;
	int			  queue_size = cfg ? cfg->queue_size : 1024;
	if (pool_size < 1)
		pool_size = 1;
	if (pool_size > 256)
		pool_size = 256;
	if (queue_size < 1)
		queue_size = 1;

	g_pool.pool_size  = pool_size;
	g_pool.queue_size = queue_size;
	g_pool.head		  = 0;
	g_pool.tail		  = 0;
	g_pool.count	  = 0;
	g_pool.stop		  = false;
	g_pool.server	  = server;

	g_pool.threads = (pthread_t*)calloc((size_t)pool_size, sizeof(pthread_t));
	g_pool.queue   = (task_t*)calloc((size_t)queue_size, sizeof(task_t));

	if (!g_pool.threads || !g_pool.queue) {
		LOG_ERROR("Failed to allocate thread pool (threads=%p queue=%p)", (void*)g_pool.threads, (void*)g_pool.queue);
		free(g_pool.threads);
		free(g_pool.queue);
		g_pool.threads = NULL;
		g_pool.queue   = NULL;
		/* Signal failure to caller via pool_size = 0 */
		g_pool.pool_size  = 0;
		g_pool.queue_size = 0;
		pthread_mutex_destroy(&g_pool.lock);
		pthread_cond_destroy(&g_pool.notify);
		return;
	}
	pthread_mutex_init(&g_pool.lock, NULL);
	pthread_cond_init(&g_pool.notify, NULL);

	for (int i = 0; i < pool_size; i++) {
		pthread_create(&g_pool.threads[i], NULL, worker_thread, NULL);
	}
}

static void pool_submit(conn_t* conn, const char* client_ip) {
	pthread_mutex_lock(&g_pool.lock);
	if (g_pool.count < g_pool.queue_size) {
		g_pool.queue[g_pool.tail].conn = *conn;
		snprintf(g_pool.queue[g_pool.tail].client_ip, sizeof(g_pool.queue[g_pool.tail].client_ip), "%s", client_ip);
		g_pool.tail = (g_pool.tail + 1) % g_pool.queue_size;
		g_pool.count++;
		pthread_cond_signal(&g_pool.notify);
	} else {
		conn_close(conn);
	}
	pthread_mutex_unlock(&g_pool.lock);
}

static void pool_shutdown(void) {
	pthread_mutex_lock(&g_pool.lock);
	g_pool.stop = true;
	pthread_cond_broadcast(&g_pool.notify);
	pthread_mutex_unlock(&g_pool.lock);

	for (int i = 0; i < g_pool.pool_size; i++) {
		pthread_join(g_pool.threads[i], NULL);
	}

	free(g_pool.threads);
	free(g_pool.queue);
	g_pool.threads = NULL;
	g_pool.queue   = NULL;

	pthread_mutex_destroy(&g_pool.lock);
	pthread_cond_destroy(&g_pool.notify);
}

/* ========================================================================
 * Internal: HTTP request parser (minimal)
 * ======================================================================== */

static void parse_err(http_request_t* req) {
	arena_destroy(&req->arena);
	if (t_arena_init)
		t_arena = req->arena;
}

static int parse_request(buf_reader_t* br, http_request_t* req, long max_body_size) {
	memset(req, 0, sizeof(*req));
	if (t_arena_init) {
		req->arena = t_arena;
	} else {
		arena_init(&req->arena, 4096);
	}

	char line[4096];
	if (br_read_line(br, line, sizeof(line)) <= 0) {
		parse_err(req);
		return -1;
	}

	char method[16], path[SSO_MAX_PATH], version[16];
	if (sscanf(line, "%15s %1023s %15s", method, path, version) < 2) {
		parse_err(req);
		return -1;
	}

	sso_strlcpy(req->method_str, method, sizeof(req->method_str));

	if (strcmp(method, "GET") == 0)
		req->method = HTTP_GET;
	else if (strcmp(method, "POST") == 0)
		req->method = HTTP_POST;
	else if (strcmp(method, "PUT") == 0)
		req->method = HTTP_PUT;
	else if (strcmp(method, "DELETE") == 0)
		req->method = HTTP_DELETE;
	else if (strcmp(method, "PATCH") == 0)
		req->method = HTTP_PATCH;
	else {
		parse_err(req);
		return -1;
	}

	memcpy(req->path, path, SSO_MAX_PATH - 1);
	req->path[SSO_MAX_PATH - 1] = '\0';

	char* qmark = strchr(req->path, '?');
	if (qmark) {
		*qmark++  = '\0';
		int count = 1;
		for (char* p = qmark; *p; p++) {
			if (*p == '&')
				count++;
		}
		req->query_params = (char**)arena_calloc(&req->arena, (size_t)(count + 1), sizeof(char*));
		if (req->query_params) {
			size_t		idx = 0;
			char*		save;
			const char* token = strtok_r(qmark, "&", &save);
			while (token) {
				req->query_params[idx++] = arena_strdup(&req->arena, token);
				token					 = strtok_r(NULL, "&", &save);
			}
			req->query_params[idx] = NULL;
		}
	}

	long content_length = 0;
	while (1) {
		if (br_read_line(br, line, sizeof(line)) <= 0)
			break;
		if (line[0] == '\0')
			break;

		if (strncasecmp(line, "Content-Length:", 15) == 0) {
			char* end = NULL;
			long  val = strtol(line + 15, &end, 10);
			if (end != line + 15 && val >= 0)
				content_length = val;
		} else if (strncasecmp(line, "Authorization:", 14) == 0) {
			const char* token = line + 14;
			while (*token == ' ')
				token++;
			if (strncasecmp(token, "Bearer ", 7) == 0) {
				sso_strlcpy(req->auth_token, token + 7, SSO_MAX_TOKEN_STR);
			} else if (strncasecmp(token, "DPoP ", 5) == 0) {
				sso_strlcpy(req->auth_token, token + 5, SSO_MAX_TOKEN_STR);
			}
		} else if (strncasecmp(line, "Origin:", 7) == 0) {
			const char* origin = line + 7;
			while (*origin == ' ')
				origin++;
			sso_strlcpy(req->origin, origin, sizeof(req->origin));
			req->origin[sizeof(req->origin) - 1] = '\0';
			/* Strip trailing whitespace/CR */
			size_t olen = strlen(req->origin);
			while (olen > 0 && (req->origin[olen - 1] == ' ' || req->origin[olen - 1] == '\r'))
				req->origin[--olen] = '\0';
		} else if (strncasecmp(line, "DPoP:", 5) == 0) {
			const char* val = line + 5;
			while (*val == ' ')
				val++;
			sso_strlcpy(req->dpop_proof, val, sizeof(req->dpop_proof));
			req->dpop_proof[sizeof(req->dpop_proof) - 1] = '\0';
			size_t olen									 = strlen(req->dpop_proof);
			while (olen > 0 && (req->dpop_proof[olen - 1] == ' ' || req->dpop_proof[olen - 1] == '\r'))
				req->dpop_proof[--olen] = '\0';
		} else if (strncasecmp(line, "Host:", 5) == 0) {
			const char* val = line + 5;
			while (*val == ' ')
				val++;
			sso_strlcpy(req->host, val, sizeof(req->host));
			req->host[sizeof(req->host) - 1] = '\0';
			size_t olen						 = strlen(req->host);
			while (olen > 0 && (req->host[olen - 1] == ' ' || req->host[olen - 1] == '\r'))
				req->host[--olen] = '\0';
		}
	}

	if (content_length > 0) {
		if (max_body_size > 0 && content_length > max_body_size) {
			parse_err(req);
			return -1;
		}
		req->body = (char*)arena_alloc(&req->arena, (size_t)content_length + 1);
		if (req->body) {
			ssize_t total = br_read(br, req->body, (size_t)content_length);
			if (total > 0) {
				req->body[(size_t)total] = '\0';
				req->body_len			 = (size_t)total;
			}
		}
	}

	return 0;
}

static ssize_t conn_write_all(conn_t* c, const void* buf, size_t n) {
	const char* p		  = (const char*)buf;
	size_t		remaining = n;
	while (remaining > 0) {
		ssize_t written = conn_write(c, p, remaining);
		if (written <= 0)
			return -1;
		p += written;
		remaining -= (size_t)written;
	}
	return (ssize_t)n;
}

static void send_response(conn_t* c, const http_response_t* resp, const char* request_id) {
	char hsts[128] = "";
	if (g_server && g_server->ssl_ctx) {
		snprintf(hsts, sizeof(hsts), "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
	}
	/* CORS: echo back the request Origin when provided, fallback to *.
	 * Never combine '*' with 'Credentials: true' (per Fetch spec). */
	const char* cors_origin = resp->cors_origin[0] ? resp->cors_origin : "*";
	char		vary[64]	= "";
	if (resp->cors_origin[0]) {
		snprintf(vary, sizeof(vary), "Vary: Origin\r\n");
	}
	char* header = (char*)malloc(16384);
	if (!header)
		return;
	int n = snprintf(header, 16384,
					 "HTTP/1.1 %d %s\r\n"
					 "Content-Type: %s\r\n"
					 "Content-Length: %zu\r\n"
					 "Connection: close\r\n"
					 "Access-Control-Allow-Origin: %s\r\n"
					 "Access-Control-Allow-Credentials: true\r\n"
					 "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
					 "Access-Control-Expose-Headers: X-SSO-User, X-SSO-Access-Token, X-SSO-Refresh-Token\r\n"
					 "X-Content-Type-Options: nosniff\r\n"
					 "X-Frame-Options: SAMEORIGIN\r\n"
					 "X-Request-Id: %s\r\n"
					 "Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n"
					 "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' "
					 "'unsafe-inline';\r\n"
					 "Cache-Control: no-cache, no-store, must-revalidate\r\n"
					 "Pragma: no-cache\r\n"
					 "%s"
					 "%s"
					 "%s"
					 "\r\n",
					 resp->status_code,
					 resp->status_code == 200	? "OK"
					 : resp->status_code == 201 ? "Created"
					 : resp->status_code == 302 ? "Found"
					 : resp->status_code == 400 ? "Bad Request"
					 : resp->status_code == 401 ? "Unauthorized"
					 : resp->status_code == 403 ? "Forbidden"
					 : resp->status_code == 404 ? "Not Found"
					 : resp->status_code == 500 ? "Internal Server Error"
												: "Unknown",
					 resp->content_type, resp->body_len, cors_origin, request_id ? request_id : "unknown", hsts, vary,
					 resp->extra_headers);

	conn_write_all(c, header, (size_t)n);
	if (resp->body && resp->body_len > 0) {
		conn_write_all(c, resp->body, resp->body_len);
	}
	free(header);
}

static void cleanup_request(conn_t* conn, http_response_t* resp, http_request_t* req) {
	if (resp->body) {
		if (!arena_contains(&req->arena, resp->body)) {
			free(resp->body);
		}
		resp->body = NULL;
	}
	if (t_arena_init) {
		t_arena = req->arena;
		arena_reset(&t_arena);
	} else {
		arena_destroy(&req->arena);
	}
	conn_close(conn);
}

/* ========================================================================
 * Handle a single client connection
 * ======================================================================== */
static void handle_client(sso_server_t* server, conn_t* conn, const char* client_ip) {
	http_request_t	req;
	http_response_t resp;

	sso_config_t* cfg = (sso_config_t*)sso_get_config(server->sso_ctx);
	if (cfg) {
		struct timeval tv;
		tv.tv_sec  = cfg->request_timeout_ms / 1000;
		tv.tv_usec = (cfg->request_timeout_ms % 1000) * 1000;
		setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	buf_reader_t br;
	br_init(&br, conn);

	long max_body = cfg ? cfg->max_body_size : 1048576;
	if (parse_request(&br, &req, max_body) != 0) {
		conn_close(conn);
		return;
	}
	/* Generate Trace ID */
	unsigned long long req_num = atomic_fetch_add(&g_request_counter, 1);
	snprintf(req.request_id, sizeof(req.request_id), "req-%lx-%08llx", (unsigned long)time(NULL), req_num);
	log_set_request_id(req.request_id);

	sso_strlcpy(req.client_ip, client_ip, sizeof(req.client_ip));
	req.client_ip[sizeof(req.client_ip) - 1] = '\0';

	/* ---------------------------------------------------------
	 * Zero-Trust Multi-Tenancy Routing Boundary
	 * --------------------------------------------------------- */
	sso_context_t* active_ctx = get_tenant_context(server, req.host);

	memset(&resp, 0, sizeof(resp));
	resp.body	  = NULL;
	resp.body_len = 0;
	strcpy(resp.content_type, "application/json");
	/* Propagate CORS origin from request to response */
	snprintf(resp.cors_origin, sizeof(resp.cors_origin), "%s", req.origin);

	/* CORS preflight */
	if (req.method == HTTP_OPTIONS) {
		snprintf(resp.extra_headers, sizeof(resp.extra_headers),
				 "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
				 "Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With\r\n"
				 "Access-Control-Max-Age: 86400\r\n");
		resp.body	  = strdup("");
		resp.body_len = 0;
		send_response(conn, &resp, req.request_id);
		cleanup_request(conn, &resp, &req);
		log_set_request_id(NULL);
		return;
	}

	/* Find matching route via method index */
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
		send_response(conn, &resp, req.request_id);
		cleanup_request(conn, &resp, &req);
		log_set_request_id(NULL);
		return;
	}

	req.userdata = NULL;
	if (matched->require_auth) {
		auth_context_t* auth = (auth_context_t*)arena_alloc(&req.arena, sizeof(auth_context_t));
		if (!auth) {
			sso_response_error(&resp, 500, "Internal server error");
			send_response(conn, &resp, req.request_id);
			cleanup_request(conn, &resp, &req);
			log_set_request_id(NULL);
			return;
		}
		sso_error_t aerr = authenticate_request(server, &req, &auth->user, &auth->token);
		if (aerr != SSO_OK) {
			const char* msg = "Authentication failed";
			if (aerr == SSO_ERR_TOKEN_EXPIRED)
				msg = "Token expired";
			sso_response_error(&resp, 401, msg);
			token_destroy(&auth->token);
			send_response(conn, &resp, req.request_id);
			cleanup_request(conn, &resp, &req);
			log_set_request_id(NULL);
			return;
		}
		req.userdata = auth;
	}

	sso_error_t err = matched->handler(active_ctx, &req, &resp);

	if (req.userdata) {
		token_destroy(&((auth_context_t*)req.userdata)->token);
		req.userdata = NULL;
	}
	if (err != SSO_OK && resp.body == NULL) {
		sso_response_error(&resp, 500, sso_strerror(err));
	}

	send_response(conn, &resp, req.request_id);
	cleanup_request(conn, &resp, &req);
	log_set_request_id(NULL);
}

/* ========================================================================
 * Signal handler for graceful shutdown
 * ======================================================================== */
static void sigint_handler(int sig) {
	(void)sig;
	if (g_server) {
		sso_server_stop(g_server);
	}
}

static void sighup_handler(int sig) {
	(void)sig;
	g_reload_config = 1;
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
				/* Clean up already-allocated method arrays */
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

	int* sock = (int*)&server->server_data;
	if (*sock > 0) {
		shutdown(*sock, SHUT_RDWR);
		close(*sock);
		*sock = 0;
	}

	if (server->ssl_ctx) {
		SSL_CTX_free(server->ssl_ctx);
		server->ssl_ctx = NULL;
	}

	/* Free per-method route index */
	for (http_method_t m = HTTP_GET; m <= HTTP_OPTIONS; m++) {
		free(server->method_routes[m]);
		server->method_routes[m] = NULL;
	}
}

sso_error_t sso_server_start(sso_server_t* server) {
	if (!server)
		return SSO_ERR_INVALID_PARAM;

	g_server = server;
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGHUP, sighup_handler);
	signal(SIGPIPE, SIG_IGN);

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		LOG_ERROR("socket() failed");
		return SSO_ERR_SOCKET;
	}

	int opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family		 = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port		 = htons((uint16_t)server->port);

	if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		LOG_ERROR("bind() failed on port %d", server->port);
		close(server_fd);
		return SSO_ERR_BIND;
	}

	if (listen(server_fd, 128) < 0) {
		LOG_ERROR("listen() failed");
		close(server_fd);
		return SSO_ERR_LISTEN;
	}

	server->server_data = (void*)(intptr_t)server_fd;

	/* TLS setup */
	sso_config_t* cfg = (sso_config_t*)sso_get_config(server->sso_ctx);
	if (cfg && cfg->tls_enabled) {
		SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
		if (!ctx) {
			LOG_ERROR("SSL_CTX_new failed");
			close(server_fd);
			return SSO_ERR_INIT;
		}

		if (SSL_CTX_use_certificate_file(ctx, cfg->tls_cert_file, SSL_FILETYPE_PEM) <= 0) {
			LOG_ERROR("Failed to load TLS cert: %s", cfg->tls_cert_file);
			SSL_CTX_free(ctx);
			close(server_fd);
			return SSO_ERR_INIT;
		}

		if (SSL_CTX_use_PrivateKey_file(ctx, cfg->tls_key_file, SSL_FILETYPE_PEM) <= 0) {
			LOG_ERROR("Failed to load TLS key: %s", cfg->tls_key_file);
			SSL_CTX_free(ctx);
			close(server_fd);
			return SSO_ERR_INIT;
		}

		server->ssl_ctx = ctx;
		LOG_INFO("TLS enabled (cert: %s)", cfg->tls_cert_file);
	}

	LOG_INFO("SSO management API listening on http%s://%s:%d", server->ssl_ctx ? "s" : "", server->host, server->port);

	pool_init(server);

	while (1) {
		struct sockaddr_in client_addr;
		socklen_t		   client_len = sizeof(client_addr);

		int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
		if (client_fd < 0) {
			if (errno == EINTR || errno == EBADF || errno == EINVAL) {
				const int* sock = (const int*)&server->server_data;
				if (*sock == 0)
					break;
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
				continue;
			}
			break;
		}

		char client_ip[64] = "unknown";
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

		conn_t conn;
		conn.fd	 = client_fd;
		conn.ssl = NULL;

		if (server->ssl_ctx) {
			conn.ssl = SSL_new(server->ssl_ctx);
			if (conn.ssl) {
				SSL_set_fd(conn.ssl, client_fd);
				if (SSL_accept(conn.ssl) != 1) {
					SSL_free(conn.ssl);
					close(client_fd);
					continue;
				}
			} else {
				close(client_fd);
				continue;
			}
		}

		pool_submit(&conn, client_ip);
	}

	pool_shutdown();
	close(server_fd);
	server->server_data = NULL;
	LOG_INFO("SSO management API stopped.");
	return SSO_OK;
}
