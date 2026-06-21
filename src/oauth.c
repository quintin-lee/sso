#include "sso.h"
#include "oauth.h"
#include "token.h"
#include "storage.h"
#include "dpop.h"
#include "config.h"
#include "user.h"
#include "logger.h"
#include "cJSON.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static bool verify_pkce(const char* code_verifier, const char* challenge, const char* method) {
	if (!challenge || challenge[0] == '\0')
		return true; /* PKCE not used for this code */
	if (!code_verifier)
		return false;

	size_t len = strlen(code_verifier);
	if (len < 43 || len > 128)
		return false;

	if (strcmp(method, "plain") == 0) {
		return strcmp(code_verifier, challenge) == 0;
	} else if (strcmp(method, "S256") == 0) {
		unsigned char hash[32];
		SHA256((const unsigned char*)code_verifier, len, hash);
		char computed_challenge[128];
		base64url_encode(hash, 32, computed_challenge, sizeof(computed_challenge));
		return strcmp(computed_challenge, challenge) == 0;
	}
	return false;
}

/* -----------------------------------------------------------------------
 * Internal helpers
 * ----------------------------------------------------------------------- */

/* Generate a random authorization code (hex string). */
static void gen_auth_code(char* buf, size_t size) {
	unsigned char raw[16];
	randombytes_buf(raw, sizeof(raw));
	char* p = buf;
	for (size_t i = 0; i < sizeof(raw) && p < buf + size - 3; i++)
		p += snprintf(p, (size_t)(buf + size - p), "%02x", raw[i]);
	*p = '\0';
}

/* Get the sso_config_t from ctx->config. */
static sso_config_t* get_cfg(sso_context_t* ctx) {
	return (sso_config_t*)sso_get_config(ctx);
}

/* Get the storage backend from ctx->storage_backend. */
static storage_backend_t* get_storage(sso_context_t* ctx) {
	return (storage_backend_t*)ctx->storage_backend;
}

/* Get the token manager from ctx->token_mgr. */
static token_manager_t* get_token_mgr(sso_context_t* ctx) {
	return (token_manager_t*)ctx->token_mgr;
}

/* Get the user manager from ctx->user_mgr. */
static user_manager_t* get_user_mgr(sso_context_t* ctx) {
	return (user_manager_t*)ctx->user_mgr;
}

/* Extract string value from a JSON body for a given key.
 * Caller must free the returned string. */
static char* json_str_value(const char* json, const char* key) {
	if (!json || !key)
		return NULL;
	char search[128];
	snprintf(search, sizeof(search), "\"%s\"", key);
	const char* p = strstr(json, search);
	if (!p)
		return NULL;
	p += strlen(search);
	while (*p && *p != ':' && *p != ',')
		p++;
	if (*p == ':')
		p++;
	while (*p && (*p == ' ' || *p == '\t' || *p == '\n'))
		p++;
	if (*p == '"')
		p++;
	else
		return NULL;
	const char* end = p;
	while (*end) {
		if (*end == '\\' && *(end + 1) == '"')
			end += 2;
		else if (*end == '"')
			break;
		else
			end++;
	}
	size_t len = (size_t)(end - p);
	char*  val = (char*)malloc(len + 1);
	if (!val)
		return NULL;
	memcpy(val, p, len);
	val[len] = '\0';
	return val;
}

/* Build a simple JSON response with a single string field. */
static void json_error_response(http_response_t* resp, int status, const char* error) {
	char buf[512];
	snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", error);
	resp->status_code = status;
	resp->body		  = strdup(buf);
	resp->body_len	  = resp->body ? strlen(buf) : 0;
	strcpy(resp->content_type, "application/json");
}

/* Add above handle_oauth_authorize */
static bool is_redirect_uri_allowed(const char* allowed_uris, const char* redirect_uri) {
	if (!allowed_uris || !allowed_uris[0])
		return false;
	char uris_copy[512];
	sso_strlcpy(uris_copy, allowed_uris, sizeof(uris_copy));
	uris_copy[sizeof(uris_copy) - 1] = '\0';

	char* saveptr = NULL;
	char* tok	  = strtok_r(uris_copy, ",", &saveptr);
	while (tok) {
		while (*tok == ' ')
			tok++; /* Trim leading spaces */
		size_t len = strlen(tok);
		while (len > 0 && tok[len - 1] == ' ') {
			tok[len - 1] = '\0';
			len--;
		}
		if (strcmp(tok, redirect_uri) == 0)
			return true;
		tok = strtok_r(NULL, ",", &saveptr);
	}
	return false;
}

static void store_refresh_token(storage_backend_t* sb, sso_id_t user_id, const char* client_id,
								const char* raw_refresh_token) {
	if (!sb || !sb->refresh_token_create || !raw_refresh_token)
		return;

	refresh_token_t rt;
	memset(&rt, 0, sizeof(rt));

	unsigned char rt_hash_bytes[32];
	crypto_hash_sha256(rt_hash_bytes, (const unsigned char*)raw_refresh_token, strlen(raw_refresh_token));
	for (size_t i = 0; i < 32; i++) {
		sprintf(&rt.token_hash[i * 2], "%02x", rt_hash_bytes[i]);
	}
	rt.user_id = user_id;
	if (client_id) {
		sso_strlcpy(rt.client_id, client_id, sizeof(rt.client_id));
		rt.client_id[sizeof(rt.client_id) - 1] = '\0';
	}
	rt.issued_at  = sso_timestamp_now();
	rt.expires_at = rt.issued_at + SSO_REFRESH_TOKEN_TTL;
	rt.revoked	  = 0;
	sb->refresh_token_create(sb, &rt);
}

static long get_client_token_ttl(const sso_config_t* cfg, storage_backend_t* sb, const char* client_id) {
	long ttl = 3600000; // Default 1 hour
	if (cfg && cfg->oauth_client_id[0] && strcmp(client_id, cfg->oauth_client_id) == 0) {
		if (cfg->token_ttl_ms > 0)
			ttl = cfg->token_ttl_ms;
	} else {
		oauth_client_t client;
		if (sb && sb->oauth_client_get && sb->oauth_client_get(sb, client_id, &client) == SSO_OK) {
			if (client.token_ttl_ms > 0) {
				ttl = client.token_ttl_ms;
			}
		}
	}
	return ttl;
}

/* ========================================================================
 * GET /api/v1/oauth/authorize
 *
 * Browser-facing: validates client_id / redirect_uri, authenticates user
 * via existing login flow, then redirects with ?code=...&state=...
 *
 * For simplicity, this expects the caller to already be authenticated.
 * The auth_context_t (from require_auth middleware) provides the user.
 * ======================================================================== */
sso_error_t handle_oauth_authorize(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_config_t* cfg = get_cfg(ctx);
	if (!cfg || !cfg->oauth_client_id[0]) {
		json_error_response(resp, 400, "oauth_not_configured");
		return SSO_OK;
	}

	/* Parse query parameters: client_id, redirect_uri, response_type, state, scope, nonce */
	/* req->query_params is an array of "key=value" strings, NULL-terminated */
	const char* client_id			  = NULL;
	const char* redirect_uri		  = NULL;
	const char* response_type		  = NULL;
	const char* state				  = NULL;
	const char* scope				  = NULL;
	const char* nonce				  = NULL;
	const char* code_challenge		  = NULL;
	const char* code_challenge_method = NULL;
	if (req->query_params) {
		for (size_t i = 0; req->query_params[i]; i++) {
			const char* eq = strchr(req->query_params[i], '=');
			if (!eq)
				continue;
			size_t		klen = (size_t)(eq - req->query_params[i]);
			const char* val	 = eq + 1;
			if (klen == 9 && strncmp(req->query_params[i], "client_id", 9) == 0)
				client_id = val;
			else if (klen == 12 && strncmp(req->query_params[i], "redirect_uri", 12) == 0)
				redirect_uri = val;
			else if (klen == 13 && strncmp(req->query_params[i], "response_type", 13) == 0)
				response_type = val;
			else if (klen == 5 && strncmp(req->query_params[i], "state", 5) == 0)
				state = val;
			else if (klen == 5 && strncmp(req->query_params[i], "scope", 5) == 0)
				scope = val;
			else if (klen == 5 && strncmp(req->query_params[i], "nonce", 5) == 0)
				nonce = val;
			else if (klen == 14 && strncmp(req->query_params[i], "code_challenge", 14) == 0)
				code_challenge = val;
			else if (klen == 21 && strncmp(req->query_params[i], "code_challenge_method", 21) == 0)
				code_challenge_method = val;
		}
	}

	if (!client_id || !redirect_uri || !response_type) {
		LOG_WARN("[oauth] authorize: missing required params (client_id=%s redirect_uri=%s response_type=%s)",
				 client_id ? client_id : "(null)", redirect_uri ? redirect_uri : "(null)",
				 response_type ? response_type : "(null)");
		json_error_response(resp, 400, "invalid_request");
		return SSO_OK;
	}

	if (code_challenge_method && strcmp(code_challenge_method, "S256") != 0 &&
		strcmp(code_challenge_method, "plain") != 0) {
		json_error_response(resp, 400, "invalid_request");
		return SSO_OK;
	}

	// Check config first
	bool		   is_config_client = false;
	oauth_client_t db_client;
	memset(&db_client, 0, sizeof(db_client));

	if (cfg && cfg->oauth_client_id[0] && strcmp(client_id, cfg->oauth_client_id) == 0) {
		is_config_client = true;
	} else {
		// Fallback to database
		storage_backend_t* sb = get_storage(ctx);
		if (sb && sb->oauth_client_get) {
			if (sb->oauth_client_get(sb, client_id, &db_client) != SSO_OK || db_client.status != 1) {
				json_error_response(resp, 400, "unauthorized_client");
				return SSO_OK;
			}
		} else {
			json_error_response(resp, 400, "unauthorized_client");
			return SSO_OK;
		}
	}

	/* Check redirect_uri against allowed URIs */
	if (is_config_client) {
		if (!is_redirect_uri_allowed(cfg->oauth_redirect_uris, redirect_uri)) {
			json_error_response(resp, 400, "invalid_redirect_uri");
			return SSO_OK;
		}
	} else {
		if (!is_redirect_uri_allowed(db_client.redirect_uris, redirect_uri)) {
			json_error_response(resp, 400, "invalid_redirect_uri");
			return SSO_OK;
		}
	}

	/* Store requested scope. We can skip deep scope validation for now or check against DB later */

	if (strcmp(response_type, "code") != 0) {
		json_error_response(resp, 400, "unsupported_response_type");
		return SSO_OK;
	}

	/* Authenticate via the existing middleware — req contains auth_context_t */
	if (!req->userdata) {
		json_error_response(resp, 401, "authentication_required");
		return SSO_OK;
	}
	auth_context_t* auth = (auth_context_t*)req->userdata;
	const user_t*	user = &auth->user;
	if (user->status != USER_STATUS_ACTIVE) {
		json_error_response(resp, 403, "user_inactive");
		return SSO_OK;
	}

	/* Generate and store the authorization code */
	oauth_auth_code_t ac;
	memset(&ac, 0, sizeof(ac));
	gen_auth_code(ac.code, sizeof(ac.code));
	sso_strlcpy(ac.client_id, client_id, sizeof(ac.client_id));
	ac.client_id[sizeof(ac.client_id) - 1] = '\0';
	ac.user_id							   = user->id;
	sso_strlcpy(ac.redirect_uri, redirect_uri, sizeof(ac.redirect_uri));
	ac.redirect_uri[sizeof(ac.redirect_uri) - 1] = '\0';
	if (scope) {
		sso_strlcpy(ac.scope, scope, sizeof(ac.scope));
		ac.scope[sizeof(ac.scope) - 1] = '\0';
	}
	if (nonce) {
		sso_strlcpy(ac.nonce, nonce, sizeof(ac.nonce));
		ac.nonce[sizeof(ac.nonce) - 1] = '\0';
	}
	if (code_challenge) {
		sso_strlcpy(ac.code_challenge, code_challenge, sizeof(ac.code_challenge));
		ac.code_challenge[sizeof(ac.code_challenge) - 1] = '\0';
	}
	if (code_challenge_method) {
		sso_strlcpy(ac.code_challenge_method, code_challenge_method, sizeof(ac.code_challenge_method));
		ac.code_challenge_method[sizeof(ac.code_challenge_method) - 1] = '\0';
	} else if (code_challenge) {
		strcpy(ac.code_challenge_method, "plain");
	}

	/* Auth codes: 60s TTL by default */
	long ttl	  = cfg->oauth_auth_code_ttl_ms > 0 ? cfg->oauth_auth_code_ttl_ms : 60000;
	ac.expires_at = sso_timestamp_now() + ttl;

	storage_backend_t* sb = get_storage(ctx);
	if (!sb || !sb->oauth_code_create) {
		json_error_response(resp, 500, "server_error");
		return SSO_OK;
	}
	sso_error_t err = sb->oauth_code_create(sb, &ac);
	if (err != SSO_OK) {
		json_error_response(resp, 500, "server_error");
		return SSO_OK;
	}

	/* Build redirect URL with code and state */
	char* location = (char*)malloc(2048);
	if (!location) {
		json_error_response(resp, 500, "Out of memory");
		return SSO_OK;
	}
	if (state) {
		snprintf(location, 2048, "%s?code=%s&state=%s", redirect_uri, ac.code, state);
	} else {
		snprintf(location, 2048, "%s?code=%s", redirect_uri, ac.code);
	}

	resp->status_code = 302;
	resp->body		  = strdup(location);
	resp->body_len	  = resp->body ? strlen(location) : 0;
	strcpy(resp->content_type, "text/plain");
	snprintf(resp->extra_headers, sizeof(resp->extra_headers), "Location: %s\r\n", location);
	free(location);
	return SSO_OK;
}

static bool verify_client_secret(const char* input_secret, const char* stored_hash) {
	if (!input_secret || !stored_hash)
		return false;
	return crypto_pwhash_str_verify(stored_hash, input_secret, strlen(input_secret)) == 0;
}

/* ========================================================================
 * POST /api/v1/oauth/token
 *
 *   grant_type=authorization_code
 *     code=<auth_code>
 *     redirect_uri=<redirect_uri>
 *     client_id=<id>
 *     client_secret=<secret>
 *
 *   grant_type=client_credentials
 *     client_id=<id>
 *     client_secret=<secret>
 *     scope=<scopes>
 *
 *   grant_type=refresh_token
 *     refresh_token=<token>
 *
 * Returns: { access_token, token_type, expires_in, refresh_token, id_token? }
 * ======================================================================== */
sso_error_t handle_oauth_token(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	const sso_config_t* cfg = get_cfg(ctx);
	if (!cfg || !cfg->oauth_client_id[0]) {
		json_error_response(resp, 400, "oauth_not_configured");
		return SSO_OK;
	}
	if (!req->body) {
		json_error_response(resp, 400, "invalid_request");
		return SSO_OK;
	}

	char* grant_type	= json_str_value(req->body, "grant_type");
	char* code			= json_str_value(req->body, "code");
	char* redirect_uri	= json_str_value(req->body, "redirect_uri");
	char* client_id		= json_str_value(req->body, "client_id");
	char* client_secret = json_str_value(req->body, "client_secret");
	char* refresh_token = json_str_value(req->body, "refresh_token");
	char* scope			= json_str_value(req->body, "scope");

	sso_error_t		   result = SSO_OK;
	token_manager_t*   tmgr	  = get_token_mgr(ctx);
	storage_backend_t* sb	  = get_storage(ctx);
	user_manager_t*	   umgr	  = get_user_mgr(ctx);
	token_t			   access_token;
	memset(&access_token, 0, sizeof(access_token));
	char* buf = NULL;

	char dpop_jkt[64] = {0};
	if (req->dpop_proof[0]) {
		char full_url[1024];
		snprintf(full_url, sizeof(full_url), "http://%s%s", req->host[0] ? req->host : "localhost", req->path);
		if (dpop_verify_proof(req->dpop_proof, req->method_str, full_url, NULL, dpop_jkt) != SSO_OK) {
			json_error_response(resp, 400, "invalid_dpop_proof");
			goto cleanup;
		}
	}

	if (!grant_type) {
		json_error_response(resp, 400, "invalid_request");
		goto cleanup;
	}

	if (strcmp(grant_type, "authorization_code") == 0) {
		/* Authorization Code Grant */
		if (!code || !redirect_uri) {
			json_error_response(resp, 400, "invalid_request");
			goto cleanup;
		}

		if (!sb || !sb->oauth_code_get || !sb->oauth_code_mark_used) {
			json_error_response(resp, 500, "server_error");
			goto cleanup;
		}

		oauth_auth_code_t ac;
		memset(&ac, 0, sizeof(ac));
		sso_error_t cerr = sb->oauth_code_get(sb, code, &ac);
		if (cerr != SSO_OK) {
			json_error_response(resp, 400, "invalid_grant");
			goto cleanup;
		}

		if (ac.used) {
			json_error_response(resp, 400, "invalid_grant");
			goto cleanup;
		}

		if (sso_timestamp_now() > ac.expires_at) {
			json_error_response(resp, 400, "invalid_grant");
			goto cleanup;
		}

		if (strcmp(ac.redirect_uri, redirect_uri) != 0) {
			json_error_response(resp, 400, "invalid_grant");
			goto cleanup;
		}

		/* Verify PKCE if a challenge was saved for this code */
		if (ac.code_challenge[0] != '\0') {
			char* code_verifier = json_str_value(req->body, "code_verifier");
			if (!verify_pkce(code_verifier, ac.code_challenge, ac.code_challenge_method)) {
				json_error_response(resp, 400, "invalid_grant");
				goto cleanup;
			}
		}

		/* Mark code as used (prevent replay) */
		sb->oauth_code_mark_used(sb, ac.code);

		/* Issue access token for the user */
		user_t		user;
		sso_error_t uerr = user_get_by_id(umgr, ac.user_id, &user);
		if (uerr != SSO_OK || user.status != USER_STATUS_ACTIVE) {
			json_error_response(resp, 403, "user_inactive");
			goto cleanup;
		}

		sso_id_t roles[16], groups[16];
		size_t	 rc = 0, gc = 0;
		user_get_roles(umgr, user.id, roles, &rc, 16);
		user_get_groups(umgr, user.id, groups, &gc, 16);

		/* Set OAuth fields on token */
		long ttl = get_client_token_ttl(cfg, sb, ac.client_id);

		sso_error_t terr = token_issue(tmgr, &user, roles, rc, groups, gc, ac.scope, ttl, dpop_jkt, &access_token);
		if (terr != SSO_OK) {
			json_error_response(resp, 500, "server_error");
			goto cleanup;
		}
		if (ac.nonce[0])
			snprintf(access_token.oauth_nonce, sizeof(access_token.oauth_nonce), "%s", ac.nonce);

		/* Store generated Refresh Token on issue */
		store_refresh_token(sb, user.id, ac.client_id, access_token.raw_refresh_token);

		/* Build JSON response */
		buf = (char*)malloc(8192);
		if (!buf) {
			json_error_response(resp, 500, "Out of memory");
			result = SSO_OK;
			goto cleanup;
		}
		bool is_openid = (strstr(ac.scope, "openid") != NULL);
		if (is_openid) {
			snprintf(buf, 8192,
					 "{"
					 "\"access_token\":\"%s\","
					 "\"token_type\":\"Bearer\","
					 "\"expires_in\":%lld,"
					 "\"refresh_token\":\"%s\","
					 "\"id_token\":\"%s\","
					 "\"user_id\":%llu"
					 "}",
					 access_token.token_str, (long long)(access_token.expires_at - access_token.issued_at) / 1000,
					 access_token.raw_refresh_token, access_token.token_str, (unsigned long long)user.id);
		} else {
			snprintf(buf, 8192,
					 "{"
					 "\"access_token\":\"%s\","
					 "\"token_type\":\"Bearer\","
					 "\"expires_in\":%lld,"
					 "\"refresh_token\":\"%s\","
					 "\"user_id\":%llu"
					 "}",
					 access_token.token_str, (long long)(access_token.expires_at - access_token.issued_at) / 1000,
					 access_token.raw_refresh_token, (unsigned long long)user.id);
		}
		sso_response_ok(resp, buf);

	} else if (strcmp(grant_type, "client_credentials") == 0) {
		/* Client Credentials Grant */
		if (!client_id || !client_secret) {
			json_error_response(resp, 400, "invalid_request");
			goto cleanup;
		}

		oauth_client_t db_client;
		memset(&db_client, 0, sizeof(db_client));

		if (cfg && cfg->oauth_client_id[0] && strcmp(client_id, cfg->oauth_client_id) == 0) {
			if (strcmp(client_secret, cfg->oauth_client_secret) != 0) {
				json_error_response(resp, 401, "invalid_client");
				goto cleanup;
			}
		} else {
			if (sb && sb->oauth_client_get) {
				if (sb->oauth_client_get(sb, client_id, &db_client) != SSO_OK || db_client.status != 1) {
					json_error_response(resp, 401, "invalid_client");
					goto cleanup;
				}
				if (!verify_client_secret(client_secret, db_client.client_secret_hash)) {
					json_error_response(resp, 401, "invalid_client");
					goto cleanup;
				}
				// Check allowed grant types
				if (db_client.allowed_grant_types[0] != '\0' &&
					!strstr(db_client.allowed_grant_types, "client_credentials")) {
					json_error_response(resp, 400, "unauthorized_client");
					goto cleanup;
				}
			} else {
				json_error_response(resp, 401, "invalid_client");
				goto cleanup;
			}
		}

		/* Create a minimal token for a "client" (user_id=0) */
		user_t client_user;
		memset(&client_user, 0, sizeof(client_user));
		client_user.id = 0;
		sso_strlcpy(client_user.username, "oauth_client", sizeof(client_user.username));
		client_user.username[sizeof(client_user.username) - 1] = '\0';
		client_user.status									   = USER_STATUS_ACTIVE;

		long ttl = get_client_token_ttl(cfg, sb, client_id);

		sso_error_t terr = token_issue(tmgr, &client_user, NULL, 0, NULL, 0, scope, ttl, dpop_jkt, &access_token);
		if (terr != SSO_OK) {
			json_error_response(resp, 500, "server_error");
			goto cleanup;
		}

		buf = (char*)malloc(8192);
		if (!buf) {
			json_error_response(resp, 500, "Out of memory");
			result = SSO_OK;
			goto cleanup;
		}
		snprintf(buf, 8192,
				 "{"
				 "\"access_token\":\"%s\","
				 "\"token_type\":\"Bearer\","
				 "\"expires_in\":%lld"
				 "}",
				 access_token.token_str, (long long)(access_token.expires_at - access_token.issued_at) / 1000);
		sso_response_ok(resp, buf);

	} else if (strcmp(grant_type, "refresh_token") == 0) {
		/* Refresh Token Grant */
		if (!refresh_token) {
			json_error_response(resp, 400, "invalid_request");
			goto cleanup;
		}

		unsigned char rt_hash_bytes[32];
		crypto_hash_sha256(rt_hash_bytes, (const unsigned char*)refresh_token, strlen(refresh_token));
		char rt_hash_hex[65];
		for (size_t i = 0; i < 32; i++) {
			sprintf(&rt_hash_hex[i * 2], "%02x", rt_hash_bytes[i]);
		}

		refresh_token_t rt_record;
		if (!sb || !sb->refresh_token_get || sb->refresh_token_get(sb, rt_hash_hex, &rt_record) != SSO_OK) {
			json_error_response(resp, 400, "invalid_grant");
			goto cleanup;
		}

		if (rt_record.revoked || sso_timestamp_now() > rt_record.expires_at) {
			json_error_response(resp, 400, "invalid_grant");
			goto cleanup;
		}

		/* Issue new access token */
		user_t user;
		if (user_get_by_id(umgr, rt_record.user_id, &user) != SSO_OK || user.status != USER_STATUS_ACTIVE) {
			json_error_response(resp, 403, "user_inactive");
			goto cleanup;
		}

		sso_id_t roles[16], groups[16];
		size_t	 rc = 0, gc = 0;
		user_get_roles(umgr, user.id, roles, &rc, 16);
		user_get_groups(umgr, user.id, groups, &gc, 16);

		long		ttl	 = get_client_token_ttl(cfg, sb, rt_record.client_id);
		sso_error_t terr = token_issue(tmgr, &user, roles, rc, groups, gc, NULL, ttl, dpop_jkt, &access_token);
		if (terr != SSO_OK) {
			json_error_response(resp, 500, "server_error");
			goto cleanup;
		}

		/* Revoke old refresh token (one-time use) */
		sb->refresh_token_revoke(sb, rt_hash_hex);

		/* Store new refresh token */
		store_refresh_token(sb, user.id, rt_record.client_id, access_token.raw_refresh_token);

		buf = (char*)malloc(8192);
		if (!buf) {
			json_error_response(resp, 500, "Out of memory");
			result = SSO_OK;
			goto cleanup;
		}
		snprintf(buf, 8192,
				 "{"
				 "\"access_token\":\"%s\","
				 "\"token_type\":\"Bearer\","
				 "\"expires_in\":%lld,"
				 "\"refresh_token\":\"%s\""
				 "}",
				 access_token.token_str, (long long)(access_token.expires_at - access_token.issued_at) / 1000,
				 access_token.raw_refresh_token);
		sso_response_ok(resp, buf);
	} else {
		json_error_response(resp, 400, "unsupported_grant_type");
	}

cleanup:
	free(buf);
	free(grant_type);
	free(code);
	free(redirect_uri);
	free(client_id);
	free(client_secret);
	free(refresh_token);
	free(scope);
	token_destroy(&access_token);
	return result;
}

/* ========================================================================
 * POST /api/v1/oauth/introspect  (RFC 7662)
 *
 * Validates a token and returns active=true/false + meta.
 * ======================================================================== */
sso_error_t handle_oauth_introspect(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		json_error_response(resp, 400, "invalid_request");
		return SSO_OK;
	}

	char* token_str = json_str_value(req->body, "token");
	if (!token_str) {
		json_error_response(resp, 400, "invalid_request");
		return SSO_OK;
	}

	token_manager_t* tmgr = get_token_mgr(ctx);
	token_t			 decoded;
	sso_error_t		 verr = token_verify(tmgr, token_str, &decoded);

	char* buf = (char*)malloc(4096);
	if (!buf) {
		free(token_str);
		token_destroy(&decoded);
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	if (verr == SSO_OK) {
		bool revoked = token_is_revoked(tmgr, decoded.jti);
		snprintf(buf, 4096,
				 "{"
				 "\"active\":%s,"
				 "\"jti\":\"%s\","
				 "\"sub\":%llu,"
				 "\"iat\":%lld,"
				 "\"exp\":%lld,"
				 "\"token_type\":\"Bearer\","
				 "\"scope\":\"%s\""
				 "}",
				 revoked ? "false" : "true", decoded.jti, (unsigned long long)decoded.user_id,
				 (long long)decoded.issued_at, (long long)decoded.expires_at, decoded.scope);
	} else {
		snprintf(buf, 4096, "{\"active\":false}");
	}

	sso_response_ok(resp, buf);
	free(buf);
	free(token_str);
	token_destroy(&decoded);
	return SSO_OK;
}

/* ========================================================================
 * POST /api/v1/oauth/revoke  (RFC 7009)
 *
 * Revokes a token by adding its jti to the blocklist.
 * Always returns 200 even if the token was already invalid (to prevent
 * token enumeration).
 * ======================================================================== */
sso_error_t handle_oauth_revoke(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		json_error_response(resp, 400, "invalid_request");
		return SSO_OK;
	}

	char* token_str = json_str_value(req->body, "token");
	if (!token_str) {
		json_error_response(resp, 400, "invalid_request");
		return SSO_OK;
	}

	token_manager_t* tmgr = get_token_mgr(ctx);
	token_t			 decoded;
	sso_error_t		 verr = token_verify(tmgr, token_str, &decoded);

	if (verr == SSO_OK) {
		token_revoke(tmgr, decoded.jti, decoded.expires_at);
	}

	/* Always return 200 to prevent token enumeration */
	sso_response_ok(resp, "{\"status\":\"ok\"}");
	free(token_str);
	token_destroy(&decoded);
	return SSO_OK;
}

/* ========================================================================
 * GET /.well-known/openid-configuration
 *
 * OIDC Discovery document.
 * ======================================================================== */
sso_error_t handle_well_known_openid_config(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	sso_config_t* cfg	 = get_cfg(ctx);
	const char*	  issuer = cfg && cfg->oauth_issuer[0] ? cfg->oauth_issuer : "http://localhost:8080";

	char* buf = (char*)malloc(4096);
	if (!buf) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	snprintf(buf, 4096,
			 "{"
			 "\"issuer\":\"%s\","
			 "\"authorization_endpoint\":\"%s/api/v1/oauth/authorize\","
			 "\"token_endpoint\":\"%s/api/v1/oauth/token\","
			 "\"userinfo_endpoint\":\"%s/api/v1/auth/userinfo\","
			 "\"introspection_endpoint\":\"%s/api/v1/oauth/introspect\","
			 "\"revocation_endpoint\":\"%s/api/v1/oauth/revoke\","
			 "\"end_session_endpoint\":\"%s/api/v1/oauth/end-session\","
			 "\"jwks_uri\":\"%s/api/v1/auth/jwks\","
			 "\"scopes_supported\":[\"openid\",\"profile\"],"
			 "\"response_types_supported\":[\"code\"],"
			 "\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\"],"
			 "\"subject_types_supported\":[\"public\"],"
			 "\"id_token_signing_alg_values_supported\":[\"HS256\",\"RS256\"],"
			 "\"token_endpoint_auth_methods_supported\":[\"client_secret_post\"]"
			 "}",
			 issuer, issuer, issuer, issuer, issuer, issuer, issuer, issuer);
	sso_response_ok(resp, buf);
	free(buf);
	return SSO_OK;
}

/* ========================================================================
 * GET /api/v1/auth/jwks
 *
 * JWKS (JSON Web Key Set) — returns the public key for RS256 mode.
 * For HS256, returns an empty keys array (symmetric mode does not publish
 * the key via JWKS).
 * ======================================================================== */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
sso_error_t handle_jwks(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	token_manager_t* tmgr = get_token_mgr(ctx);
	if (!tmgr) {
		json_error_response(resp, 500, "server_error");
		return SSO_OK;
	}

	if (tmgr->mode != SSO_TOKEN_MODE_RS256 || !tmgr->keys.rsa.pub_key) {
		sso_response_ok(resp, "{\"keys\":[]}");
		return SSO_OK;
	}

	EVP_PKEY* pkey = (EVP_PKEY*)tmgr->keys.rsa.pub_key;
	RSA*	  rsa  = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		json_error_response(resp, 500, "server_error");
		return SSO_OK;
	}

	const BIGNUM* n_bn = NULL;
	const BIGNUM* e_bn = NULL;
	RSA_get0_key(rsa, &n_bn, &e_bn, NULL);
	if (!n_bn || !e_bn) {
		RSA_free(rsa);
		json_error_response(resp, 500, "server_error");
		return SSO_OK;
	}

	unsigned char* n_bytes = malloc(BN_num_bytes(n_bn));
	unsigned char* e_bytes = malloc(BN_num_bytes(e_bn));
	if (!n_bytes || !e_bytes) {
		free(n_bytes);
		free(e_bytes);
		RSA_free(rsa);
		json_error_response(resp, 500, "server_error");
		return SSO_OK;
	}

	int n_len = BN_bn2bin(n_bn, n_bytes);
	int e_len = BN_bn2bin(e_bn, e_bytes);

	/* Allocate buffer for base64url encoding (around 2x binary size is safe) */
	char* n_b64 = malloc(n_len * 2 + 10);
	char* e_b64 = malloc(e_len * 2 + 10);
	if (!n_b64 || !e_b64) {
		free(n_bytes);
		free(e_bytes);
		free(n_b64);
		free(e_b64);
		RSA_free(rsa);
		json_error_response(resp, 500, "server_error");
		return SSO_OK;
	}

	base64url_encode(n_bytes, n_len, n_b64, n_len * 2 + 10);
	base64url_encode(e_bytes, e_len, e_b64, e_len * 2 + 10);

	char* buf = (char*)malloc(4096);
	if (!buf) {
		free(n_bytes);
		free(e_bytes);
		free(n_b64);
		free(e_b64);
		RSA_free(rsa);
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	snprintf(buf, 4096,
			 "{"
			 "\"keys\":[{"
			 "\"kty\":\"RSA\","
			 "\"alg\":\"RS256\","
			 "\"use\":\"sig\","
			 "\"kid\":\"sso-key-1\","
			 "\"n\":\"%s\","
			 "\"e\":\"%s\""
			 "}]"
			 "}",
			 n_b64, e_b64);

	free(n_bytes);
	free(e_bytes);
	free(n_b64);
	free(e_b64);
	RSA_free(rsa);

	sso_response_ok(resp, buf);
	free(buf);
	return SSO_OK;
}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* ========================================================================
 * GET /api/v1/auth/userinfo
 *
 * OIDC UserInfo endpoint. Returns claims about the authenticated user.
 * Requires a valid Bearer token (handled by require_auth middleware).
 * ======================================================================== */
sso_error_t handle_userinfo(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)ctx;
	if (!req->userdata) {
		json_error_response(resp, 401, "unauthorized");
		return SSO_OK;
	}
	const auth_context_t* auth = (const auth_context_t*)req->userdata;
	const user_t*		  user = &auth->user;

	char* buf = (char*)malloc(4096);
	if (!buf) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	snprintf(buf, 4096,
			 "{"
			 "\"sub\":%llu,"
			 "\"preferred_username\":\"%s\","
			 "\"email\":\"%s\","
			 "\"name\":\"%s\""
			 "}",
			 (unsigned long long)user->id, user->username, user->email, user->display_name);
	sso_response_ok(resp, buf);
	free(buf);
	return SSO_OK;
}

static const char* get_query_param(const http_request_t* req, const char* key) {
	if (!req->query_params)
		return NULL;
	size_t key_len = strlen(key);
	for (size_t i = 0; req->query_params[i]; i++) {
		const char* eq = strchr(req->query_params[i], '=');
		if (eq) {
			size_t klen = (size_t)(eq - req->query_params[i]);
			if (klen == key_len && strncmp(req->query_params[i], key, key_len) == 0) {
				return eq + 1;
			}
		}
	}
	return NULL;
}

sso_error_t handle_oauth_end_session(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	token_manager_t* tmgr					  = get_token_mgr(ctx);
	const char*		 id_token_hint			  = get_query_param(req, "id_token_hint");
	const char*		 post_logout_redirect_uri = get_query_param(req, "post_logout_redirect_uri");
	const char*		 state					  = get_query_param(req, "state");

	token_t token;
	memset(&token, 0, sizeof(token));
	if (id_token_hint) {
		if (token_verify(tmgr, id_token_hint, &token) == SSO_OK) {
			token_revoke(tmgr, token.jti, token.expires_at);
			token_bump_nonce(tmgr, token.user_id);
			token_destroy(&token);
		}
	}

	auth_context_t* auth = (auth_context_t*)req->userdata;
	if (auth) {
		token_revoke(tmgr, auth->token.jti, auth->token.expires_at);
		token_bump_nonce(tmgr, auth->user.id);
	}

	bool redirect_allowed = false;
	if (post_logout_redirect_uri) {
		sso_config_t* cfg = get_cfg(ctx);
		if (cfg && cfg->oauth_redirect_uris[0] &&
			is_redirect_uri_allowed(cfg->oauth_redirect_uris, post_logout_redirect_uri)) {
			redirect_allowed = true;
		} else {
			storage_backend_t* sb = get_storage(ctx);
			oauth_client_t	   clients[64];
			size_t			   count = 0;
			if (sb && sb->oauth_client_list && sb->oauth_client_list(sb, 0, 64, clients, &count, 64) == SSO_OK) {
				for (size_t i = 0; i < count; i++) {
					if (is_redirect_uri_allowed(clients[i].redirect_uris, post_logout_redirect_uri)) {
						redirect_allowed = true;
						break;
					}
				}
			}
		}
	}

	if (redirect_allowed && post_logout_redirect_uri) {
		char* redirect_url = (char*)malloc(1024);
		if (!redirect_url) {
			sso_response_error(resp, 500, "Out of memory");
			return SSO_OK;
		}
		if (state) {
			snprintf(redirect_url, 1024, "%s%cstate=%s", post_logout_redirect_uri,
					 strchr(post_logout_redirect_uri, '?') ? '&' : '?', state);
		} else {
			snprintf(redirect_url, 1024, "%s", post_logout_redirect_uri);
		}
		resp->status_code = 302;
		snprintf(resp->extra_headers, sizeof(resp->extra_headers), "Location: %s\r\n", redirect_url);
		free(redirect_url);
		resp->body	   = strdup("");
		resp->body_len = 0;
	} else {
		sso_response_ok(resp, "{\"status\":\"logged_out\"}");
	}

	return SSO_OK;
}
