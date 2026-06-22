/*
 * handlers_common.c — Shared HTTP handler utilities.
 *
 * Provides JSON helper functions (json_str_value, json_int_value,
 * json_bool_value), standardized error response construction,
 * CORS header injection, auth context extraction middleware, query
 * parameter parsing, and response body building routines used by
 * all handler modules.
 */

#include "sso.h"
#include "server.h"
#include "logger.h"
#include "config.h"

#include "handlers.h"
#include "dpop.h"

#include <curl/curl.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

uint64_t get_time_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

void parse_query_params(const http_request_t* req, char* q, int* status, int* page, int* limit) {
	if (q)
		q[0] = '\0';
	if (status)
		*status = -1;
	if (page)
		*page = 1;
	if (limit)
		*limit = 20;

	if (!req || !req->query_params)
		return;

	for (size_t i = 0; req->query_params[i]; i++) {
		char* param = strdup(req->query_params[i]);
		if (!param)
			continue;
		char* eq = strchr(param, '=');
		if (eq) {
			*eq				= '\0';
			const char* key = param;
			const char* val = eq + 1;
			if (strcmp(key, "q") == 0 && q) {
				sso_strlcpy(q, val, SSO_MAX_QUERY);
				q[SSO_MAX_QUERY - 1] = '\0';
			} else if (strcmp(key, "status") == 0 && status) {
				*status = atoi(val);
			} else if (strcmp(key, "page") == 0 && page) {
				*page = atoi(val);
				if (*page < 1)
					*page = 1;
			} else if (strcmp(key, "limit") == 0 && limit) {
				*limit = atoi(val);
				if (*limit < 1)
					*limit = 1;
				if (*limit > 100)
					*limit = 100;
			}
		}
		free(param);
	}
}

/* Helper: extract numeric ID from a path like /api/v1/xxx/NNN */
sso_id_t extract_path_id(const char* path, const char* prefix) {
	const char* p = strstr(path, prefix);
	if (!p)
		return 0;
	p += strlen(prefix);
	return (sso_id_t)atoll(p);
}

/* -----------------------------------------------------------------------
 * Real SMS sending via libcurl (Generic JSON API)
 * ----------------------------------------------------------------------- */
sso_error_t send_real_sms(const char* phone, const char* code) {
	CURL*		curl;
	CURLcode	res;
	sso_error_t err = SSO_OK;

	curl = curl_easy_init();
	if (!curl) {
		LOG_ERROR("curl_easy_init() failed");
		return SSO_ERR_CURL;
	}

	/* Configuration: in production, load these from environment variables */
	const char* url		= getenv("SSO_SMS_GATEWAY_URL");
	const char* api_key = getenv("SSO_SMS_API_KEY");

	if (!url) {
		LOG_INFO("[SMS] MOCK SEND: Code %s sent to %s (Set SSO_SMS_GATEWAY_URL for real send)", code, phone);
		curl_easy_cleanup(curl);
		return SSO_OK;
	}

	/* Construct JSON body */
	char post_data[512];
	snprintf(post_data, sizeof(post_data), "{\"phone\":\"%s\",\"code\":\"%s\",\"api_key\":\"%s\"}", phone, code,
			 api_key ? api_key : "");

	struct curl_slist* headers = NULL;
	headers					   = curl_slist_append(headers, "Content-Type: application/json");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); /* 5s timeout */

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		LOG_ERROR("[SMS] curl_easy_perform() failed: %s", curl_easy_strerror(res));
		err = SSO_ERR_CURL;
	} else {
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code >= 200 && http_code < 300) {
			LOG_INFO("[SMS] Real SMS request sent to %s (HTTP %ld)", phone, http_code);
		} else {
			LOG_ERROR("[SMS] Gateway returned error: HTTP %ld", http_code);
			err = SSO_ERR_CURL;
		}
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return err;
}

char* json_str_value(const char* json, const char* key) {
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

	/* Find closing quote, respecting all escapes */
	const char* end = p;
	while (*end) {
		if (*end == '\\' && *(end + 1) != '\0') {
			end += 2; /* skip escaped character */
		} else if (*end == '"') {
			break;
		} else {
			end++;
		}
	}

	size_t len = (size_t)(end - p);
	char*  val = (char*)malloc(len + 1);
	if (!val)
		return NULL;
	/* Copy and unescape */
	size_t j = 0;
	for (size_t i = 0; i < len; i++) {
		if (p[i] == '\\' && i + 1 < len) {
			if (p[i + 1] == '"') {
				val[j++] = '"';
				i++;
			} else if (p[i + 1] == '\\') {
				val[j++] = '\\';
				i++;
			} else if (p[i + 1] == '/') {
				val[j++] = '/';
				i++;
			} else if (p[i + 1] == 'b') {
				val[j++] = '\b';
				i++;
			} else if (p[i + 1] == 'f') {
				val[j++] = '\f';
				i++;
			} else if (p[i + 1] == 'n') {
				val[j++] = '\n';
				i++;
			} else if (p[i + 1] == 'r') {
				val[j++] = '\r';
				i++;
			} else if (p[i + 1] == 't') {
				val[j++] = '\t';
				i++;
			} else {
				val[j++] = p[i];
			}
		} else {
			val[j++] = p[i];
		}
	}
	val[j] = '\0';
	return val;
}

/* Find a JSON number (int64) value by key.  Returns default on missing. */
int64_t json_int_value(const char* json, const char* key, int64_t def) {
	if (!json || !key)
		return def;
	char search[128];
	snprintf(search, sizeof(search), "\"%s\"", key);
	const char* p = strstr(json, search);
	if (!p)
		return def;
	p += strlen(search);
	while (*p && *p != ':' && *p != ',')
		p++;
	if (*p == ':')
		p++;
	while (*p && (*p == ' ' || *p == '\t' || *p == '\n'))
		p++;
	return (int64_t)atoll(p);
}

const char* validate_password(const char* password, const password_policy_t* policy) {
	if (!password)
		return "Password required";

	static const password_policy_t default_policy = PASSWORD_POLICY_DEFAULT;
	if (!policy)
		policy = &default_policy;

	size_t len	   = strlen(password);
	int	   min_len = policy->min_length > 0 ? policy->min_length : 8;
	int	   max_len = policy->max_length > 0 ? policy->max_length : 128;
	if ((int)len < min_len)
		return "Password must be at least 8 characters";
	if ((int)len > max_len)
		return "Password must not exceed 128 characters";

	bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)password[i];
		if (c >= 'A' && c <= 'Z')
			has_upper = true;
		else if (c >= 'a' && c <= 'z')
			has_lower = true;
		else if (c >= '0' && c <= '9')
			has_digit = true;
		else if (c > 32 && c < 127)
			has_special = true;
	}
	if (policy->require_upper && !has_upper)
		return "Password must contain an uppercase letter";
	if (policy->require_lower && !has_lower)
		return "Password must contain a lowercase letter";
	if (policy->require_digit && !has_digit)
		return "Password must contain a digit";
	if (policy->require_special && !has_special)
		return "Password must contain a special character";
	return NULL;
}

/* ========================================================================
 * Response helpers (shared by server.c / server_mhd.c)
 * ======================================================================== */
void sso_response_ok(http_response_t* resp, const char* body_json) {
	resp->status_code = 200;
	resp->body		  = strdup(body_json);
	resp->body_len	  = resp->body ? strlen(body_json) : 0;
	strcpy(resp->content_type, "application/json");
}

void sso_response_error(http_response_t* resp, int status_code, const char* message) {
	resp->status_code = status_code;
	LOG_WARN("API Error Response [%d]: %s", status_code, message);
	char buf[1024];
	snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", message);
	resp->body	   = strdup(buf);
	resp->body_len = resp->body ? strlen(buf) : 0;
	strcpy(resp->content_type, "application/json");
}

/* ========================================================================
 * Route matching (shared by server.c / server_mhd.c)
 * ======================================================================== */
bool match_route(const char* pattern, const char* path, char** params) {
	if (!pattern || !path)
		return false;

	while (*pattern && *path) {
		if (*pattern == ':') {
			pattern++;
			while (*pattern && *pattern != '/')
				pattern++;
			while (*path && *path != '/')
				path++;
			if (params) {
			}
		} else if (*pattern == '*') {
			pattern++;
			while (*path && *path != '/')
				path++;
			if (*pattern) {
				return match_route(pattern, path, params);
			}
			return true;
		} else {
			if (*pattern != *path)
				return false;
			pattern++;
			path++;
		}
	}

	if (*pattern == '/' && *path == '\0')
		pattern++;
	if (*path == '/' && *pattern == '\0')
		path++;

	return *pattern == '\0' && *path == '\0';
}

/* ========================================================================
 * Auth middleware (shared by server.c / server_mhd.c)
 * ======================================================================== */
sso_error_t authenticate_request(sso_context_t* ctx, const http_request_t* req, user_t* user, token_t* tok) {
	if (!ctx || !req || !user || !tok)
		return SSO_ERR_INVALID_PARAM;

	if (req->auth_token[0] == '\0')
		return SSO_ERR_AUTH_FAILED;

	token_manager_t* tmgr = (token_manager_t*)ctx->token_mgr;
	sso_error_t		 err  = token_verify(tmgr, req->auth_token, tok);
	if (err != SSO_OK)
		return err;

	if (token_is_revoked(tmgr, tok->jti))
		return SSO_ERR_TOKEN_INVALID;

	if (tok->jkt[0] != '\0') {
		if (req->dpop_proof[0] == '\0') {
			return SSO_ERR_AUTH_FAILED;
		}

		char derived_jkt[64] = {0};
		char full_url[2048];
		snprintf(full_url, sizeof(full_url), "http://%s%s", req->host[0] ? req->host : "localhost", req->path);

		if (dpop_verify_proof(req->dpop_proof, req->method_str, full_url, req->auth_token, derived_jkt) != SSO_OK) {
			return SSO_ERR_AUTH_FAILED;
		}

		if (strcmp(derived_jkt, tok->jkt) != 0) {
			return SSO_ERR_AUTH_FAILED;
		}
	}

	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	sso_error_t		uerr = user_get_by_id(umgr, tok->user_id, user);
	if (uerr != SSO_OK)
		return uerr;

	/* Check user token nonce (supports "logout all sessions") */
	uint64_t expected_nonce = token_get_nonce(tmgr, user->id);
	if (tok->nonce < expected_nonce)
		return SSO_ERR_TOKEN_INVALID;

	return SSO_OK;
}
