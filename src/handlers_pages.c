/*
 * handlers_pages.c — Public page and monitoring HTTP handlers.
 *
 * Implements the /health (liveness probe), /metrics (Prometheus
 * instrumentation), /admin/status (system administration status),
 * and audit log retrieval endpoints.  These endpoints are unauthenticated
 * or rely on embedded HTML/JS for admin UI presentation.
 */

#include "sso.h"
#include "server.h"
#include "logger.h"
#include "handlers.h"
#include "permission.h"
#include "storage.h"
#include "user.h"
#include "role.h"

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

sso_error_t handle_health(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	/* Check storage backend readiness */
	bool db_ready = false;
	if (ctx && ctx->storage_backend) {
		storage_backend_t* sb = ctx->storage_backend;
		/* Use a lightweight ping: try to list users with limit=0 */
		sso_id_t dummy_ids[1];
		size_t	 count = 0, total = 0;
		if (sb->user_list) {
			sso_error_t err = sb->user_list(sb, NULL, -1, 0, 0, dummy_ids, &count, &total);
			db_ready		= (err == SSO_OK || err == SSO_ERR_NOT_FOUND);
		}
	}

	char buf[512];
	snprintf(buf, sizeof(buf),
			 "{"
			 "\"status\":\"ok\","
			 "\"service\":\"sso\","
			 "\"version\":\"1.1.0\","
			 "\"checks\":{"
			 "\"database\":{\"status\":\"%s\"}"
			 "}"
			 "}",
			 db_ready ? "ready" : "unavailable");
	sso_response_ok(resp, buf);
	return SSO_OK;
}

sso_error_t handle_metrics(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	char* perm_buf = (char*)arena_alloc((arena_t*)&req->arena, 2048);
	char* buf	   = (char*)arena_alloc((arena_t*)&req->arena, 8192);
	if (!perm_buf || !buf) {
		/* free(perm_buf); */
		/* free(buf); */
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	if (perm_engine_get_metrics((permission_engine_t*)ctx->perm_engine, perm_buf, 2048) != SSO_OK) {
		/* free(perm_buf); */
		/* free(buf); */
		sso_response_error(resp, 500, "Failed to retrieve metrics");
		return SSO_OK;
	}

	int				   active_conn			= atomic_load(&g_metric_active_connections);
	unsigned long long mfa_success			= atomic_load(&g_metric_mfa_success);
	unsigned long long mfa_failure			= atomic_load(&g_metric_mfa_failure);
	unsigned long long jwt_issue			= atomic_load(&g_metric_jwt_issue);
	unsigned long long jwt_revoke			= atomic_load(&g_metric_jwt_revoke);
	unsigned long long db_read_count		= atomic_load(&g_metric_db_read_count);
	unsigned long long db_read_duration_us	= atomic_load(&g_metric_db_read_duration_us);
	unsigned long long db_write_count		= atomic_load(&g_metric_db_write_count);
	unsigned long long db_write_duration_us = atomic_load(&g_metric_db_write_duration_us);
	unsigned long long arena_blocks			= atomic_load(&g_metric_arena_blocks);

	double db_read_avg_ms  = db_read_count > 0 ? ((double)db_read_duration_us / db_read_count) / 1000.0 : 0.0;
	double db_write_avg_ms = db_write_count > 0 ? ((double)db_write_duration_us / db_write_count) / 1000.0 : 0.0;

	snprintf(buf, 8192,
			 "%s"
			 "# HELP sso_active_connections Active HTTP connections currently being processed\n"
			 "# TYPE sso_active_connections gauge\n"
			 "sso_active_connections %d\n"
			 "# HELP sso_mfa_verifications_total Total MFA verification attempts\n"
			 "# TYPE sso_mfa_verifications_total counter\n"
			 "sso_mfa_verifications_total{result=\"success\"} %llu\n"
			 "sso_mfa_verifications_total{result=\"failure\"} %llu\n"
			 "# HELP sso_jwt_tokens_total Total JWT tokens processed\n"
			 "# TYPE sso_jwt_tokens_total counter\n"
			 "sso_jwt_tokens_total{action=\"issue\"} %llu\n"
			 "sso_jwt_tokens_total{action=\"revoke\"} %llu\n"
			 "# HELP sso_db_queries_total Total number of database queries executed\n"
			 "# TYPE sso_db_queries_total counter\n"
			 "sso_db_queries_total{type=\"read\"} %llu\n"
			 "sso_db_queries_total{type=\"write\"} %llu\n"
			 "# HELP sso_db_query_duration_seconds_total Cumulative database query execution duration in seconds\n"
			 "# TYPE sso_db_query_duration_seconds_total counter\n"
			 "sso_db_query_duration_seconds_total{type=\"read\"} %.6f\n"
			 "sso_db_query_duration_seconds_total{type=\"write\"} %.6f\n"
			 "# HELP sso_db_query_duration_seconds_avg Average database query duration in seconds\n"
			 "# TYPE sso_db_query_duration_seconds_avg gauge\n"
			 "sso_db_query_duration_seconds_avg{type=\"read\"} %.6f\n"
			 "sso_db_query_duration_seconds_avg{type=\"write\"} %.6f\n"
			 "# HELP sso_arena_allocated_blocks_total Total number of memory blocks allocated in Arenas\n"
			 "# TYPE sso_arena_allocated_blocks_total gauge\n"
			 "sso_arena_allocated_blocks_total %llu\n",
			 perm_buf, active_conn, mfa_success, mfa_failure, jwt_issue, jwt_revoke, db_read_count, db_write_count,
			 (double)db_read_duration_us / 1000000.0, (double)db_write_duration_us / 1000000.0, db_read_avg_ms / 1000.0,
			 db_write_avg_ms / 1000.0, arena_blocks);

	resp->status_code = 200;
	resp->body		  = strdup(buf);
	resp->body_len	  = strlen(buf);
	strcpy(resp->content_type, "text/plain; version=0.0.4; charset=utf-8");
	/* free(perm_buf); */
	/* free(buf); */
	return SSO_OK;
}

sso_error_t handle_admin_status(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	user_manager_t* umgr	   = (user_manager_t*)ctx->user_mgr;
	size_t			user_count = 0;
	sso_id_t		ids[1];
	user_list(umgr, NULL, -1, 0, 0, ids, &user_count, &user_count);

	char* buf = (char*)arena_alloc((arena_t*)&req->arena, 2048);
	if (!buf) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	snprintf(buf, 2048,
			 "{"
			 "\"service\":\"sso\","
			 "\"version\":\"1.0.0\","
			 "\"users\":%zu,"
			 "\"uptime_ms\":%llu"
			 "}",
			 user_count, (unsigned long long)get_time_ms());
	sso_response_ok(resp, buf);
	/* free(buf); */
	return SSO_OK;
}

sso_error_t handle_list_audit_logs(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	/* Parse query params: user_id filter, limit, offset */
	sso_id_t filter_uid = SSO_ID_NONE;
	int		 limit = 100, offset_local = 0;
	if (req->query_params) {
		for (size_t i = 0; req->query_params[i]; i++) {
			char* eq = strchr(req->query_params[i], '=');
			if (!eq)
				continue;
			*eq++ = '\0';
			if (strcmp(req->query_params[i], "user_id") == 0)
				filter_uid = (sso_id_t)atoll(eq);
			if (strcmp(req->query_params[i], "limit") == 0) {
				int v = atoi(eq);
				if (v > 0 && v <= 1000)
					limit = v;
			}
			if (strcmp(req->query_params[i], "offset") == 0) {
				int v = atoi(eq);
				if (v > 0)
					offset_local = v;
			}
		}
	}

	/* 1. Try to read from database if supported */
	if (ctx && ctx->storage_backend) {
		storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
		if (sb->audit_log_list) {
			char*  json		   = NULL;
			size_t total_count = 0;
			if (sb->audit_log_list(sb, filter_uid, offset_local, limit, &json, &total_count) == SSO_OK && json) {
				sso_response_ok(resp, json);
				/* free(json); */
				return SSO_OK;
			}
		}
	}

	/* 2. Fallback to file logs */
	const char*	  log_path = "audit.log";
	sso_config_t* cfg	   = sso_get_config(ctx);
	if (cfg) {
		if (cfg->audit_log_path[0]) {
			log_path = cfg->audit_log_path;
		}
	}
	FILE* f = fopen(log_path, "r");
	if (!f) {
		sso_response_ok(resp, "[]");
		return SSO_OK;
	}

	/* Read matching lines into a growing buffer */
	size_t cap = 4096, total = 0, match_idx = 0;
	char*  json = (char*)arena_alloc((arena_t*)&req->arena, cap);
	if (!json) {
		fclose(f);
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	json[0]		 = '[';
	total		 = 1;
	bool  first	 = true;
	char* buffer = (char*)arena_alloc((arena_t*)&req->arena, 10240);
	if (!buffer) {
		/* free(json); */
		fclose(f);
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	size_t line_num = 0;

	while (fgets(buffer, 10240, f)) {
		line_num++;
		if (offset_local > 0 && line_num <= (size_t)offset_local)
			continue;
		if (filter_uid != SSO_ID_NONE) {
			char uid_str[32];
			snprintf(uid_str, sizeof(uid_str), "\"user_id\":%llu", (unsigned long long)filter_uid);
			if (!strstr(buffer, uid_str))
				continue;
		}

		char* nl = strchr(buffer, '\n');
		if (nl)
			*nl = '\0';

		size_t needed = total + strlen(buffer) + 3;
		if (needed > cap) {
			cap			   = needed * 2;
			char* new_json = (char*)realloc(json, cap);
			if (!new_json) {
				/* free(json); */
				/* free(buffer); */
				fclose(f);
				sso_response_error(resp, 500, "Out of memory");
				return SSO_OK;
			}
			json = new_json;
		}

		if (!first)
			json[total++] = ',';
		first = false;
		memcpy(json + total, buffer, strlen(buffer));
		total += strlen(buffer);

		if (++match_idx >= (size_t)limit)
			break;
	}
	fclose(f);
	json[total++] = ']';
	json[total]	  = '\0';

	sso_response_ok(resp, json);
	/* free(json); */
	/* free(buffer); */
	return SSO_OK;
}

sso_error_t handle_swagger_ui(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)ctx;
	(void)req;
	FILE* f = fopen("docs/swagger-ui.html", "r");
	if (!f) {
		sso_response_error(resp, 404, "Swagger UI template not found");
		return SSO_OK;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char* buf = (char*)arena_alloc((arena_t*)&req->arena, fsize + 1);
	if (!buf) {
		fclose(f);
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	fread(buf, 1, fsize, f);
	fclose(f);
	buf[fsize] = 0;

	resp->status_code = 200;
	resp->body		  = buf;
	resp->body_len	  = fsize;
	strcpy(resp->content_type, "text/html; charset=utf-8");
	return SSO_OK;
}

sso_error_t handle_openapi_yaml(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)ctx;
	(void)req;
	FILE* f = fopen("docs/openapi.yaml", "r");
	if (!f) {
		sso_response_error(resp, 404, "openapi.yaml not found");
		return SSO_OK;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char* buf = (char*)arena_alloc((arena_t*)&req->arena, fsize + 1);
	if (!buf) {
		fclose(f);
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	fread(buf, 1, fsize, f);
	fclose(f);
	buf[fsize] = 0;

	resp->status_code = 200;
	resp->body		  = buf;
	resp->body_len	  = fsize;
	strcpy(resp->content_type, "application/yaml; charset=utf-8");
	return SSO_OK;
}
