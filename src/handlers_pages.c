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

sso_error_t handle_health(sso_context_t *ctx, const http_request_t *req,
                                  http_response_t *resp) {
    (void)ctx; (void)req;
    sso_response_ok(resp, "{"
        "\"status\":\"ok\","
        "\"service\":\"sso\","
        "\"version\":\"1.0.0\""
    "}");
    return SSO_OK;
}

sso_error_t handle_metrics(sso_context_t *ctx, const http_request_t *req,
                                    http_response_t *resp) {
    (void)req;
    char buf[4096];
    if (perm_engine_get_metrics((permission_engine_t *)ctx->perm_engine, buf, sizeof(buf)) != SSO_OK) {
        sso_response_error(resp, 500, "Failed to retrieve metrics");
        return SSO_OK;
    }
    
    resp->status_code = 200;
    resp->body = strdup(buf);
    resp->body_len = strlen(buf);
    strcpy(resp->content_type, "text/plain; version=0.0.4; charset=utf-8");
    return SSO_OK;
}

sso_error_t handle_admin_status(sso_context_t *ctx, const http_request_t *req,
                                         http_response_t *resp) {
    (void)req;
    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    size_t user_count = 0;
    sso_id_t ids[1];
    user_list(umgr, NULL, -1, 0, 0, ids, &user_count, &user_count);

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{"
        "\"service\":\"sso\","
        "\"version\":\"1.0.0\","
        "\"users\":%zu,"
        "\"uptime_ms\":%llu"
        "}",
        user_count,
        (unsigned long long)get_time_ms());
    sso_response_ok(resp, buf);
    return SSO_OK;
}

sso_error_t handle_list_audit_logs(sso_context_t *ctx, const http_request_t *req,
                                            http_response_t *resp) {
    const char *log_path = "audit.log";
    if (ctx && ctx->config) {
        sso_config_t *cfg = (sso_config_t *)ctx->config;
        if (cfg->audit_log_path[0]) {
            log_path = cfg->audit_log_path;
        }
    }
    FILE *f = fopen(log_path, "r");
    if (!f) {
        sso_response_ok(resp, "[]");
        return SSO_OK;
    }

    /* Parse query params: user_id filter, limit, offset */
    sso_id_t filter_uid = SSO_ID_NONE;
    int limit = 100, offset_local = 0;
    if (req->query_params) {
        for (size_t i = 0; req->query_params[i]; i++) {
            char *eq = strchr(req->query_params[i], '=');
            if (!eq) continue;
            *eq++ = '\0';
            if (strcmp(req->query_params[i], "user_id") == 0) filter_uid = (sso_id_t)atoll(eq);
            if (strcmp(req->query_params[i], "limit") == 0) { int v = atoi(eq); if (v > 0 && v <= 1000) limit = v; }
            if (strcmp(req->query_params[i], "offset") == 0) { int v = atoi(eq); if (v > 0) offset_local = v; }
        }
    }

    /* Read matching lines into a growing buffer */
    size_t cap = 4096, total = 0, match_idx = 0;
    char *json = (char *)malloc(cap);
    if (!json) { fclose(f); sso_response_error(resp, 500, "Out of memory"); return SSO_OK; }
    json[0] = '['; total = 1;
    bool first = true;
    char buffer[10240];
    size_t line_num = 0;

    while (fgets(buffer, sizeof(buffer), f)) {
        line_num++;
        if (offset_local > 0 && line_num <= (size_t)offset_local) continue;
        if (filter_uid != SSO_ID_NONE) {
            char uid_str[32];
            snprintf(uid_str, sizeof(uid_str), "\"user_id\":%llu", (unsigned long long)filter_uid);
            if (!strstr(buffer, uid_str)) continue;
        }

        char *nl = strchr(buffer, '\n');
        if (nl) *nl = '\0';

        size_t needed = total + strlen(buffer) + 3;
        if (needed > cap) {
            cap = needed * 2;
            char *new_json = (char *)realloc(json, cap);
            if (!new_json) { free(json); fclose(f); sso_response_error(resp, 500, "Out of memory"); return SSO_OK; }
            json = new_json;
        }

        if (!first) json[total++] = ',';
        first = false;
        memcpy(json + total, buffer, strlen(buffer));
        total += strlen(buffer);

        if (++match_idx >= (size_t)limit) break;
    }
    fclose(f);
    json[total++] = ']';
    json[total] = '\0';

    sso_response_ok(resp, json);
    free(json);
    return SSO_OK;
}
