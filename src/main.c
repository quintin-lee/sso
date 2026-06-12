/*
 * main.c — SSO system entry point and comprehensive demo.
 *
 * Demonstrates:
 *   1. System initialization with SQLite storage
 *   2. User, role, group CRUD
 *   3. Policy creation for all three strategy types
 *   4. Assignment of roles and policies
 *   5. Permission checks (functional, API, data)
 *   6. Token-based authentication
 *
 * Build:
 *   make
 *
 * Run:
 *   ./sso_system              — runs the demo and exits
 *   ./sso_system --server     — starts the HTTP management API on port 8080
 */

#include "sso.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "permission.h"
#include "token.h"
#include "storage.h"
#include "server.h"
#include "login_page.h"
#include "admin_page.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ========================================================================
 * Built-in login page — serves the embedded HTML login/register UI
 * ======================================================================== */
static sso_error_t handle_login_page(sso_context_t *ctx,
                                      const http_request_t *req,
                                      http_response_t *resp) {
    (void)ctx; (void)req;
    resp->status_code = 200;
    resp->body = strdup(LOGIN_PAGE_HTML);
    resp->body_len = strlen(LOGIN_PAGE_HTML);
    strcpy(resp->content_type, "text/html; charset=utf-8");
    return SSO_OK;
}

/* ========================================================================
 * Demo — comprehensive walkthrough
 * ======================================================================== */
static int run_demo(void) {
    sso_error_t err;
    printf("=== SSO System Demo ===\n\n");

    /* ---- 1. Init SSO context ---- */
    printf("[1] Initialising SSO system...\n");
    storage_backend_t *storage = NULL;
    err = storage_sqlite_create(&storage);
    if (err != SSO_OK) {
        fprintf(stderr, "  Failed to create storage: %s\n", sso_strerror(err));
        return 1;
    }

    sso_context_t ctx;
    err = sso_init(&ctx, storage, "sso_demo.db");
    if (err != SSO_OK) {
        fprintf(stderr, "  Failed to init SSO: %s\n", sso_strerror(err));
        return 1;
    }
    printf("  OK\n\n");

    user_manager_t   *umgr = (user_manager_t   *)ctx.user_mgr;
    role_manager_t   *rmgr = (role_manager_t   *)ctx.role_mgr;
    group_manager_t  *gmgr = (group_manager_t  *)ctx.group_mgr;
    policy_manager_t *pmgr = (policy_manager_t *)ctx.policy_mgr;

    /* ---- 2. Create users ---- */
    printf("[2] Creating users...\n");
    user_t admin_user, alice_user, bob_user;

    err = user_create(umgr, "admin", "admin123", "admin@example.com", "Admin", &admin_user);
    printf("  admin: id=%lu status=%s\n",
           (unsigned long)admin_user.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    err = user_create(umgr, "alice", "alice456", "alice@example.com", "Alice", &alice_user);
    printf("  alice: id=%lu status=%s\n",
           (unsigned long)alice_user.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    err = user_create(umgr, "bob", "bob789", "bob@example.com", "Bob", &bob_user);
    printf("  bob:   id=%lu status=%s\n",
           (unsigned long)bob_user.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    printf("\n");

    /* ---- 3. Create roles ---- */
    printf("[3] Creating roles...\n");
    role_t admin_role, editor_role, viewer_role;

    err = role_create(rmgr, "admin",  "Full system access",     SSO_ID_NONE, &admin_role);
    err = role_create(rmgr, "editor", "Can edit content",       admin_role.id, &editor_role);
    err = role_create(rmgr, "viewer", "Read-only access",       editor_role.id, &viewer_role);
    printf("  admin=%lu  editor=%lu  viewer=%lu\n",
           (unsigned long)admin_role.id,
           (unsigned long)editor_role.id,
           (unsigned long)viewer_role.id);

    /* ---- 4. Create groups ---- */
    printf("[4] Creating groups...\n");
    group_t engineering, finance;

    err = group_create(gmgr, "engineering", "Engineering Department", SSO_ID_NONE, &engineering);
    err = group_create(gmgr, "finance",     "Finance Department",     SSO_ID_NONE, &finance);
    printf("  engineering=%lu  finance=%lu\n",
           (unsigned long)engineering.id,
           (unsigned long)finance.id);

    /* ---- 5. Assign roles and group memberships ---- */
    printf("[5] Assigning roles and group memberships...\n");
    role_assign_to_user(rmgr, admin_role.id, admin_user.id);
    role_assign_to_user(rmgr, editor_role.id, alice_user.id);
    role_assign_to_user(rmgr, viewer_role.id, bob_user.id);

    group_add_user(gmgr, engineering.id, alice_user.id);
    group_add_user(gmgr, finance.id, bob_user.id);
    printf("  admin   ← admin role\n");
    printf("  alice   ← editor role + engineering group\n");
    printf("  bob     ← viewer role + finance group\n");
    printf("\n");

    /* ---- 6. Create functional permission policy ---- */
    printf("[6] Creating FUNCTIONAL permission policy...\n");
    policy_t func_policy;
    err = policy_create(pmgr, "User Management Functions",
                        PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW,
                        100, /* high priority */
                        "{"
                        "  \"functions\": ["
                        "    {\"code\": \"user:create\", \"effect\": \"allow\"},"
                        "    {\"code\": \"user:view\",   \"effect\": \"allow\"},"
                        "    {\"code\": \"user:delete\", \"effect\": \"deny\"},"
                        "    {\"code\": \"report:*\",    \"effect\": \"allow\"}"
                        "  ]"
                        "}",
                        &func_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)func_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 7. Create API permission policy ---- */
    printf("[7] Creating API permission policy...\n");
    policy_t api_policy;
    err = policy_create(pmgr, "API Access Rules",
                        PERM_STRATEGY_API, POLICY_EFFECT_ALLOW,
                        90,
                        "{"
                        "  \"endpoints\": ["
                        "    {\"method\": \"GET\",    \"path\": \"/api/v1/users\",      \"effect\": \"allow\"},"
                        "    {\"method\": \"GET\",    \"path\": \"/api/v1/users/*\",    \"effect\": \"allow\"},"
                        "    {\"method\": \"POST\",   \"path\": \"/api/v1/users\",      \"effect\": \"allow\"},"
                        "    {\"method\": \"DELETE\", \"path\": \"/api/v1/users/*\",    \"effect\": \"deny\"},"
                        "    {\"method\": \"*\",      \"path\": \"/api/v1/public/*\",   \"effect\": \"allow\"}"
                        "  ]"
                        "}",
                        &api_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)api_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 8. Create data permission policy ---- */
    printf("[8] Creating DATA permission policy...\n");
    policy_t data_policy;
    err = policy_create(pmgr, "Order Data Access",
                        PERM_STRATEGY_DATA, POLICY_EFFECT_ALLOW,
                        80,
                        "{"
                        "  \"rules\": ["
                        "    {"
                        "      \"resource\": \"order\","
                        "      \"scope\": \"organization\","
                        "      \"conditions\": ["
                        "        {\"field\": \"status\", \"op\": \"in\", \"value\": [\"pending\", \"processing\"]}"
                        "      ],"
                        "      \"fields\": [\"id\", \"title\", \"status\", \"amount\"]"
                        "    },"
                        "    {"
                        "      \"resource\": \"customer\","
                        "      \"scope\": \"all\","
                        "      \"fields\": [\"id\", \"name\", \"email\"]"
                        "    }"
                        "  ]"
                        "}",
                        &data_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)data_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 9. Assign policies ---- */
    printf("\n[9] Assigning policies to roles...\n");
    policy_assign_to(pmgr, func_policy.id, POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, api_policy.id,  POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, data_policy.id, POLICY_TARGET_ROLE, editor_role.id);
    printf("  Admin role   ← functional + API policies\n");
    printf("  Editor role  ← data policy\n");
    printf("\n");

    /* ---- 10. Permission checks ---- */
    printf("[10] Functional permission checks:\n");
    bool allowed;

    perm_check_function(&ctx, admin_user.id, "user:create", &allowed);
    printf("  admin  user:create  → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_function(&ctx, admin_user.id, "user:delete", &allowed);
    printf("  admin  user:delete  → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_function(&ctx, admin_user.id, "report:view", &allowed);
    printf("  admin  report:view  → %s\n", allowed ? "ALLOW" : "DENY");

    printf("\n[11] API permission checks:\n");
    perm_check_api(&ctx, admin_user.id, "GET", "/api/v1/users", &allowed);
    printf("  admin  GET /api/v1/users       → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_api(&ctx, admin_user.id, "POST", "/api/v1/users", &allowed);
    printf("  admin  POST /api/v1/users      → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_api(&ctx, admin_user.id, "DELETE", "/api/v1/users/42", &allowed);
    printf("  admin  DELETE /api/v1/users/42 → %s\n", allowed ? "ALLOW" : "DENY");

    printf("\n[12] Data permission checks:\n");
    char **fields = NULL;
    size_t field_count = 0;

    bool data_allowed = false;
    perm_check_data(&ctx, alice_user.id, "order",
                    "{\"id\":1,\"title\":\"Test\",\"status\":\"pending\",\"amount\":100}",
                    &data_allowed, &fields, &field_count);
    printf("  alice  order access  → %s  fields=", data_allowed ? "ALLOW" : "DENY");
    if (fields) {
        printf("[");
        for (size_t i = 0; i < field_count; i++) {
            printf("%s%s", fields[i], i < field_count - 1 ? "," : "");
            free(fields[i]);
        }
        printf("]");
        free(fields);
    }
    printf("\n");

    /* ---- 11. Token authentication ---- */
    printf("\n[13] Token-based authentication:\n");
    token_manager_t *tmgr = (token_manager_t *)ctx.token_mgr;

    user_t auth_user;
    err = user_authenticate(umgr, "admin", "admin123", &auth_user);
    printf("  admin login: %s\n", err == SSO_OK ? "OK" : sso_strerror(err));

    if (err == SSO_OK) {
        sso_id_t roles[8], groups[8];
        size_t rc = 0, gc = 0;
        user_get_roles(umgr, auth_user.id, roles, &rc, 8);
        user_get_groups(umgr, auth_user.id, groups, &gc, 8);

        token_t token;
        token_issue(tmgr, &auth_user, roles, rc, groups, gc, 3600000, &token);
        printf("  token: %s\n", token.token_str);

        /* Verify token */
        token_t decoded;
        err = token_verify(tmgr, token.token_str, &decoded);
        printf("  token verify: %s  (user=%lu)\n",
               err == SSO_OK ? "OK" : sso_strerror(err),
               (unsigned long)decoded.user_id);
    }

    /* ---- 12. Role hierarchy ---- */
    printf("\n[14] Role hierarchy:\n");
    sso_id_t ancestors[8];
    size_t depth = 0;
    role_get_ancestors(rmgr, viewer_role.id, ancestors, &depth, 8);
    printf("  viewer ancestors: ");
    for (size_t i = 0; i < depth; i++) {
        role_t r;
        role_get_by_id(rmgr, ancestors[i], &r);
        printf("%s ", r.name);
    }
    printf("\n");

    /* ---- 13. Policy resolution ---- */
    printf("\n[15] Policy resolution for admin:\n");
    policy_t resolved[16];
    size_t resolved_count = 0;
    err = policy_resolve_for_user(pmgr, admin_user.id, resolved, &resolved_count, 16);
    if (err == SSO_OK || resolved_count > 0) {
        for (size_t i = 0; i < resolved_count; i++) {
            printf("  [pri=%d] %s (strategy=%s)\n",
                   resolved[i].priority,
                   resolved[i].name,
                   perm_strategy_name(resolved[i].strategy_type));
        }
    }

    /* ---- Cleanup ---- */
    printf("\n=== Demo complete. ===\n");
    sso_destroy(&ctx);

    return 0;
}

/* ========================================================================
 * Helpers: JSON field extraction (minimal — no external parser needed)
 * ======================================================================== */

/* Find a JSON string value by key.  Returns malloc'd copy or NULL. */
static char *json_str_value(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p && *p != ':' && *p != ',') p++;
    if (*p == ':') p++;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
    if (*p == '"') p++; else return NULL;
    const char *end = p;
    while (*end && *end != '"') end++;
    size_t len = (size_t)(end - p);
    char *val = (char *)malloc(len + 1);
    if (!val) return NULL;
    memcpy(val, p, len);
    val[len] = '\0';
    return val;
}

/* Find a JSON number (int64) value by key.  Returns default on missing. */
static int64_t json_int_value(const char *json, const char *key, int64_t def) {
    if (!json || !key) return def;
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return def;
    p += strlen(search);
    while (*p && *p != ':' && *p != ',') p++;
    if (*p == ':') p++;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
    return (int64_t)atoll(p);
}

/* ========================================================================
 * API route handlers
 * ======================================================================== */

/* GET /api/v1/health */
static sso_error_t handle_health(sso_context_t *ctx, const http_request_t *req,
                                  http_response_t *resp) {
    (void)ctx; (void)req;
    sso_response_ok(resp, "{"
        "\"status\":\"ok\","
        "\"service\":\"sso\","
        "\"version\":\"1.0.0\""
    "}");
    return SSO_OK;
}

/* POST /api/v1/auth/login */
static sso_error_t handle_login(sso_context_t *ctx, const http_request_t *req,
                                 http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *username = json_str_value(req->body, "username");
    char *password = json_str_value(req->body, "password");
    if (!username || !password) {
        free(username); free(password);
        sso_response_error(resp, 400, "username and password required");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    sso_error_t err = user_authenticate(umgr, username, password, &user);
    free(username); free(password);

    if (err != SSO_OK) {
        sso_response_error(resp, 401, "Invalid credentials");
        return SSO_OK;
    }

    sso_id_t roles[16], groups[16];
    size_t rc = 0, gc = 0;
    user_get_roles(umgr, user.id, roles, &rc, 16);
    user_get_groups(umgr, user.id, groups, &gc, 16);

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t token;
    err = token_issue(tmgr, &user, roles, rc, groups, gc, 3600000, &token);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to issue token");
        return SSO_OK;
    }

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{"
        "\"token\":\"%s\","
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"display_name\":\"%s\""
        "}",
        token.token_str,
        (unsigned long long)user.id,
        user.username,
        user.display_name);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/auth/register */
static sso_error_t handle_register(sso_context_t *ctx, const http_request_t *req,
                                    http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *username = json_str_value(req->body, "username");
    char *password = json_str_value(req->body, "password");
    char *email    = json_str_value(req->body, "email");
    char *display  = json_str_value(req->body, "display_name");

    if (!username || !password) {
        free(username); free(password); free(email); free(display);
        sso_response_error(resp, 400, "username and password required");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    sso_error_t err = user_create(umgr, username, password,
                                  email ? email : "",
                                  display ? display : username,
                                  &user);
    free(username); free(password); free(email); free(display);

    if (err == SSO_ERR_ALREADY_EXISTS) {
        sso_response_error(resp, 409, "Username already exists");
        return SSO_OK;
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to create user");
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"user_id\":%llu,\"username\":\"%s\",\"created\":true}",
        (unsigned long long)user.id, user.username);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/auth/verify — verify a token from body or header */
static sso_error_t handle_verify(sso_context_t *ctx, const http_request_t *req,
                                  http_response_t *resp) {
    const char *token_str = NULL;
    if (req->body) {
        char *t = json_str_value(req->body, "token");
        if (t) { token_str = t; }
    }
    if (!token_str && req->auth_token[0]) {
        token_str = req->auth_token;
    }
    if (!token_str) {
        sso_response_error(resp, 400, "Token required in body or Authorization header");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t tok;
    sso_error_t err = token_verify(tmgr, token_str, &tok);
    if (token_str != req->auth_token) free((void*)token_str);

    if (err == SSO_ERR_TOKEN_EXPIRED) {
        sso_response_error(resp, 401, "Token expired");
        return SSO_OK;
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 401, "Invalid token");
        return SSO_OK;
    }
    if (token_is_revoked(tmgr, tok.jti)) {
        sso_response_error(resp, 401, "Token revoked");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    err = user_get_by_id(umgr, tok.user_id, &user);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "User not found");
        return SSO_OK;
    }

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{"
        "\"valid\":true,"
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"display_name\":\"%s\","
        "\"expires_at\":%lld"
        "}",
        (unsigned long long)user.id,
        user.username,
        user.display_name,
        (long long)tok.expires_at);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/auth/refresh */
static sso_error_t handle_refresh(sso_context_t *ctx, const http_request_t *req,
                                   http_response_t *resp) {
    auth_context_t *auth = (auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t new_token;
    sso_error_t err = token_refresh(tmgr, &auth->token, 3600000, &new_token);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to refresh token");
        return SSO_OK;
    }

    char buf[1024];
    snprintf(buf, sizeof(buf),
        "{\"token\":\"%s\",\"expires_at\":%lld}",
        new_token.token_str, (long long)new_token.expires_at);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/auth/logout */
static sso_error_t handle_logout(sso_context_t *ctx, const http_request_t *req,
                                  http_response_t *resp) {
    auth_context_t *auth = (auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    sso_error_t err = token_revoke(tmgr, auth->token.jti);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to revoke token");
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"logged_out\":true}");
    return SSO_OK;
}

/* GET /api/v1/auth/me */
static sso_error_t handle_me(sso_context_t *ctx, const http_request_t *req,
                              http_response_t *resp) {
    (void)ctx;
    auth_context_t *auth = (auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{"
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"email\":\"%s\","
        "\"display_name\":\"%s\","
        "\"token_jti\":\"%s\""
        "}",
        (unsigned long long)auth->user.id,
        auth->user.username,
        auth->user.email,
        auth->user.display_name,
        auth->token.jti);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/functional */
static sso_error_t handle_check_functional(sso_context_t *ctx, const http_request_t *req,
                                            http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *function_code = json_str_value(req->body, "function_code");
    if (!function_code) {
        sso_response_error(resp, 400, "function_code required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        free(function_code);
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    bool allowed = false;
    sso_error_t err = perm_check_function(ctx, user_id, function_code, &allowed);

    char result_code[64];
    strncpy(result_code, function_code, sizeof(result_code) - 1);
    free(function_code);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"allowed\":%s,\"user_id\":%llu,\"function\":\"%s\"}",
        allowed ? "true" : "false",
        (unsigned long long)user_id,
        result_code);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/api */
static sso_error_t handle_check_api(sso_context_t *ctx, const http_request_t *req,
                                     http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *method = json_str_value(req->body, "method");
    char *path   = json_str_value(req->body, "path");
    if (!method || !path) {
        free(method); free(path);
        sso_response_error(resp, 400, "method and path required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        free(method); free(path);
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    bool allowed = false;
    sso_error_t err = perm_check_api(ctx, user_id, method, path, &allowed);
    free(method); free(path);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"allowed\":%s,\"user_id\":%llu}",
        allowed ? "true" : "false",
        (unsigned long long)user_id);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/data */
static sso_error_t handle_check_data(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *resource_type = json_str_value(req->body, "resource_type");
    char *record_json   = json_str_value(req->body, "record");
    if (!resource_type) {
        free(resource_type); free(record_json);
        sso_response_error(resp, 400, "resource_type required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        free(resource_type); free(record_json);
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    bool allowed = false;
    char **fields = NULL;
    size_t field_count = 0;
    sso_error_t err = perm_check_data(ctx, user_id, resource_type,
                                       record_json, &allowed,
                                       &fields, &field_count);
    free(resource_type);
    free(record_json);
    /* Note: fields is owned by the SSO system — do not free here */

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    char buf[2048];
    size_t off = (size_t)snprintf(buf, sizeof(buf),
        "{\"allowed\":%s,\"user_id\":%llu",
        allowed ? "true" : "false",
        (unsigned long long)user_id);

    if (fields && field_count > 0) {
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, ",\"fields\":[");
        for (size_t i = 0; i < field_count; i++) {
            off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                "%s\"%s\"", i > 0 ? "," : "", fields[i]);
            free(fields[i]);
        }
        off += (size_t)snprintf(buf + off, sizeof(buf) - off, "]");
        free(fields);
    }
    snprintf(buf + off, sizeof(buf) - off, "}");
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/users — create user (admin endpoint) */
static sso_error_t handle_create_user(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *username = json_str_value(req->body, "username");
    char *password = json_str_value(req->body, "password");
    char *email    = json_str_value(req->body, "email");
    char *display  = json_str_value(req->body, "display_name");

    if (!username || !password) {
        free(username); free(password); free(email); free(display);
        sso_response_error(resp, 400, "username and password required");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    sso_error_t err = user_create(umgr, username, password,
                                  email ? email : "",
                                  display ? display : username,
                                  &user);
    free(username); free(password); free(email); free(display);

    if (err == SSO_ERR_ALREADY_EXISTS) {
        sso_response_error(resp, 409, "Username already exists");
        return SSO_OK;
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to create user");
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"user_id\":%llu,\"username\":\"%s\",\"created\":true}",
        (unsigned long long)user.id, user.username);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/roles — create role */
static sso_error_t handle_create_role(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *name = json_str_value(req->body, "name");
    if (!name) {
        sso_response_error(resp, 400, "name required");
        return SSO_OK;
    }
    char *desc = json_str_value(req->body, "description");
    sso_id_t parent_id = (sso_id_t)json_int_value(req->body, "parent_role_id", 0);

    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    role_t role;
    sso_error_t err = role_create(rmgr, name, desc ? desc : "", parent_id, &role);
    free(name); free(desc);
    if (err == SSO_ERR_ALREADY_EXISTS) {
        sso_response_error(resp, 409, "Role already exists");
        return SSO_OK;
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to create role");
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"role_id\":%llu,\"name\":\"%s\",\"created\":true}",
        (unsigned long long)role.id, role.name);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/roles/:id/assign */
static sso_error_t handle_assign_role(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    /* Parse role_id from path: /api/v1/roles/NNN/assign */
    sso_id_t role_id = 0;
    const char *p = req->path;
    /* Skip to role id segment */
    const char *id_start = strstr(p, "/roles/");
    if (id_start) {
        id_start += 7; /* past "/roles/" */
        role_id = (sso_id_t)atoll(id_start);
    }

    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    sso_id_t group_id = (sso_id_t)json_int_value(req->body, "group_id", 0);

    if (user_id == 0 && group_id == 0) {
        sso_response_error(resp, 400, "user_id or group_id required");
        return SSO_OK;
    }

    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    sso_error_t err;
    if (user_id != 0) {
        err = role_assign_to_user(rmgr, role_id, user_id);
    } else {
        err = role_assign_to_group(rmgr, role_id, group_id);
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"assigned\":true}");
    return SSO_OK;
}

/* ========================================================================
 * List handlers — return JSON arrays of objects
 * ======================================================================== */

/* GET /api/v1/users */
static sso_error_t handle_list_users(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    (void)req;
    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    sso_id_t ids[256];
    size_t count = 0;
    sso_error_t err = user_list(umgr, ids, &count, 256);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to list users");
        return SSO_OK;
    }

    size_t total = 2;
    for (size_t i = 0; i < count; i++) {
        total += 512;
    }

    char *json = (char *)calloc(1, total + 1);
    if (!json) {
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }

    strcat(json, "[");
    for (size_t i = 0; i < count; i++) {
        user_t u;
        err = user_get_by_id(umgr, ids[i], &u);
        if (err != SSO_OK) continue;

        /* Get roles for this user */
        sso_id_t role_ids[16];
        size_t rc = 0;
        user_get_roles(umgr, u.id, role_ids, &rc, 16);

        char roles_json[512] = "";
        strcat(roles_json, "[");
        for (size_t j = 0; j < rc; j++) {
            role_t r;
            char buf[128];
            if (role_get_by_id(rmgr, role_ids[j], &r) == SSO_OK) {
                snprintf(buf, sizeof(buf), "%s{\"id\":%llu,\"name\":\"%s\"}",
                         j > 0 ? "," : "",
                         (unsigned long long)r.id, r.name);
                strcat(roles_json, buf);
            }
        }
        strcat(roles_json, "]");

        char buf[1024];
        snprintf(buf, sizeof(buf),
            "%s{"
            "\"id\":%llu,"
            "\"username\":\"%s\","
            "\"email\":\"%s\","
            "\"display_name\":\"%s\","
            "\"status\":%d,"
            "\"roles\":%s,"
            "\"created_at\":%lld"
            "}",
            i > 0 ? "," : "",
            (unsigned long long)u.id,
            u.username,
            u.email,
            u.display_name,
            (int)u.status,
            roles_json,
            (long long)u.created_at);
        strcat(json, buf);
    }
    strcat(json, "]");

    sso_response_ok(resp, json);
    free(json);
    return SSO_OK;
}

/* GET /api/v1/roles */
static sso_error_t handle_list_roles(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    (void)req;
    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    sso_id_t ids[256];
    size_t count = 0;
    sso_error_t err = role_list(rmgr, ids, &count, 256);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to list roles");
        return SSO_OK;
    }

    size_t total = 2;
    for (size_t i = 0; i < count; i++) total += 512;

    char *json = (char *)calloc(1, total + 1);
    if (!json) {
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }

    strcat(json, "[");
    for (size_t i = 0; i < count; i++) {
        role_t r;
        err = role_get_by_id(rmgr, ids[i], &r);
        if (err != SSO_OK) continue;

        /* Get parent role name */
        char parent_name[64] = "";
        if (r.parent_role_id != 0) {
            role_t parent;
            if (role_get_by_id(rmgr, r.parent_role_id, &parent) == SSO_OK) {
                snprintf(parent_name, sizeof(parent_name), "%s", parent.name);
            }
        }

        char buf[1024];
        snprintf(buf, sizeof(buf),
            "%s{"
            "\"id\":%llu,"
            "\"name\":\"%s\","
            "\"description\":\"%s\","
            "\"parent_role_id\":%llu,"
            "\"parent_name\":\"%s\","
            "\"created_at\":%lld"
            "}",
            i > 0 ? "," : "",
            (unsigned long long)r.id,
            r.name,
            r.description,
            (unsigned long long)r.parent_role_id,
            parent_name,
            (long long)r.created_at);
        strcat(json, buf);
    }
    strcat(json, "]");

    sso_response_ok(resp, json);
    free(json);
    return SSO_OK;
}

/* GET /api/v1/policies */
static sso_error_t handle_list_policies(sso_context_t *ctx, const http_request_t *req,
                                         http_response_t *resp) {
    (void)req;
    policy_manager_t *pmgr = (policy_manager_t *)ctx->policy_mgr;
    sso_id_t ids[256];
    size_t count = 0;
    sso_error_t err = policy_list(pmgr, ids, &count, 256);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to list policies");
        return SSO_OK;
    }

    size_t total = 2;
    for (size_t i = 0; i < count; i++) total += 1024;

    char *json = (char *)calloc(1, total + 1);
    if (!json) {
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }

    strcat(json, "[");
    for (size_t i = 0; i < count; i++) {
        policy_t p;
        err = policy_get_by_id(pmgr, ids[i], &p);
        if (err != SSO_OK) continue;

        char buf[8192];
        snprintf(buf, sizeof(buf),
            "%s{"
            "\"id\":%llu,"
            "\"name\":\"%s\","
            "\"strategy_type\":%d,"
            "\"strategy_name\":\"%s\","
            "\"effect\":%d,"
            "\"priority\":%d,"
            "\"status\":%d,"
            "\"rules\":%.4000s,"
            "\"created_at\":%lld"
            "}",
            i > 0 ? "," : "",
            (unsigned long long)p.id,
            p.name,
            (int)p.strategy_type,
            perm_strategy_name(p.strategy_type),
            (int)p.effect,
            p.priority,
            (int)p.status,
            p.rules,
            (long long)p.created_at);
        strcat(json, buf);
    }
    strcat(json, "]");

    sso_response_ok(resp, json);
    free(json);
    return SSO_OK;
}

/* GET /api/v1/groups */
static sso_error_t handle_list_groups(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    (void)req;
    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;
    sso_id_t ids[256];
    size_t count = 0;
    sso_error_t err = group_list(gmgr, ids, &count, 256);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to list groups");
        return SSO_OK;
    }

    size_t total = 2;
    for (size_t i = 0; i < count; i++) total += 512;

    char *json = (char *)calloc(1, total + 1);
    if (!json) {
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }

    strcat(json, "[");
    for (size_t i = 0; i < count; i++) {
        group_t g;
        err = group_get_by_id(gmgr, ids[i], &g);
        if (err != SSO_OK) continue;

        char parent_name[64] = "";
        if (g.parent_group_id != 0) {
            group_t parent;
            if (group_get_by_id(gmgr, g.parent_group_id, &parent) == SSO_OK) {
                snprintf(parent_name, sizeof(parent_name), "%s", parent.name);
            }
        }

        char buf[1024];
        snprintf(buf, sizeof(buf),
            "%s{"
            "\"id\":%llu,"
            "\"name\":\"%s\","
            "\"description\":\"%s\","
            "\"parent_group_id\":%llu,"
            "\"parent_name\":\"%s\","
            "\"created_at\":%lld"
            "}",
            i > 0 ? "," : "",
            (unsigned long long)g.id,
            g.name,
            g.description,
            (unsigned long long)g.parent_group_id,
            parent_name,
            (long long)g.created_at);
        strcat(json, buf);
    }
    strcat(json, "]");

    sso_response_ok(resp, json);
    free(json);
    return SSO_OK;
}

/* POST /api/v1/policies — create a policy */
static sso_error_t handle_create_policy(sso_context_t *ctx, const http_request_t *req,
                                         http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *name = json_str_value(req->body, "name");
    if (!name) {
        sso_response_error(resp, 400, "name required");
        return SSO_OK;
    }

    int strategy_type = (int)json_int_value(req->body, "strategy_type", 1);
    int effect = (int)json_int_value(req->body, "effect", 1);
    int priority = (int)json_int_value(req->body, "priority", 50);
    char *rules = json_str_value(req->body, "rules");

    policy_manager_t *pmgr = (policy_manager_t *)ctx->policy_mgr;
    policy_t policy;
    sso_error_t err = policy_create(pmgr, name,
                                     (perm_strategy_type_t)strategy_type,
                                     (policy_effect_t)effect,
                                     priority,
                                     rules ? rules : "{}",
                                     &policy);
    free(name);
    free(rules);

    if (err == SSO_ERR_ALREADY_EXISTS) {
        sso_response_error(resp, 409, "Policy already exists");
        return SSO_OK;
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to create policy");
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"policy_id\":%llu,\"name\":\"%s\",\"created\":true}",
        (unsigned long long)policy.id, policy.name);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/policies/:id/assign */
static sso_error_t handle_assign_policy(sso_context_t *ctx, const http_request_t *req,
                                         http_response_t *resp) {
    sso_id_t policy_id = 0;
    const char *p = req->path;
    const char *id_start = strstr(p, "/policies/");
    if (id_start) {
        id_start += 10;
        policy_id = (sso_id_t)atoll(id_start);
    }

    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    int target_type = (int)json_int_value(req->body, "target_type", 0);
    sso_id_t target_id = (sso_id_t)json_int_value(req->body, "target_id", 0);

    if (target_id == 0) {
        sso_response_error(resp, 400, "target_id required");
        return SSO_OK;
    }

    policy_manager_t *pmgr = (policy_manager_t *)ctx->policy_mgr;
    sso_error_t err = policy_assign_to(pmgr, policy_id,
                                        (policy_target_type_t)target_type,
                                        target_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"assigned\":true}");
    return SSO_OK;
}

/* POST /api/v1/groups — create group */
static sso_error_t handle_create_group(sso_context_t *ctx, const http_request_t *req,
                                        http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *name = json_str_value(req->body, "name");
    if (!name) {
        sso_response_error(resp, 400, "name required");
        return SSO_OK;
    }
    char *desc = json_str_value(req->body, "description");
    sso_id_t parent_id = (sso_id_t)json_int_value(req->body, "parent_group_id", 0);

    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;
    group_t group;
    sso_error_t err = group_create(gmgr, name, desc ? desc : "", parent_id, &group);
    free(name); free(desc);
    if (err == SSO_ERR_ALREADY_EXISTS) {
        sso_response_error(resp, 409, "Group already exists");
        return SSO_OK;
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to create group");
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"id\":%llu,\"name\":\"%s\",\"created\":true}",
        (unsigned long long)group.id, group.name);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* GET /admin — serve the admin management page */
static sso_error_t handle_admin_page(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    (void)ctx; (void)req;
    resp->status_code = 200;
    resp->body = strdup(ADMIN_PAGE_HTML);
    resp->body_len = strlen(ADMIN_PAGE_HTML);
    strcpy(resp->content_type, "text/html; charset=utf-8");
    return SSO_OK;
}

/* ========================================================================
 * Bootstrap: create default admin + roles on first server start
 * ======================================================================== */
static sso_error_t bootstrap_data(sso_context_t *ctx) {
    sso_error_t err;
    user_manager_t   *umgr = (user_manager_t   *)ctx->user_mgr;
    role_manager_t   *rmgr = (role_manager_t   *)ctx->role_mgr;
    policy_manager_t *pmgr = (policy_manager_t *)ctx->policy_mgr;

    /* Check if admin already exists */
    user_t admin_user;
    err = user_get_by_username(umgr, "admin", &admin_user);
    if (err == SSO_OK) return SSO_OK; /* already bootstrapped */

    /* Create admin user */
    printf("[bootstrap] Creating admin user...\n");
    err = user_create(umgr, "admin", "admin123", "admin@example.com", "Admin", &admin_user);
    if (err != SSO_OK) {
        fprintf(stderr, "[bootstrap] Failed to create admin: %s\n", sso_strerror(err));
        return err;
    }
    printf("[bootstrap] admin id=%lu\n", (unsigned long)admin_user.id);

    /* Create roles */
    role_t admin_role, editor_role, viewer_role;
    err = role_create(rmgr, "admin",  "Full system access",     SSO_ID_NONE, &admin_role);
    if (err != SSO_OK) return err;
    err = role_create(rmgr, "editor", "Can edit content",       admin_role.id, &editor_role);
    if (err != SSO_OK) return err;
    err = role_create(rmgr, "viewer", "Read-only access",       editor_role.id, &viewer_role);
    if (err != SSO_OK) return err;

    /* Assign admin role to admin user */
    role_assign_to_user(rmgr, admin_role.id, admin_user.id);

    /* Create functional policy */
    policy_t func_policy;
    err = policy_create(pmgr, "System Functions",
        PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW, 100,
        "{\"functions\":["
          "{\"code\":\"admin:*\",\"effect\":\"allow\"},"
          "{\"code\":\"user:create\",\"effect\":\"allow\"},"
          "{\"code\":\"user:view\",\"effect\":\"allow\"},"
          "{\"code\":\"user:delete\",\"effect\":\"deny\"}"
        "]}",
        &func_policy);
    if (err != SSO_OK) return err;

    /* Create API policy */
    policy_t api_policy;
    err = policy_create(pmgr, "System API",
        PERM_STRATEGY_API, POLICY_EFFECT_ALLOW, 90,
        "{\"endpoints\":["
          "{\"method\":\"GET\",\"path\":\"/api/v1/*\",\"effect\":\"allow\"},"
          "{\"method\":\"POST\",\"path\":\"/api/v1/*\",\"effect\":\"allow\"}"
        "]}",
        &api_policy);
    if (err != SSO_OK) return err;

    /* Assign policies to admin role */
    policy_assign_to(pmgr, func_policy.id, POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, api_policy.id,  POLICY_TARGET_ROLE, admin_role.id);

    printf("[bootstrap] Default admin and roles created\n");
    return SSO_OK;
}

/* ========================================================================
 * Server mode
 * ======================================================================== */
static int run_server(void) {
    sso_error_t err;

    /* Init SSO */
    storage_backend_t *storage = NULL;
    storage_sqlite_create(&storage);

    sso_context_t ctx;
    err = sso_init(&ctx, storage, "sso_server.db");
    if (err != SSO_OK) {
        fprintf(stderr, "Failed to init SSO: %s\n", sso_strerror(err));
        return 1;
    }

    printf("Starting SSO management server...\n");

    /* Bootstrap default data on first run */
    bootstrap_data(&ctx);

    /* Define API routes */
    route_t routes[] = {
        /* Public — login page */
        {"/",                       HTTP_GET,  handle_login_page,       false},
        {"/login",                  HTTP_GET,  handle_login_page,       false},

        /* Public — admin page (auth is handled by the frontend) */
        {"/admin",                  HTTP_GET,  handle_admin_page,       false},

        /* Public — API */
        {"/api/v1/health",          HTTP_GET,  handle_health,          false},
        {"/api/v1/auth/login",      HTTP_POST, handle_login,           false},
        {"/api/v1/auth/register",   HTTP_POST, handle_register,        false},

        /* Auth required */
        {"/api/v1/auth/verify",     HTTP_POST, handle_verify,           true},
        {"/api/v1/auth/refresh",    HTTP_POST, handle_refresh,          true},
        {"/api/v1/auth/logout",     HTTP_POST, handle_logout,           true},
        {"/api/v1/auth/me",         HTTP_GET,  handle_me,               true},

        /* Permission checks */
        {"/api/v1/check/functional",HTTP_POST, handle_check_functional,  true},
        {"/api/v1/check/api",       HTTP_POST, handle_check_api,         true},
        {"/api/v1/check/data",      HTTP_POST, handle_check_data,        true},

        /* Management — CRUD */
        {"/api/v1/users",           HTTP_GET,  handle_list_users,        true},
        {"/api/v1/users",           HTTP_POST, handle_create_user,       true},
        {"/api/v1/roles",           HTTP_GET,  handle_list_roles,        true},
        {"/api/v1/roles",           HTTP_POST, handle_create_role,       true},
        {"/api/v1/roles/*/assign",  HTTP_POST, handle_assign_role,       true},
        {"/api/v1/policies",        HTTP_GET,  handle_list_policies,     true},
        {"/api/v1/policies",        HTTP_POST, handle_create_policy,     true},
        {"/api/v1/policies/*/assign",HTTP_POST, handle_assign_policy,    true},
        {"/api/v1/groups",          HTTP_GET,  handle_list_groups,       true},
        {"/api/v1/groups",          HTTP_POST, handle_create_group,      true},
    };

    size_t route_count = sizeof(routes) / sizeof(routes[0]);

    sso_server_t server;
    sso_server_init(&server, &ctx, "0.0.0.0", 8080, routes, route_count);

    printf("  Login: http://localhost:%d/\n", 8080);
    printf("  API: http://localhost:%d/api/v1/health\n", 8080);
    printf("  Auth: POST /api/v1/auth/login\n");
    printf("  Auth: POST /api/v1/auth/verify\n");
    printf("  Auth: POST /api/v1/auth/register\n");
    printf("  Auth: POST /api/v1/auth/refresh\n");
    printf("  Auth: POST /api/v1/auth/logout\n");
    printf("  Auth: GET  /api/v1/auth/me\n");
    printf("  Check: POST /api/v1/check/functional\n");
    printf("  Check: POST /api/v1/check/api\n");
    printf("  Check: POST /api/v1/check/data\n");
    printf("  Mgmt:  POST /api/v1/users\n");
    printf("  Mgmt:  POST /api/v1/roles\n");
    printf("  Mgmt:  POST /api/v1/roles/:id/assign\n");
    printf("  Press Ctrl+C to stop.\n\n");

    err = sso_server_start(&server);
    if (err != SSO_OK) {
        fprintf(stderr, "Server error: %s\n", sso_strerror(err));
    }

    sso_destroy(&ctx);
    return 0;
}

/* ========================================================================
 * Entry point
 * ======================================================================== */
int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--server") == 0) {
        return run_server();
    }
    return run_demo();
}
