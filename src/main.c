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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
 * API route handlers (simplified stubs)
 * ======================================================================== */

/* POST /api/v1/auth/login */
static sso_error_t handle_login(sso_context_t *ctx, const http_request_t *req,
                                 http_response_t *resp) {
    /* In production: parse JSON body for username/password, authenticate, issue token */
    sso_response_ok(resp, "{\"token\":\"demo-token\",\"user_id\":1}");
    return SSO_OK;
}

/* GET /api/v1/health */
static sso_error_t handle_health(sso_context_t *ctx, const http_request_t *req,
                                  http_response_t *resp) {
    sso_response_ok(resp, "{\"status\":\"ok\",\"version\":\"1.0.0\"}");
    return SSO_OK;
}

/* POST /api/v1/check/functional */
static sso_error_t handle_check_functional(sso_context_t *ctx, const http_request_t *req,
                                            http_response_t *resp) {
    /* Parse JSON body, extract user_id and function_code, check permission */
    bool allowed = false;
    /* Simplified: always return true */
    allowed = true;
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"allowed\":%s}", allowed ? "true" : "false");
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/api */
static sso_error_t handle_check_api(sso_context_t *ctx, const http_request_t *req,
                                     http_response_t *resp) {
    bool allowed = false;
    allowed = true;
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"allowed\":%s}", allowed ? "true" : "false");
    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/data */
static sso_error_t handle_check_data(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    bool allowed = false;
    allowed = true;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"allowed\":%s,\"fields\":[\"id\",\"name\",\"email\"]}",
             allowed ? "true" : "false");
    sso_response_ok(resp, buf);
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

    /* Define API routes */
    route_t routes[] = {
        {"/api/v1/health",          HTTP_GET,  handle_health,          false},
        {"/api/v1/auth/login",      HTTP_POST, handle_login,           false},
        {"/api/v1/check/functional",HTTP_POST, handle_check_functional, true},
        {"/api/v1/check/api",       HTTP_POST, handle_check_api,       true},
        {"/api/v1/check/data",      HTTP_POST, handle_check_data,      true},
    };

    sso_server_t server;
    sso_server_init(&server, &ctx, "0.0.0.0", 8080, routes, 5);

    printf("Starting SSO management server...\n");
    printf("  API: http://localhost:8080/api/v1/health\n");
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
