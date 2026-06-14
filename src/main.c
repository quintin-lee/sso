/*
 * main.c — SSO system entry point, comprehensive demo, and interactive config.
 *
 * Demonstrates:
 *   1. System initialization with SQLite storage
 *   2. User, role, group CRUD
 *   3. Policy creation for all six strategy types
 *   4. Assignment of roles and policies
 *   5. Permission checks (functional, API, data, RBAC, LBAC, ABAC)
 *   6. Token-based authentication
 *
 * Interactive config mode provides a step-by-step guided menu for
 * configuring all permission strategy types interactively.
 *
 * Build:
 *   make
 *
 * Run:
 *   ./sso_system              — runs the demo and exits
 *   ./sso_system --server     — starts the HTTP management API on port 8080
 *   ./sso_system --interactive — guided configuration shell
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
#include "ratelimit.h"
#include "cJSON.h"
#include "login_page.h"
#include "admin_page.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <curl/curl.h>

static uint64_t get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

/* Helper: extract numeric ID from a path like /api/v1/xxx/NNN */
static sso_id_t extract_path_id(const char *path, const char *prefix) {
    const char *p = strstr(path, prefix);
    if (!p) return 0;
    p += strlen(prefix);
    return (sso_id_t)atoll(p);
}

/* -----------------------------------------------------------------------
 * Real SMS sending via libcurl (Generic JSON API)
 * ----------------------------------------------------------------------- */
static sso_error_t send_real_sms(const char *phone, const char *code) {
    CURL *curl;
    CURLcode res;
    sso_error_t err = SSO_OK;

    curl = curl_easy_init();
    if (!curl) return SSO_ERR_GENERAL;

    /* Configuration: in production, load these from environment variables */
    const char *url = getenv("SSO_SMS_GATEWAY_URL");
    const char *api_key = getenv("SSO_SMS_API_KEY");

    if (!url) {
        /* Fallback for demo: just log and return OK */
        printf("[SMS] MOCK SEND: Code %s sent to %s (Set SSO_SMS_GATEWAY_URL for real send)\n", code, phone);
        curl_easy_cleanup(curl);
        return SSO_OK;
    }

    /* Construct JSON body */
    char post_data[512];
    snprintf(post_data, sizeof(post_data), 
             "{\"phone\":\"%s\",\"code\":\"%s\",\"api_key\":\"%s\"}", 
             phone, code, api_key ? api_key : "");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); /* 5s timeout */

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "[SMS] curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        err = SSO_ERR_GENERAL;
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code >= 200 && http_code < 300) {
            printf("[SMS] Real SMS request sent to %s (HTTP %ld)\n", phone, http_code);
        } else {
            fprintf(stderr, "[SMS] Gateway returned error: HTTP %ld\n", http_code);
            err = SSO_ERR_GENERAL;
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return err;
}

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
                        "  \"resource_type\": \"order\","
                        "  \"conditions\": ["
                        "    {\"field\": \"status\", \"op\": \"eq\", \"value\": \"pending\"}"
                        "  ],"
                        "  \"allowed_fields\": [\"id\", \"title\", \"status\"],"
                        "  \"effect\": \"allow\""
                        "}",
                        &data_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)data_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 9. Create RBAC permission policy ---- */
    printf("\n[9] Creating RBAC permission policy...\n");
    policy_t rbac_policy;
    err = policy_create(pmgr, "Admin Role Access",
                        PERM_STRATEGY_RBAC, POLICY_EFFECT_ALLOW,
                        70,
                        "{"
                        "  \"roles\": ["
                        "    {\"name\": \"admin\",  \"effect\": \"allow\"},"
                        "    {\"name\": \"editor\", \"effect\": \"allow\"}"
                        "  ]"
                        "}",
                        &rbac_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)rbac_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 10. Create Location permission policy ---- */
    printf("\n[10] Creating Location permission policy...\n");
    policy_t loc_policy;
    err = policy_create(pmgr, "Local Network Access",
                        PERM_STRATEGY_LOCATION, POLICY_EFFECT_ALLOW,
                        60,
                        "{"
                        "  \"locations\": ["
                        "    {\"type\": \"ip_cidr\", \"value\": \"127.0.0.0/8\",  \"effect\": \"allow\"},"
                        "    {\"type\": \"ip_cidr\", \"value\": \"10.0.0.0/8\",   \"effect\": \"allow\"},"
                        "    {\"type\": \"ip_cidr\", \"value\": \"0.0.0.0/0\",    \"effect\": \"deny\"}"
                        "  ]"
                        "}",
                        &loc_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)loc_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 11. Create LBAC (Label-Based) permission policy ---- */
    printf("\n[11] Creating LBAC (Label-Based) permission policy...\n");
    policy_t lbac_policy;
    err = policy_create(pmgr, "Confidential Data Access",
                        PERM_STRATEGY_LBAC, POLICY_EFFECT_ALLOW,
                        55,
                        "{"
                        "  \"labels\": ["
                        "    {\"name\": \"CONFIDENTIAL\", \"effect\": \"allow\"},"
                        "    {\"name\": \"TOP_SECRET\",   \"effect\": \"allow\"}"
                        "  ]"
                        "}",
                        &lbac_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)lbac_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 12. Create ABAC permission policy ---- */
    printf("\n[12] Creating ABAC permission policy...\n");
    policy_t abac_policy;
    err = policy_create(pmgr, "Engineering Department Access",
                        PERM_STRATEGY_ABAC, POLICY_EFFECT_ALLOW,
                        50,
                        "{"
                        "  \"conditions\": ["
                        "    {\"source\": \"subject\", \"attr\": \"department\", \"op\": \"eq\", \"value\": \"engineering\"}"
                        "  ],"
                        "  \"logic\": \"and\","
                        "  \"effect\": \"allow\""
                        "}",
                        &abac_policy);
    printf("  policy id=%lu status=%s\n",
           (unsigned long)abac_policy.id,
           err == SSO_OK ? "OK" : sso_strerror(err));

    /* ---- 13. Assign policies ---- */
    printf("\n[13] Assigning policies to roles...\n");
    policy_assign_to(pmgr, func_policy.id, POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, api_policy.id,  POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, data_policy.id, POLICY_TARGET_ROLE, editor_role.id);
    policy_assign_to(pmgr, rbac_policy.id, POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, loc_policy.id, POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, lbac_policy.id, POLICY_TARGET_ROLE, admin_role.id);
    policy_assign_to(pmgr, abac_policy.id, POLICY_TARGET_ROLE, admin_role.id);
    printf("  Admin role   ← functional + API + RBAC + Location + LBAC + ABAC policies\n");
    printf("  Editor role  ← data policy\n");
    printf("\n");

    /* ---- 14. Functional permission checks ---- */
    printf("[14] Functional permission checks:\n");
    bool allowed;

    perm_check_function(&ctx, admin_user.id, "user:create", &allowed);
    printf("  admin  user:create  → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_function(&ctx, admin_user.id, "user:delete", &allowed);
    printf("  admin  user:delete  → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_function(&ctx, admin_user.id, "report:view", &allowed);
    printf("  admin  report:view  → %s\n", allowed ? "ALLOW" : "DENY");

    printf("\n[15] API permission checks:\n");
    perm_check_api(&ctx, admin_user.id, "GET", "/api/v1/users", &allowed);
    printf("  admin  GET /api/v1/users       → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_api(&ctx, admin_user.id, "POST", "/api/v1/users", &allowed);
    printf("  admin  POST /api/v1/users      → %s\n", allowed ? "ALLOW" : "DENY");

    perm_check_api(&ctx, admin_user.id, "DELETE", "/api/v1/users/42", &allowed);
    printf("  admin  DELETE /api/v1/users/42 → %s\n", allowed ? "ALLOW" : "DENY");

    printf("\n[16] Data permission checks:\n");
    char **fields = NULL;
    size_t field_count = 0;

    /* Test 1: Condition matches (status=pending) */
    bool data_allowed = false;
    perm_check_data(&ctx, alice_user.id, "order",
                    "{\"id\":101,\"title\":\"MacBook Pro\",\"status\":\"pending\",\"amount\":1999}",
                    &data_allowed, &fields, &field_count);
    printf("  alice  order(pending) → %s  allowed_fields=", data_allowed ? "ALLOW" : "DENY");
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

    /* Test 2: Condition fails (status=shipped) */
    perm_check_data(&ctx, alice_user.id, "order",
                    "{\"id\":102,\"title\":\"iPad\",\"status\":\"shipped\",\"amount\":799}",
                    &data_allowed, &fields, &field_count);
    printf("  alice  order(shipped) → %s\n", data_allowed ? "ALLOW" : "DENY");

    /* ---- 16b. Cache Performance Stress Test ---- */
    printf("\n[16b] Cache Performance Stress Test (1000 iterations)...\n");
    uint64_t start_time = get_time_ms();
    for (int i = 0; i < 1000; i++) {
        perm_check_function(&ctx, admin_user.id, "user:create", &allowed);
    }
    uint64_t duration = get_time_ms() - start_time;
    printf("  1000 functional checks: %lums (%.3fms per check)\n", 
           (long)duration, (double)duration / 1000.0);
    printf("  OK (Check stderr for telemetry)\n");

    /* ---- 17. RBAC permission check ---- */
    printf("\n[17] RBAC permission checks:\n");
    perm_check_rbac(&ctx, admin_user.id, "admin", &allowed);
    printf("  admin  check_rbac(\"admin\")    → %s\n", allowed ? "ALLOW" : "DENY");
    perm_check_rbac(&ctx, bob_user.id,   "admin", &allowed);
    printf("  bob    check_rbac(\"admin\")    → %s\n", allowed ? "ALLOW" : "DENY");
    perm_check_rbac(&ctx, admin_user.id, "viewer", &allowed);
    printf("  admin  check_rbac(\"viewer\")   → %s\n", allowed ? "ALLOW" : "DENY");

    /* ---- 18. Location permission check ---- */
    printf("\n[18] Location permission checks:\n");
    perm_check_location(&ctx, admin_user.id, "127.0.0.1", NULL, &allowed);
    printf("  admin  source=127.0.0.1         → %s\n", allowed ? "ALLOW" : "DENY");
    perm_check_location(&ctx, admin_user.id, "10.0.0.5",  NULL, &allowed);
    printf("  admin  source=10.0.0.5          → %s\n", allowed ? "ALLOW" : "DENY");
    perm_check_location(&ctx, admin_user.id, "203.0.113.1", NULL, &allowed);
    printf("  admin  source=203.0.113.1       → %s\n", allowed ? "ALLOW" : "DENY");

    /* ---- 19. LBAC (Label-Based) permission check ---- */
    printf("\n[19] LBAC (Label-Based) permission checks:\n");
    perm_check_lbac(&ctx, admin_user.id, "PUBLIC,CONFIDENTIAL", "CONFIDENTIAL", &allowed);
    printf("  admin  labels=[PUBLIC,CONFIDENTIAL] target=CONFIDENTIAL → %s\n", allowed ? "ALLOW" : "DENY");
    perm_check_lbac(&ctx, admin_user.id, "PUBLIC", "TOP_SECRET", &allowed);
    printf("  admin  labels=[PUBLIC]              target=TOP_SECRET    → %s\n", allowed ? "ALLOW" : "DENY");

    /* ---- 20. ABAC permission check ---- */
    printf("\n[20] ABAC permission checks:\n");
    perm_check_abac(&ctx, admin_user.id,
                    "{\"department\":\"engineering\"}", NULL, NULL, &allowed);
    printf("  admin  dept=engineering         → %s\n", allowed ? "ALLOW" : "DENY");
    perm_check_abac(&ctx, admin_user.id,
                    "{\"department\":\"sales\"}", NULL, NULL, &allowed);
    printf("  admin  dept=sales               → %s\n", allowed ? "ALLOW" : "DENY");

    /* ---- 21. Token authentication ---- */
    printf("\n[21] Token-based authentication:\n");
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

    /* ---- 22. Role hierarchy ---- */
    printf("\n[22] Role hierarchy:\n");
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

    /* ---- 23. Policy resolution ---- */
    printf("\n[23] Policy resolution for admin:\n");
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
 * Interactive configuration shell — guided menu for all 6 strategy types.
 * Run with: ./sso_system --interactive
 * ======================================================================== */

/* Helper: read a line from stdin, strip trailing newline. */
static void prompt_line(const char *msg, char *buf, size_t size) {
    printf("%s", msg);
    fflush(stdout);
    if (fgets(buf, (int)size, stdin)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = '\0';
    }
}

static void print_banner(void) {
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║     SSO Permission Strategy Configurator      ║\n");
    printf("  ║     Configure all 7 strategy types            ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n\n");
}

static void print_menu(void) {
    printf("  ┌───── Strategy Configuration ─────────────────────┐\n");
    printf("  │  1. Functional    (feature/menu permissions)     │\n");
    printf("  │  2. API           (HTTP method + path control)   │\n");
    printf("  │  3. Data          (resource/field-level access)  │\n");
    printf("  │  4. RBAC          (role membership check)        │\n");
    printf("  │  5. Location      (IP/location-based control)    │\n");
    printf("  │  6. ABAC          (attribute-based conditions)   │\n");
    printf("  │  7. LBAC          (label-based control)          │\n");
    printf("  ├───── Actions ────────────────────────────────────┤\n");
    printf("  │  8. Assign a policy to a role                    │\n");
    printf("  │  9. Test a permission check                      │\n");
    printf("  │  10. List all policies                           │\n");
    printf("  ├───── User Management ────────────────────────────┤\n");
    printf("  │  11. Create user                                 │\n");
    printf("  │  12. List all users                              │\n");
    printf("  │  13. Delete user                                 │\n");
    printf("  ├───── Role Management ────────────────────────────┤\n");
    printf("  │  14. Create role                                 │\n");
    printf("  │  15. List all roles                              │\n");
    printf("  │  16. Delete role                                 │\n");
    printf("  │  17. Assign role to user                         │\n");
    printf("  │  18. Unassign role from user                     │\n");
    printf("  ├───── Group Management ───────────────────────────┤\n");
    printf("  │  19. Create group                                │\n");
    printf("  │  20. List all groups                             │\n");
    printf("  │  21. Add user to group                           │\n");
    printf("  │  22. Remove user from group                      │\n");
    printf("  │  0. Exit                                         │\n");
    printf("  └──────────────────────────────────────────────────┘\n");
    printf("  Choice: ");
    fflush(stdout);
}

/* ------------------------------------------------------------------
 * Sub-menus for each strategy type
 * ------------------------------------------------------------------ */

static void config_functional(policy_manager_t *pmgr) {
    printf("\n  ─── Functional Permission ───\n");
    printf("  Controls feature/menu/button-level access.\n");
    printf("  Examples: \"user:create\", \"report:*\", \"admin:settings\"\n\n");

    char name[64], code[128], effect[8];
    prompt_line("  Policy name [Functional Rules]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "Functional Rules");
    prompt_line("  Function code (e.g. report:view): ", code, sizeof(code));
    if (code[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"functions\":[{\"code\":\"%s\",\"effect\":\"%s\"}]}", code, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  \u2192 %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_api(policy_manager_t *pmgr) {
    printf("\n  ─── API Endpoint Permission ───\n");
    printf("  Controls HTTP method + path access.\n");
    printf("  Supports wildcards: * matches any method/path segment.\n\n");

    char name[64], method[8], path[SSO_MAX_PATH], effect[8];
    prompt_line("  Policy name [API Rules]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "API Rules");
    prompt_line("  HTTP method (GET/POST/PUT/DELETE/*): ", method, sizeof(method));
    if (method[0] == '\0') strcpy(method, "GET");
    prompt_line("  Path (e.g. /api/v1/users/*): ", path, sizeof(path));
    if (path[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"endpoints\":[{\"method\":\"%s\",\"path\":\"%s\",\"effect\":\"%s\"}]}",
        method, path, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_API, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  \u2192 %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_data(policy_manager_t *pmgr) {
    printf("\n  ─── Data Scope Permission ───\n");
    printf("  Controls resource/field-level access with conditions.\n\n");

    char name[64], resource[64], scope[32], fields[256], effect[8];
    prompt_line("  Policy name [Data Rules]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "Data Rules");
    prompt_line("  Resource type (e.g. order, customer, report): ", resource, sizeof(resource));
    if (resource[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Scope (self/organization/all) [all]: ", scope, sizeof(scope));
    if (scope[0] == '\0') strcpy(scope, "all");
    prompt_line("  Allowed fields (comma-separated, e.g. id,name,email): ", fields, sizeof(fields));
    if (fields[0] == '\0') strcpy(fields, "id");
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    /* Build JSON fields array from comma-separated input */
    char field_list[512];
    size_t flen = 0;
    field_list[0] = '\0';
    char fields_copy[256];
    strncpy(fields_copy, fields, sizeof(fields_copy));
    char *tok = strtok(fields_copy, ",");
    while (tok) {
        while (*tok == ' ') { memmove(tok, tok+1, strlen(tok)); }
        char *endp = tok + strlen(tok) - 1;
        while (endp > tok && *endp == ' ') *endp-- = '\0';
        if (flen > 0) { strncat(field_list, ",", sizeof(field_list) - flen - 1); flen++; }
        char entry[64];
        int n = snprintf(entry, sizeof(entry), "\"%s\"", tok);
        strncat(field_list, entry, sizeof(field_list) - flen - 1);
        flen += (size_t)n;
        tok = strtok(NULL, ",");
    }

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"rules\":[{\"resource\":\"%s\",\"scope\":\"%s\",\"fields\":[%s]}],\"effect\":\"%s\"}",
        resource, scope, field_list, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_DATA, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  \u2192 %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_rbac(policy_manager_t *pmgr) {
    printf("\n  ─── RBAC Permission (Role-Based) ───\n");
    printf("  Grants access based on role membership.\n");
    printf("  The user must hold the specified role.\n\n");

    char name[64], role_name[64], effect[8];
    prompt_line("  Policy name [RBAC Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "RBAC Rule");
    prompt_line("  Role name to check (e.g. admin, editor): ", role_name, sizeof(role_name));
    if (role_name[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"roles\":[{\"name\":\"%s\",\"effect\":\"%s\"}]}", role_name, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_RBAC, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  \u2192 %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_location(policy_manager_t *pmgr) {
    printf("\n  ─── Location Permission (IP-Based) ───\n");
    printf("  Controls access based on source IP address.\n");
    printf("  Uses CIDR notation: 10.0.0.0/8, 192.168.0.0/16, etc.\n\n");

    char name[64], cidr[128], effect[8];
    prompt_line("  Policy name [Location Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "Location Rule");
    prompt_line("  CIDR range (e.g. 10.0.0.0/8): ", cidr, sizeof(cidr));
    if (cidr[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"locations\":[{\"type\":\"ip_cidr\",\"value\":\"%s\",\"effect\":\"%s\"}]}",
        cidr, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_LOCATION, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  \u2192 %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_lbac(policy_manager_t *pmgr) {
    printf("\n  ─── LBAC Permission (Label-Based) ───\n");
    printf("  Controls access based on security labels (MLS).\n");
    printf("  Examples: \"INTERNAL\", \"CONFIDENTIAL\", \"TOP_SECRET\"\n\n");

    char name[64], label[64], effect[8];
    prompt_line("  Policy name [LBAC Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "LBAC Rule");
    prompt_line("  Required label (e.g. CONFIDENTIAL): ", label, sizeof(label));
    if (label[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"labels\":[{\"name\":\"%s\",\"effect\":\"%s\"}]}", label, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_LBAC, POLICY_EFFECT_ALLOW, 55, rules, &p);
    printf("  \u2192 %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_abac(policy_manager_t *pmgr) {
    printf("\n  ─── ABAC Permission (Attribute-Based) ───\n");
    printf("  Evaluates conditions against subject/resource/environment attributes.\n");
    printf("  Operators: eq, neq, gt, gte, lt, lte, contains, in\n\n");

    char name[64], source[16], attr[64], op[16], value[128], logic[8], effect[8];
    prompt_line("  Policy name [ABAC Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "ABAC Rule");
    prompt_line("  Attribute source (subject/resource/environment) [subject]: ", source, sizeof(source));
    if (source[0] == '\0') strcpy(source, "subject");
    prompt_line("  Attribute name (e.g. department, clearance): ", attr, sizeof(attr));
    if (attr[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Operator (eq/neq/gt/gte/lt/lte/contains/in) [eq]: ", op, sizeof(op));
    if (op[0] == '\0') strcpy(op, "eq");
    prompt_line("  Value to compare (e.g. engineering, 3): ", value, sizeof(value));
    if (value[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Logic (and/or) [and]: ", logic, sizeof(logic));
    if (logic[0] == '\0') strcpy(logic, "and");
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"conditions\":[{\"source\":\"%s\",\"attr\":\"%s\",\"op\":\"%s\",\"value\":\"%s\"}],\"logic\":\"%s\",\"effect\":\"%s\"}",
        source, attr, op, value, logic, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_ABAC, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  \u2192 %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

/* ------------------------------------------------------------------
 * Action: assign policy to a role
 * ------------------------------------------------------------------ */
static void action_assign(policy_manager_t *pmgr, role_manager_t *rmgr) {
    printf("\n  ─── Assign Policy to Role ───\n");
    char pid_str[16], rid_str[16];
    prompt_line("  Policy ID: ", pid_str, sizeof(pid_str));
    if (pid_str[0] == '\0') return;
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;

    sso_id_t policy_id = (sso_id_t)atoll(pid_str);
    sso_id_t role_id = (sso_id_t)atoll(rid_str);

    /* Verify role exists */
    role_t r;
    if (role_get_by_id(rmgr, role_id, &r) != SSO_OK) {
        printf("  Role %lu not found.\n", (unsigned long)role_id);
        return;
    }

    sso_error_t err = policy_assign_to(pmgr, policy_id, POLICY_TARGET_ROLE, role_id);
    printf("  \u2192 %s\n",
        err == SSO_OK ? "Assigned" : sso_strerror(err));
    if (err == SSO_OK) {
        printf("  Policy %lu \u2192 Role \"%s\"\n", (unsigned long)policy_id, r.name);
    }
}

/* ------------------------------------------------------------------
 * Action: test a permission check
 * ------------------------------------------------------------------ */
static void action_check(sso_context_t *ctx) {
    printf("\n  ─── Test Permission Check ───\n");
    printf("  Strategy types: 1=Functional  2=API  3=Data\n");
    printf("                  4=RBAC        5=Location  6=ABAC  7=LBAC\n");
    char type_str[4], uid_str[16];
    prompt_line("  Strategy type (1-7): ", type_str, sizeof(type_str));
    if (type_str[0] == '\0') return;
    int st = atoi(type_str);
    prompt_line("  User ID [1]: ", uid_str, sizeof(uid_str));
    sso_id_t uid = uid_str[0] ? (sso_id_t)atoll(uid_str) : 1;

    bool allowed = false;
    sso_error_t err = SSO_ERR_GENERAL;

    switch (st) {
    case 1: { /* Functional */
        char code[128];
        prompt_line("  Function code (e.g. report:view): ", code, sizeof(code));
        if (code[0]) err = perm_check_function(ctx, uid, code, &allowed);
        printf("  check_function(\"%s\") \u2192 %s\n", code, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 2: { /* API */
        char method[8], path[SSO_MAX_PATH];
        prompt_line("  HTTP method: ", method, sizeof(method));
        prompt_line("  Path: ", path, sizeof(path));
        if (method[0] && path[0]) err = perm_check_api(ctx, uid, method, path, &allowed);
        printf("  check_api(\"%s %s\") \u2192 %s\n", method, path, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 3: { /* Data */
        char rtype[64], record[512];
        prompt_line("  Resource type: ", rtype, sizeof(rtype));
        prompt_line("  Record JSON (or empty): ", record, sizeof(record));
        if (rtype[0]) {
            char **fields = NULL;
            size_t fcount = 0;
            err = perm_check_data(ctx, uid, rtype,
                record[0] ? record : NULL, &allowed, &fields, &fcount);
            printf("  check_data(\"%s\") \u2192 %s", rtype, allowed ? "ALLOW" : "DENY");
            if (fields) {
                printf("  fields=[");
                for (size_t i = 0; i < fcount; i++) {
                    printf("%s%s", fields[i], i < fcount-1 ? "," : "");
                    free(fields[i]);
                }
                printf("]");
                free(fields);
            }
            printf("\n");
        }
        break;
    }
    case 4: { /* RBAC */
        char rname[64];
        prompt_line("  Role name: ", rname, sizeof(rname));
        if (rname[0]) err = perm_check_rbac(ctx, uid, rname, &allowed);
        printf("  check_rbac(\"%s\") \u2192 %s\n", rname, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 5: { /* Location */
        char ip[64];
        prompt_line("  Source IP address: ", ip, sizeof(ip));
        if (ip[0]) err = perm_check_location(ctx, uid, ip, NULL, &allowed);
        printf("  check_location(\"%s\") \u2192 %s\n", ip, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 6: { /* ABAC */
        char attrs[SSO_MAX_ATTRIBUTES];
        prompt_line("  Subject attrs JSON (e.g. {\"department\":\"engineering\"}): ", attrs, sizeof(attrs));
        if (attrs[0]) err = perm_check_abac(ctx, uid, attrs, NULL, NULL, &allowed);
        printf("  check_abac() \u2192 %s\n", allowed ? "ALLOW" : "DENY");
        break;
    }
    case 7: { /* LBAC (Label-Based) */
        char u_labels[256], r_label[64];
        prompt_line("  User labels (comma-separated): ", u_labels, sizeof(u_labels));
        prompt_line("  Resource label: ", r_label, sizeof(r_label));
        if (u_labels[0] && r_label[0]) err = perm_check_lbac(ctx, uid, u_labels, r_label, &allowed);
        printf("  check_lbac(\"%s\", \"%s\") \u2192 %s\n", u_labels, r_label, allowed ? "ALLOW" : "DENY");
        break;
    }
    default:
        printf("  Invalid type.\n");
        return;
    }
    if (err != SSO_OK) {
        printf("  (engine: %s)\n", sso_strerror(err));
    }
}

/* ------------------------------------------------------------------
 * Action: list all policies
 * ------------------------------------------------------------------ */
static void action_list(policy_manager_t *pmgr) {
    printf("\n  ─── All Policies ───\n");
    for (sso_id_t i = 1; i <= 64; i++) {
        policy_t p;
        if (policy_get_by_id(pmgr, i, &p) == SSO_OK) {
            printf("  [%2lu] %-30s type=%-2d pri=%-3d status=%s  rules=%.40s\n",
                (unsigned long)p.id, p.name, p.strategy_type, p.priority,
                p.status == POLICY_STATUS_ENABLED ? "enabled" : "disabled",
                p.rules);
        }
    }
}

/* ------------------------------------------------------------------
 * Entity management actions
 * ------------------------------------------------------------------ */

static void action_create_user(user_manager_t *umgr) {
    printf("\n  ─── Create User ───\n");
    char username[SSO_MAX_USERNAME];
    char password[SSO_MAX_USERNAME];
    char email[SSO_MAX_EMAIL];
    char display_name[SSO_MAX_DISPLAY_NAME];

    prompt_line("  Username: ", username, sizeof(username));
    if (username[0] == '\0') return;
    prompt_line("  Password: ", password, sizeof(password));
    if (password[0] == '\0') return;
    prompt_line("  Email (optional): ", email, sizeof(email));
    prompt_line("  Display name (optional): ", display_name, sizeof(display_name));

    user_t u;
    sso_error_t err = user_create(umgr, username, password, email, display_name, &u);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Created" : sso_strerror(err),
        (unsigned long)u.id);
}

static void action_list_users(sso_context_t *ctx) {
    printf("\n  ─── All Users ───\n");
    user_manager_t  *umgr = (user_manager_t  *)ctx->user_mgr;
    role_manager_t  *rmgr = (role_manager_t  *)ctx->role_mgr;
    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;

    sso_id_t ids[256];
    size_t count = 0;
    if (user_list(umgr, ids, &count, 256) != SSO_OK) {
        printf("  Failed to list users.\n");
        return;
    }

    for (size_t i = 0; i < count; i++) {
        user_t u;
        if (user_get_by_id(umgr, ids[i], &u) != SSO_OK) continue;

        sso_id_t role_ids[16], group_ids[16];
        size_t rc = 0, gc = 0;
        user_get_roles(umgr, u.id, role_ids, &rc, 16);
        user_get_groups(umgr, u.id, group_ids, &gc, 16);

        printf("  [%2lu] %-12s  status=%-6s  email=%-20s",
            (unsigned long)u.id, u.username,
            u.status == USER_STATUS_ACTIVE ? "active" :
            u.status == USER_STATUS_LOCKED ? "locked" : "inactive",
            u.email);

        if (rc > 0) {
            printf("  roles=[");
            for (size_t j = 0; j < rc; j++) {
                role_t r;
                if (role_get_by_id(rmgr, role_ids[j], &r) == SSO_OK)
                    printf("%s%s", r.name, j < rc - 1 ? "," : "");
            }
            printf("]");
        }

        if (gc > 0) {
            printf("  groups=[");
            for (size_t j = 0; j < gc; j++) {
                group_t g;
                if (group_get_by_id(gmgr, group_ids[j], &g) == SSO_OK)
                    printf("%s%s", g.name, j < gc - 1 ? "," : "");
            }
            printf("]");
        }
        printf("\n");
    }
    printf("  Total: %zu user(s)\n", count);
}

static void action_delete_user(user_manager_t *umgr) {
    printf("\n  ─── Delete User ───\n");
    char uid_str[16];
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;
    sso_id_t uid = (sso_id_t)atoll(uid_str);

    user_t u;
    if (user_get_by_id(umgr, uid, &u) != SSO_OK) {
        printf("  User %lu not found.\n", (unsigned long)uid);
        return;
    }
    sso_error_t err = user_delete(umgr, uid);
    printf("  → %s\n", err == SSO_OK ? "Deleted" : sso_strerror(err));
}

static void action_create_role(role_manager_t *rmgr) {
    printf("\n  ─── Create Role ───\n");
    char name[SSO_MAX_ROLE_NAME], desc[SSO_MAX_DESCRIPTION], pid_str[16];
    prompt_line("  Role name: ", name, sizeof(name));
    if (name[0] == '\0') return;
    prompt_line("  Description (optional): ", desc, sizeof(desc));
    prompt_line("  Parent role ID (0=none): ", pid_str, sizeof(pid_str));
    sso_id_t parent_id = pid_str[0] ? (sso_id_t)atoll(pid_str) : SSO_ID_NONE;

    role_t r;
    sso_error_t err = role_create(rmgr, name, desc, parent_id, &r);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Created" : sso_strerror(err),
        (unsigned long)r.id);
}

static void action_list_roles(role_manager_t *rmgr) {
    printf("\n  ─── All Roles ───\n");
    sso_id_t ids[256];
    size_t count = 0;
    if (role_list(rmgr, ids, &count, 256) != SSO_OK) {
        printf("  Failed to list roles.\n");
        return;
    }

    for (size_t i = 0; i < count; i++) {
        role_t r;
        if (role_get_by_id(rmgr, ids[i], &r) != SSO_OK) continue;
        printf("  [%2lu] %-16s  parent=%-3lu  desc=%s\n",
            (unsigned long)r.id, r.name,
            (unsigned long)r.parent_role_id,
            r.description);
    }
    printf("  Total: %zu role(s)\n", count);
}

static void action_delete_role(role_manager_t *rmgr) {
    printf("\n  ─── Delete Role ───\n");
    char rid_str[16];
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;
    sso_id_t rid = (sso_id_t)atoll(rid_str);

    role_t r;
    if (role_get_by_id(rmgr, rid, &r) != SSO_OK) {
        printf("  Role %lu not found.\n", (unsigned long)rid);
        return;
    }
    sso_error_t err = role_delete(rmgr, rid);
    printf("  → %s\n", err == SSO_OK ? "Deleted" : sso_strerror(err));
}

static void action_assign_role_to_user(role_manager_t *rmgr) {
    printf("\n  ─── Assign Role to User ───\n");
    char rid_str[16], uid_str[16];
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t rid = (sso_id_t)atoll(rid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = role_assign_to_user(rmgr, rid, uid);
    printf("  → %s\n", err == SSO_OK ? "Assigned" : sso_strerror(err));
}

static void action_unassign_role_from_user(role_manager_t *rmgr) {
    printf("\n  ─── Unassign Role from User ───\n");
    char rid_str[16], uid_str[16];
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t rid = (sso_id_t)atoll(rid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = role_unassign_from_user(rmgr, rid, uid);
    printf("  → %s\n", err == SSO_OK ? "Unassigned" : sso_strerror(err));
}

static void action_create_group(group_manager_t *gmgr) {
    printf("\n  ─── Create Group ───\n");
    char name[SSO_MAX_GROUP_NAME], desc[SSO_MAX_DESCRIPTION], pid_str[16];
    prompt_line("  Group name: ", name, sizeof(name));
    if (name[0] == '\0') return;
    prompt_line("  Description (optional): ", desc, sizeof(desc));
    prompt_line("  Parent group ID (0=none): ", pid_str, sizeof(pid_str));
    sso_id_t parent_id = pid_str[0] ? (sso_id_t)atoll(pid_str) : SSO_ID_NONE;

    group_t g;
    sso_error_t err = group_create(gmgr, name, desc, parent_id, &g);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Created" : sso_strerror(err),
        (unsigned long)g.id);
}

static void action_list_groups(group_manager_t *gmgr) {
    printf("\n  ─── All Groups ───\n");
    sso_id_t ids[256];
    size_t count = 0;
    if (group_list(gmgr, ids, &count, 256) != SSO_OK) {
        printf("  Failed to list groups.\n");
        return;
    }

    for (size_t i = 0; i < count; i++) {
        group_t g;
        if (group_get_by_id(gmgr, ids[i], &g) != SSO_OK) continue;
        printf("  [%2lu] %-16s  parent=%-3lu  desc=%s\n",
            (unsigned long)g.id, g.name,
            (unsigned long)g.parent_group_id,
            g.description);
    }
    printf("  Total: %zu group(s)\n", count);
}

static void action_add_user_to_group(group_manager_t *gmgr) {
    printf("\n  ─── Add User to Group ───\n");
    char gid_str[16], uid_str[16];
    prompt_line("  Group ID: ", gid_str, sizeof(gid_str));
    if (gid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t gid = (sso_id_t)atoll(gid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = group_add_user(gmgr, gid, uid);
    printf("  → %s\n", err == SSO_OK ? "Added" : sso_strerror(err));
}

static void action_remove_user_from_group(group_manager_t *gmgr) {
    printf("\n  ─── Remove User from Group ───\n");
    char gid_str[16], uid_str[16];
    prompt_line("  Group ID: ", gid_str, sizeof(gid_str));
    if (gid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t gid = (sso_id_t)atoll(gid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = group_remove_user(gmgr, gid, uid);
    printf("  → %s\n", err == SSO_OK ? "Removed" : sso_strerror(err));
}

/* ========================================================================
 * Interactive configuration shell entry point
 * ======================================================================== */
static int interactive_config(void) {
    sso_error_t err;

    printf("=== SSO Interactive Configuration ===\n\n");

    /* Initialize */
    storage_backend_t *storage = NULL;
    err = storage_sqlite_create(&storage);
    if (err != SSO_OK) {
        fprintf(stderr, "Failed to create storage: %s\n", sso_strerror(err));
        return 1;
    }

    sso_context_t ctx;
    err = sso_init(&ctx, storage, "sso_config.db");
    if (err != SSO_OK) {
        fprintf(stderr, "Failed to init SSO: %s\n", sso_strerror(err));
        return 1;
    }
    printf("System initialized (db: sso_config.db)\n");

    /* Bootstrap default users, roles, groups if first run */
    {
        user_manager_t  *umgr = (user_manager_t  *)ctx.user_mgr;
        role_manager_t  *rmgr = (role_manager_t  *)ctx.role_mgr;
        group_manager_t *gmgr = (group_manager_t *)ctx.group_mgr;

        /* Check if admin exists already */
        user_t admin;
        err = user_get_by_username(umgr, "admin", &admin);
        if (err != SSO_OK) {
            printf("Bootstrapping default data...\n");

            user_t admin_user, alice_user, bob_user;
            user_create(umgr, "admin", "admin123", "admin@example.com", "Admin", &admin_user);
            user_create(umgr, "alice", "alice456", "alice@example.com", "Alice", &alice_user);
            user_create(umgr, "bob",   "bob789",   "bob@example.com",   "Bob",   &bob_user);

            role_t admin_role, editor_role, viewer_role;
            role_create(rmgr, "admin",  "Full system access",   SSO_ID_NONE, &admin_role);
            role_create(rmgr, "editor", "Can edit content",     admin_role.id, &editor_role);
            role_create(rmgr, "viewer", "Read-only access",     editor_role.id, &viewer_role);

            group_t engineering, finance;
            group_create(gmgr, "engineering", "Engineering", SSO_ID_NONE, &engineering);
            group_create(gmgr, "finance",     "Finance",     SSO_ID_NONE, &finance);

            role_assign_to_user(rmgr, admin_role.id, admin_user.id);
            role_assign_to_user(rmgr, editor_role.id, alice_user.id);
            role_assign_to_user(rmgr, viewer_role.id, bob_user.id);
            group_add_user(gmgr, engineering.id, alice_user.id);
            group_add_user(gmgr, finance.id, bob_user.id);

            printf("  Users:  admin(1), alice(2), bob(3)\n");
            printf("  Roles:  admin(1), editor(2), viewer(3)\n");
            printf("  Groups: engineering(1), finance(2)\n");
        } else {
            printf("Existing database found with admin user.\n");
        }
    }

    print_banner();

    user_manager_t  *umgr = (user_manager_t  *)ctx.user_mgr;
    role_manager_t  *rmgr = (role_manager_t  *)ctx.role_mgr;
    group_manager_t *gmgr = (group_manager_t *)ctx.group_mgr;
    policy_manager_t *pmgr = (policy_manager_t *)ctx.policy_mgr;

    char choice[16];
    int running = 1;
    while (running) {
        print_menu();
        if (!fgets(choice, sizeof(choice), stdin)) break;
        int opt = atoi(choice);

        switch (opt) {
        case 1:  config_functional(pmgr); break;
        case 2:  config_api(pmgr); break;
        case 3:  config_data(pmgr); break;
        case 4:  config_rbac(pmgr); break;
        case 5:  config_location(pmgr); break;
        case 6:  config_abac(pmgr); break;
        case 7:  config_lbac(pmgr); break;
        case 8:  action_assign(pmgr, rmgr); break;
        case 9:  action_check(&ctx); break;
        case 10: action_list(pmgr); break;
        case 11: action_create_user(umgr); break;
        case 12: action_list_users(&ctx); break;
        case 13: action_delete_user(umgr); break;
        case 14: action_create_role(rmgr); break;
        case 15: action_list_roles(rmgr); break;
        case 16: action_delete_role(rmgr); break;
        case 17: action_assign_role_to_user(rmgr); break;
        case 18: action_unassign_role_from_user(rmgr); break;
        case 19: action_create_group(gmgr); break;
        case 20: action_list_groups(gmgr); break;
        case 21: action_add_user_to_group(gmgr); break;
        case 22: action_remove_user_from_group(gmgr); break;
        case 0:  running = 0; break;
        default: printf("  Invalid option.\n"); break;
        }
        printf("\n");
    }

    printf("Exiting. Database saved to sso_config.db\n");
    printf("Reuse with --interactive (existing config) or delete sso_config.db for fresh start.\n");
    sso_destroy(&ctx);
    return 0;
}

/* ========================================================================
 * Helpers: JSON field extraction (minimal — no external parser needed)
 * ======================================================================== */

/* Find a JSON string value by key.  Returns malloc'd copy or NULL.
 * Handles escaped quotes (\\") inside the string value. */
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

    /* Find closing quote, respecting \\" escapes */
    const char *end = p;
    while (*end) {
        if (*end == '\\' && *(end + 1) == '"') {
            end += 2; /* skip escaped quote */
        } else if (*end == '"') {
            break;
        } else {
            end++;
        }
    }

    size_t len = (size_t)(end - p);
    char *val = (char *)malloc(len + 1);
    if (!val) return NULL;
    /* Copy and unescape */
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == '\\' && i + 1 < len && p[i + 1] == '"') {
            val[j++] = '"';
            i++; /* skip backslash */
        } else {
            val[j++] = p[i];
        }
    }
    val[j] = '\0';
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

/* GET /metrics */
static sso_error_t handle_metrics(sso_context_t *ctx, const http_request_t *req,
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

/* POST /api/v1/auth/login */
static sso_error_t handle_login(sso_context_t *ctx, const http_request_t *req,
                                 http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    /* Rate limiting: 5 attempts per minute per IP */
    if (ctx->rate_limiter) {
        sso_error_t rerr = rate_limiter_check((rate_limiter_t *)ctx->rate_limiter, 
                                               req->client_ip, 60000, 5);
        if (rerr != SSO_OK) {
            sso_response_error(resp, 429, "Too many login attempts. Please wait.");
            return SSO_OK;
        }
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

    /* Success: reset rate limit for this IP */
    if (ctx->rate_limiter) {
        rate_limiter_reset((rate_limiter_t *)ctx->rate_limiter, req->client_ip);
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

/* POST /api/v1/auth/send_sms */
static sso_error_t handle_send_sms(sso_context_t *ctx, const http_request_t *req,
                                   http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *phone = json_str_value(req->body, "phone");
    if (!phone) {
        sso_response_error(resp, 400, "phone required");
        return SSO_OK;
    }

    /* 1. 安全防刷检查：IP 限流 (1 min / 1 request) */
    if (ctx->rate_limiter) {
        sso_error_t rerr = rate_limiter_check((rate_limiter_t *)ctx->rate_limiter, 
                                               req->client_ip, 60000, 1);
        if (rerr != SSO_OK) {
            free(phone);
            sso_response_error(resp, 429, "Too many SMS requests. Please wait 1 minute.");
            return SSO_OK;
        }
    }

    /* 2. 生成 6 位随机验证码 */
    char code[8];
    snprintf(code, sizeof(code), "%06d", rand() % 1000000);

    /* 3. 存储到数据库 sms_codes 表，设置 5 分钟 (300秒) 过期 */
    storage_backend_t *sb = (storage_backend_t *)ctx->storage_backend;
    sso_error_t err = SSO_ERR_NOT_IMPLEMENTED;
    if (sb && sb->save_sms_code) {
        err = sb->save_sms_code(sb, phone, code, sso_timestamp_now() + 300000);
    }

    if (err != SSO_OK) {
        free(phone);
        sso_response_error(resp, 500, "Failed to generate SMS code");
        return SSO_OK;
    }

    /* 4. 调用真实发送逻辑 (libcurl) */
    err = send_real_sms(phone, code);
    if (err != SSO_OK) {
        free(phone);
        sso_response_error(resp, 500, "SMS gateway error");
        return SSO_OK;
    }
    
    free(phone);
    sso_response_ok(resp, "{\"status\":\"sent\"}");
    return SSO_OK;
}

/* POST /api/v1/auth/login_by_sms */
static sso_error_t handle_login_by_sms(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *phone = json_str_value(req->body, "phone");
    char *code  = json_str_value(req->body, "code");

    if (!phone || !code) {
        if (phone) free(phone);
        if (code) free(code);
        sso_response_error(resp, 400, "phone and code required");
        return SSO_OK;
    }

    storage_backend_t *sb = (storage_backend_t *)ctx->storage_backend;
    if (!sb || !sb->get_sms_code || !sb->delete_sms_code) {
        free(phone); free(code);
        sso_response_error(resp, 500, "SMS feature not enabled in storage backend");
        return SSO_OK;
    }

    /* 1. 验证码校验 */
    char expected_code[16];
    sso_error_t err = sb->get_sms_code(sb, phone, expected_code);
    if (err != SSO_OK || strcmp(code, expected_code) != 0) {
        free(phone); free(code);
        sso_response_error(resp, 401, "Invalid or expired verification code");
        return SSO_OK;
    }

    /* 验证成功即销毁，防重放 */
    sb->delete_sms_code(sb, phone);
    free(code);

    /* 2. 获取用户 (如果不存在则自动注册) */
    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    err = user_get_by_phone(umgr, phone, &user);
    if (err == SSO_ERR_NOT_FOUND) {
        /* 自动注册：对于手机验证码登录，无需密码 */
        err = user_create_by_phone(umgr, phone, &user);
    }
    
    if (err != SSO_OK || user.status != USER_STATUS_ACTIVE) {
        free(phone);
        sso_response_error(resp, 403, "Account disabled or error");
        return SSO_OK;
    }
    free(phone);

    /* 3. 签发 JWT Token (复用现有的 token_issue) */
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

    /* 4. 返回标准 Token */
    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{"
        "\"token\":\"%s\","
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"phone\":\"%s\""
        "}",
        token.token_str,
        (unsigned long long)user.id,
        user.username,
        user.phone);
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

    if (err == SSO_OK) {
        /* Assign default 'user' role */
        role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
        role_t member_role;
        if (role_get_by_name(rmgr, "user", &member_role) == SSO_OK) {
            role_assign_to_user(rmgr, member_role.id, user.id);
        } else {
            /* If 'user' role doesn't exist, try to create it */
            if (role_create(rmgr, "user", "Regular member", SSO_ID_NONE, &member_role) == SSO_OK) {
                role_assign_to_user(rmgr, member_role.id, user.id);
            }
        }
    }

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
        "\"email\":\"%s\","
        "\"display_name\":\"%s\","
        "\"expires_at\":%lld"
        "}",
        (unsigned long long)user.id,
        user.username,
        user.email,
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

/* POST /api/v1/auth/change_password */
static sso_error_t handle_change_password(sso_context_t *ctx, const http_request_t *req,
                                           http_response_t *resp) {
    auth_context_t *auth = (auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *new_pass = json_str_value(req->body, "password");
    if (!new_pass || strlen(new_pass) < 6) {
        if (new_pass) free(new_pass);
        sso_response_error(resp, 400, "Password must be at least 6 characters");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    sso_error_t err = user_set_password(umgr, auth->user.id, new_pass);
    free(new_pass);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to update password");
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"updated\":true}");
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

static sso_error_t handle_check_permission(sso_context_t *ctx, const http_request_t *req,
                                         http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    eval_context_t ectx;
    user_t user;
    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    if (user_get_by_id(umgr, user_id, &user) != SSO_OK) {
        sso_response_error(resp, 404, "User not found");
        return SSO_OK;
    }

    eval_context_init(&ectx, &user);

    /* Populate the context with all available parameters from the JSON body */
    char *function_code = json_str_value(req->body, "function_code");
    if (function_code) {
        strncpy(ectx.params.functional.function_code, function_code, sizeof(ectx.params.functional.function_code) - 1);
        free(function_code);
    }

    char *api_method = json_str_value(req->body, "api_method");
    char *api_path = json_str_value(req->body, "api_path");
    if (api_method && api_path) {
        strncpy(ectx.params.api.http_method, api_method, sizeof(ectx.params.api.http_method) - 1);
        strncpy(ectx.params.api.request_path, api_path, sizeof(ectx.params.api.request_path) - 1);
        free(api_method); free(api_path);
    }

    char *resource_type = json_str_value(req->body, "resource_type");
    if (resource_type) {
        strncpy(ectx.params.data.resource_type, resource_type, sizeof(ectx.params.data.resource_type) - 1);
        free(resource_type);
        
        char *record = json_str_value(req->body, "record");
        if (record) {
             ectx.params.data.record = record; /* Must be freed later */
        }
    }

    char *role_name = json_str_value(req->body, "role_name");
    if (role_name) {
        strncpy(ectx.params.rbac.role_name, role_name, sizeof(ectx.params.rbac.role_name) - 1);
        free(role_name);
    }

    char *source_ip = json_str_value(req->body, "source_ip");
    if (source_ip) {
        strncpy(ectx.params.location.source_ip, source_ip, sizeof(ectx.params.location.source_ip) - 1);
        free(source_ip);
    }

    char *lbac_user_labels = json_str_value(req->body, "lbac_user_labels");
    char *lbac_resource_label = json_str_value(req->body, "lbac_resource_label");
    if (lbac_user_labels && lbac_resource_label) {
        strncpy(ectx.params.lbac.user_labels, lbac_user_labels, sizeof(ectx.params.lbac.user_labels) - 1);
        strncpy(ectx.params.lbac.resource_label, lbac_resource_label, sizeof(ectx.params.lbac.resource_label) - 1);
        free(lbac_user_labels); free(lbac_resource_label);
    }

    char *abac_subject_attrs = json_str_value(req->body, "abac_subject_attrs");
    char *abac_resource_attrs = json_str_value(req->body, "abac_resource_attrs");
    char *abac_action = json_str_value(req->body, "abac_action");
    if (abac_subject_attrs) {
        strncpy(ectx.params.abac.subject_attrs, abac_subject_attrs, sizeof(ectx.params.abac.subject_attrs) - 1);
        free(abac_subject_attrs);
    }
    if (abac_resource_attrs) {
        strncpy(ectx.params.abac.resource_attrs, abac_resource_attrs, sizeof(ectx.params.abac.resource_attrs) - 1);
        free(abac_resource_attrs);
    }
    if (abac_action) {
        strncpy(ectx.params.abac.action, abac_action, sizeof(ectx.params.abac.action) - 1);
        free(abac_action);
    }

    char *env_attrs = json_str_value(req->body, "environment");
    if (env_attrs) {
        strncpy(ectx.environment, env_attrs, sizeof(ectx.environment) - 1);
        free(env_attrs);
    }

    bool allowed = false;
    char *trace = NULL;
    sso_error_t err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, &allowed, &trace);

    if (err != SSO_OK) {
        if (ectx.params.data.record) free((void *)ectx.params.data.record);
        if (trace) free(trace);
        eval_context_destroy(&ectx);
        sso_response_error(resp, 500, "Permission evaluation failed");
        return SSO_OK;
    }

    /* Build JSON response */
    char buf[8192];
    
    /* Safely format trace for JSON if present */
    char escaped_trace[4096] = "";
    if (trace) {
        size_t j = 0;
        for (size_t i = 0; trace[i] && j < sizeof(escaped_trace) - 3; i++) {
            if (trace[i] == '"') { escaped_trace[j++] = '\\'; escaped_trace[j++] = '"'; }
            else if (trace[i] == '\n') { escaped_trace[j++] = '\\'; escaped_trace[j++] = 'n'; }
            else if (trace[i] == '\t') { escaped_trace[j++] = '\\'; escaped_trace[j++] = 't'; }
            else escaped_trace[j++] = trace[i];
        }
    }

    /* Serialize allowed fields if present */
    char fields_buf[1024] = "[]";
    if (ectx.params.data.field_filter_count > 0) {
        strcpy(fields_buf, "[");
        for (size_t i = 0; i < ectx.params.data.field_filter_count; i++) {
            char fbuf[128];
            snprintf(fbuf, sizeof(fbuf), "\"%s\"%s", ectx.params.data.field_filter[i],
                     i < ectx.params.data.field_filter_count - 1 ? "," : "");
            strncat(fields_buf, fbuf, sizeof(fields_buf) - strlen(fields_buf) - 1);
        }
        strcat(fields_buf, "]");
    }

    snprintf(buf, sizeof(buf),
             "{"
             "\"allowed\":%s,"
             "\"allowed_fields\":%s,"
             "\"trace\":\"%s\""
             "}",
             allowed ? "true" : "false",
             fields_buf,
             trace ? escaped_trace : "");

    sso_response_ok(resp, buf);

    if (ectx.params.data.record) free((void *)ectx.params.data.record);
    if (trace) free(trace);
    eval_context_destroy(&ectx);
    
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

/* POST /api/v1/check/rbac */
static sso_error_t handle_check_rbac(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *role_name = json_str_value(req->body, "role_name");
    if (!role_name) {
        sso_response_error(resp, 400, "role_name required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        free(role_name);
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    bool allowed = false;
    sso_error_t err = perm_check_rbac(ctx, user_id, role_name, &allowed);

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"allowed\":%s,\"user_id\":%llu,\"role\":\"%s\"}",
        allowed ? "true" : "false",
        (unsigned long long)user_id,
        role_name);
    free(role_name);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/location */
static sso_error_t handle_check_location(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *source_ip  = json_str_value(req->body, "source_ip");
    char *geo_country = json_str_value(req->body, "geo_country");
    if (!source_ip) {
        free(source_ip); free(geo_country);
        sso_response_error(resp, 400, "source_ip required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        free(source_ip); free(geo_country);
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    bool allowed = false;
    sso_error_t err = perm_check_location(ctx, user_id, source_ip, geo_country, &allowed);

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"allowed\":%s,\"user_id\":%llu,\"source_ip\":\"%s\"}",
        allowed ? "true" : "false",
        (unsigned long long)user_id,
        source_ip);
    free(source_ip);
    free(geo_country);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/lbac */
static sso_error_t handle_check_lbac(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *user_labels    = json_str_value(req->body, "user_labels");
    char *resource_label = json_str_value(req->body, "resource_label");
    if (!user_labels || !resource_label) {
        free(user_labels); free(resource_label);
        sso_response_error(resp, 400, "user_labels and resource_label required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        free(user_labels); free(resource_label);
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    bool allowed = false;
    sso_error_t err = perm_check_lbac(ctx, user_id, user_labels, resource_label, &allowed);

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"allowed\":%s,\"user_id\":%llu,\"user_labels\":\"%s\",\"resource_label\":\"%s\"}",
        allowed ? "true" : "false",
        (unsigned long long)user_id,
        user_labels, resource_label);
    free(user_labels);
    free(resource_label);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/check/abac */
static sso_error_t handle_check_abac(sso_context_t *ctx, const http_request_t *req,
                                      http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *subject_attrs  = json_str_value(req->body, "subject_attrs");
    char *resource_attrs = json_str_value(req->body, "resource_attrs");
    char *action_str     = json_str_value(req->body, "action");

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        auth_context_t *auth = (auth_context_t *)req->userdata;
        if (auth) user_id = auth->user.id;
    }
    if (user_id == 0) {
        free(subject_attrs); free(resource_attrs); free(action_str);
        sso_response_error(resp, 400, "user_id or authentication required");
        return SSO_OK;
    }

    bool allowed = false;
    sso_error_t err = perm_check_abac(ctx, user_id,
                                       subject_attrs, resource_attrs,
                                       action_str, &allowed);

    char buf[1024];
    snprintf(buf, sizeof(buf),
        "{\"allowed\":%s,\"user_id\":%llu}",
        allowed ? "true" : "false",
        (unsigned long long)user_id);
    free(subject_attrs);
    free(resource_attrs);
    free(action_str);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, buf);
    return SSO_OK;
}

/* POST /api/v1/users — create user (admin endpoint) */
static sso_error_t handle_add_group_member(sso_context_t *ctx, const http_request_t *req,
                                           http_response_t *resp) {
    sso_id_t group_id = extract_path_id(req->path, "/groups/");
    if (!group_id || !req->body) {
        sso_response_error(resp, 400, "group_id and body required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    if (user_id == 0) {
        sso_response_error(resp, 400, "user_id required");
        return SSO_OK;
    }

    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;
    sso_error_t err = group_add_user(gmgr, group_id, user_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"added\":true}");
    return SSO_OK;
}

static sso_error_t handle_remove_group_member(sso_context_t *ctx, const http_request_t *req,
                                              http_response_t *resp) {
    /* Path: /api/v1/groups/:id/members/:user_id */
    sso_id_t group_id = extract_path_id(req->path, "/groups/");
    
    /* Extract user_id from end of path */
    const char *last_slash = strrchr(req->path, '/');
    if (!last_slash || !group_id) {
        sso_response_error(resp, 400, "invalid path");
        return SSO_OK;
    }
    sso_id_t user_id = (sso_id_t)atoll(last_slash + 1);

    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;
    sso_error_t err = group_remove_user(gmgr, group_id, user_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"removed\":true}");
    return SSO_OK;
}

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

    if (!role_id) {
        sso_response_error(resp, 400, "Invalid role ID in path");
        return SSO_OK;
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
        total += 2048;
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

        char roles_json[1024];
        roles_json[0] = '\0';
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

        /* Get groups for this user */
        sso_id_t group_ids[16];
        size_t gc = 0;
        user_get_groups(umgr, u.id, group_ids, &gc, 16);
        group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;

        char groups_json[1024];
        groups_json[0] = '\0';
        strcat(groups_json, "[");
        for (size_t j = 0; j < gc; j++) {
            group_t g;
            char buf[128];
            if (group_get_by_id(gmgr, group_ids[j], &g) == SSO_OK) {
                snprintf(buf, sizeof(buf), "%s{\"id\":%llu,\"name\":\"%s\"}",
                         j > 0 ? "," : "",
                         (unsigned long long)g.id, g.name);
                strcat(groups_json, buf);
            }
        }
        strcat(groups_json, "]");

        char buf[2048];
        snprintf(buf, sizeof(buf),
            "%s{"
            "\"id\":%llu,"
            "\"username\":\"%s\","
            "\"email\":\"%s\","
            "\"display_name\":\"%s\","
            "\"phone\":\"%s\","
            "\"status\":%d,"
            "\"roles\":%s,"
            "\"groups\":%s,"
            "\"created_at\":%lld"
            "}",
            i > 0 ? "," : "",
            (unsigned long long)u.id,
            u.username,
            u.email,
            u.display_name,
            u.phone,
            (int)u.status,
            roles_json,
            groups_json,
            (long long)u.created_at);
        strcat(json, buf);
    }
    strcat(json, "]");

    sso_response_ok(resp, json);
    free(json);
    return SSO_OK;
}

/* GET /api/v1/users/:id */
static sso_error_t handle_get_user(sso_context_t *ctx, const http_request_t *req,
                                    http_response_t *resp) {
    sso_id_t user_id = extract_path_id(req->path, "/api/v1/users/");
    if (user_id == 0) {
        sso_response_error(resp, 400, "Invalid user ID");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;

    user_t u;
    sso_error_t err = user_get_by_id(umgr, user_id, &u);
    if (err != SSO_OK) {
        sso_response_error(resp, 404, "User not found");
        return SSO_OK;
    }

    sso_id_t role_ids[16];
    size_t rc = 0;
    user_get_roles(umgr, u.id, role_ids, &rc, 16);

    char roles_json[1024];
    roles_json[0] = '\0';
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

    sso_id_t group_ids[16];
    size_t gc = 0;
    user_get_groups(umgr, u.id, group_ids, &gc, 16);

    char groups_json[1024];
    groups_json[0] = '\0';
    strcat(groups_json, "[");
    for (size_t j = 0; j < gc; j++) {
        group_t g;
        char buf[128];
        if (group_get_by_id(gmgr, group_ids[j], &g) == SSO_OK) {
            snprintf(buf, sizeof(buf), "%s{\"id\":%llu,\"name\":\"%s\"}",
                     j > 0 ? "," : "",
                     (unsigned long long)g.id, g.name);
            strcat(groups_json, buf);
        }
    }
    strcat(groups_json, "]");

    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"id\":%llu,"
        "\"username\":\"%s\","
        "\"email\":\"%s\","
        "\"display_name\":\"%s\","
        "\"phone\":\"%s\","
        "\"status\":%d,"
        "\"roles\":%s,"
        "\"groups\":%s,"
        "\"created_at\":%lld"
        "}",
        (unsigned long long)u.id,
        u.username,
        u.email,
        u.display_name,
        u.phone,
        (int)u.status,
        roles_json,
        groups_json,
        (long long)u.created_at);

    sso_response_ok(resp, json);
    return SSO_OK;
}

/* GET /api/v1/audit/logs */
static sso_error_t handle_list_audit_logs(sso_context_t *ctx, const http_request_t *req,
                                           http_response_t *resp) {
    (void)ctx; (void)req;
    FILE *f = fopen("audit.log", "r");
    if (!f) {
        sso_response_ok(resp, "[]");
        return SSO_OK;
    }

    /* Simple tail implementation: read last 100 lines */
    char *lines[100];
    int count = 0;
    char buffer[10240];

    while (fgets(buffer, sizeof(buffer), f)) {
        if (count < 100) {
            lines[count++] = strdup(buffer);
        } else {
            free(lines[0]);
            for (int i = 0; i < 99; i++) lines[i] = lines[i+1];
            lines[99] = strdup(buffer);
        }
    }
    fclose(f);

    /* Construct JSON array */
    size_t total_len = 3; /* [ ] \0 */
    for (int i = 0; i < count; i++) total_len += strlen(lines[i]) + 1;

    char *json = (char *)malloc(total_len);
    if (!json) {
        for (int i = 0; i < count; i++) free(lines[i]);
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }

    strcpy(json, "[");
    for (int i = 0; i < count; i++) {
        /* Remove newline if present */
        char *nl = strchr(lines[i], '\n');
        if (nl) *nl = '\0';
        
        strcat(json, lines[i]);
        if (i < count - 1) strcat(json, ",");
        free(lines[i]);
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
    for (size_t i = 0; i < count; i++) total += 2048;

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
    for (size_t i = 0; i < count; i++) total += 2048;

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

/* GET /api/v1/auth/certs — export public key for RS256 */
static sso_error_t handle_certs(sso_context_t *ctx, const http_request_t *req,
                                http_response_t *resp) {
    (void)req;
    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    if (tmgr->mode != SSO_TOKEN_MODE_RS256) {
        sso_response_error(resp, 404, "Server not in RS256 mode");
        return SSO_OK;
    }

    char *pem = token_manager_get_public_key_pem(tmgr);
    if (!pem) {
        sso_response_error(resp, 500, "Failed to export public key");
        return SSO_OK;
    }

    /* Wrap in JSON */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "public_key", pem);
    cJSON_AddStringToObject(root, "alg", "RS256");

    char *json = cJSON_PrintUnformatted(root);
    sso_response_ok(resp, json);

    free(json);
    cJSON_Delete(root);
    free(pem);
    return SSO_OK;
}

/* ========================================================================
 * Permission checks — POST handlers
 * ======================================================================== */

/* PUT /api/v1/users/:id */
static sso_error_t handle_update_user(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    sso_id_t user_id = extract_path_id(req->path, "/users/");
    if (!user_id || !req->body) {
        sso_response_error(resp, 400, "user_id and body required");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    sso_error_t err = user_get_by_id(umgr, user_id, &user);
    if (err != SSO_OK) {
        sso_response_error(resp, 404, "User not found");
        return SSO_OK;
    }

    char *email = json_str_value(req->body, "email");
    char *display = json_str_value(req->body, "display_name");
    int status = (int)json_int_value(req->body, "status", -1);

    if (email) {
        strncpy(user.email, email, SSO_MAX_EMAIL - 1);
        free(email);
    }
    if (display) {
        strncpy(user.display_name, display, SSO_MAX_DISPLAY_NAME - 1);
        free(display);
    }
    if (status >= 0) {
        user.status = (user_status_t)status;
    }

    err = user_update(umgr, &user);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"updated\":true}");
    return SSO_OK;
}

/* DELETE /api/v1/users/:id */
static sso_error_t handle_delete_user(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    (void)req;
    sso_id_t user_id = extract_path_id(req->path, "/users/");
    if (!user_id) {
        sso_response_error(resp, 400, "user_id required");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    sso_error_t err = user_delete(umgr, user_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"deleted\":true}");
    return SSO_OK;
}

/* PUT /api/v1/roles/:id */
static sso_error_t handle_update_role(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    sso_id_t role_id = extract_path_id(req->path, "/roles/");
    if (!role_id || !req->body) {
        sso_response_error(resp, 400, "role_id and body required");
        return SSO_OK;
    }

    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    role_t role;
    sso_error_t err = role_get_by_id(rmgr, role_id, &role);
    if (err != SSO_OK) {
        sso_response_error(resp, 404, "Role not found");
        return SSO_OK;
    }

    char *name = json_str_value(req->body, "name");
    char *desc = json_str_value(req->body, "description");
    sso_id_t parent = (sso_id_t)json_int_value(req->body, "parent_role_id", -1);

    if (name) {
        strncpy(role.name, name, SSO_MAX_ROLE_NAME - 1);
        free(name);
    }
    if (desc) {
        strncpy(role.description, desc, SSO_MAX_DESCRIPTION - 1);
        free(desc);
    }
    if (parent != (sso_id_t)-1) {
        role.parent_role_id = parent;
    }

    err = role_update(rmgr, &role);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"updated\":true}");
    return SSO_OK;
}

/* DELETE /api/v1/roles/:id */
static sso_error_t handle_delete_role(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    (void)req;
    sso_id_t role_id = extract_path_id(req->path, "/roles/");
    if (!role_id) {
        sso_response_error(resp, 400, "role_id required");
        return SSO_OK;
    }

    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    sso_error_t err = role_delete(rmgr, role_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"deleted\":true}");
    return SSO_OK;
}

/* POST /api/v1/roles/:id/unassign — unassign role from user/group */
static sso_error_t handle_unassign_role(sso_context_t *ctx, const http_request_t *req,
                                          http_response_t *resp) {
    sso_id_t role_id = extract_path_id(req->path, "/roles/");
    if (!role_id || !req->body) {
        sso_response_error(resp, 400, "role_id and body required");
        return SSO_OK;
    }

    sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
    sso_id_t group_id = (sso_id_t)json_int_value(req->body, "group_id", 0);

    role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
    sso_error_t err;
    if (user_id != 0) {
        err = role_unassign_from_user(rmgr, role_id, user_id);
    } else if (group_id != 0) {
        err = role_unassign_from_group(rmgr, role_id, group_id);
    } else {
        sso_response_error(resp, 400, "user_id or group_id required");
        return SSO_OK;
    }

    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"unassigned\":true}");
    return SSO_OK;
}

/* PUT /api/v1/groups/:id */
static sso_error_t handle_update_group(sso_context_t *ctx, const http_request_t *req,
                                        http_response_t *resp) {
    sso_id_t group_id = extract_path_id(req->path, "/groups/");
    if (!group_id || !req->body) {
        sso_response_error(resp, 400, "group_id and body required");
        return SSO_OK;
    }

    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;
    group_t group;
    sso_error_t err = group_get_by_id(gmgr, group_id, &group);
    if (err != SSO_OK) {
        sso_response_error(resp, 404, "Group not found");
        return SSO_OK;
    }

    char *name = json_str_value(req->body, "name");
    char *desc = json_str_value(req->body, "description");
    sso_id_t parent = (sso_id_t)json_int_value(req->body, "parent_group_id", -1);

    if (name) {
        strncpy(group.name, name, SSO_MAX_GROUP_NAME - 1);
        free(name);
    }
    if (desc) {
        strncpy(group.description, desc, SSO_MAX_DESCRIPTION - 1);
        free(desc);
    }
    if (parent != (sso_id_t)-1) {
        group.parent_group_id = parent;
    }

    err = group_update(gmgr, &group);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"updated\":true}");
    return SSO_OK;
}

/* DELETE /api/v1/groups/:id */
static sso_error_t handle_delete_group(sso_context_t *ctx, const http_request_t *req,
                                        http_response_t *resp) {
    (void)req;
    sso_id_t group_id = extract_path_id(req->path, "/groups/");
    if (!group_id) {
        sso_response_error(resp, 400, "group_id required");
        return SSO_OK;
    }

    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;
    sso_error_t err = group_delete(gmgr, group_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"deleted\":true}");
    return SSO_OK;
}

/* PUT /api/v1/policies/:id */
static sso_error_t handle_update_policy(sso_context_t *ctx, const http_request_t *req,
                                         http_response_t *resp) {
    sso_id_t policy_id = extract_path_id(req->path, "/policies/");
    if (!policy_id || !req->body) {
        sso_response_error(resp, 400, "policy_id and body required");
        return SSO_OK;
    }

    policy_manager_t *pmgr = (policy_manager_t *)ctx->policy_mgr;
    policy_t policy;
    sso_error_t err = policy_get_by_id(pmgr, policy_id, &policy);
    if (err != SSO_OK) {
        sso_response_error(resp, 404, "Policy not found");
        return SSO_OK;
    }

    char *name = json_str_value(req->body, "name");
    char *rules = json_str_value(req->body, "rules");
    int effect = (int)json_int_value(req->body, "effect", -1);
    int priority = (int)json_int_value(req->body, "priority", -1);
    int status = (int)json_int_value(req->body, "status", -1);

    if (name) {
        strncpy(policy.name, name, SSO_MAX_POLICY_NAME - 1);
        free(name);
    }
    if (rules) {
        strncpy(policy.rules, rules, SSO_MAX_RULES_JSON - 1);
        free(rules);
    }
    if (effect >= 0) policy.effect = (policy_effect_t)effect;
    if (priority >= 0) policy.priority = priority;
    if (status >= 0) policy.status = (policy_status_t)status;

    err = policy_update(pmgr, &policy);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"updated\":true}");
    return SSO_OK;
}

/* DELETE /api/v1/policies/:id */
static sso_error_t handle_delete_policy(sso_context_t *ctx, const http_request_t *req,
                                         http_response_t *resp) {
    (void)req;
    sso_id_t policy_id = extract_path_id(req->path, "/policies/");
    if (!policy_id) {
        sso_response_error(resp, 400, "policy_id required");
        return SSO_OK;
    }

    policy_manager_t *pmgr = (policy_manager_t *)ctx->policy_mgr;
    sso_error_t err = policy_delete(pmgr, policy_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"deleted\":true}");
    return SSO_OK;
}

/* POST /api/v1/policies/:id/unassign — unassign policy from target */
static sso_error_t handle_unassign_policy(sso_context_t *ctx, const http_request_t *req,
                                            http_response_t *resp) {
    sso_id_t policy_id = extract_path_id(req->path, "/policies/");
    if (!policy_id || !req->body) {
        sso_response_error(resp, 400, "policy_id and body required");
        return SSO_OK;
    }

    sso_id_t target_id = (sso_id_t)json_int_value(req->body, "target_id", 0);
    int target_type = (int)json_int_value(req->body, "target_type", -1);
    if (!target_id || target_type < 0) {
        sso_response_error(resp, 400, "target_id and target_type required");
        return SSO_OK;
    }

    policy_manager_t *pmgr = (policy_manager_t *)ctx->policy_mgr;
    sso_error_t err = policy_unassign_from(pmgr, policy_id,
        (policy_target_type_t)target_type, target_id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, sso_strerror(err));
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"unassigned\":true}");
    return SSO_OK;
}

/* GET /admin — serve the admin management page */
static sso_error_t handle_admin_page(sso_context_t *ctx, const http_request_t *req,
                                       http_response_t *resp) {
    (void)ctx;
    auth_context_t *auth = (auth_context_t *)req->userdata;
    
    /* If auth header was provided but role is not admin, reject immediately.
     * If no auth header, we serve the HTML and let JS handle the initial login redirect. */
    if (auth) {
        user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
        role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
        sso_id_t roles[16];
        size_t count = 0;
        user_get_roles(umgr, auth->user.id, roles, &count, 16);

        bool is_admin = false;
        for (size_t i = 0; i < count; i++) {
            role_t r;
            if (role_get_by_id(rmgr, roles[i], &r) == SSO_OK) {
                if (strcmp(r.name, "admin") == 0) { is_admin = true; break; }
            }
        }

        if (!is_admin) {
            sso_response_error(resp, 403, "Access denied: Admin role required");
            return SSO_OK;
        }
    }

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

    /* Determine initial admin password */
    const char *admin_password = getenv("SSO_ADMIN_PASSWORD");
    char random_pass[32];
    bool using_random = false;

    if (!admin_password || admin_password[0] == '\0') {
        /* Generate a random password if none provided */
        unsigned char rand_bytes[12];
        FILE *f = fopen("/dev/urandom", "r");
        if (f) {
            fread(rand_bytes, 1, sizeof(rand_bytes), f);
            fclose(f);
        }
        snprintf(random_pass, sizeof(random_pass), "admin-%02x%02x%02x%02x", 
                 rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3]);
        admin_password = random_pass;
        using_random = true;
    }

    /* Create admin user */
    printf("[bootstrap] Creating admin user...\n");
    if (using_random) {
        printf("\n======================================================================\n");
        printf("⚠️  WARNING: No SSO_ADMIN_PASSWORD set in environment.\n");
        printf("⚠️  Generated initial admin password: %s\n", admin_password);
        printf("⚠️  Please save this password! You can change it later via the API.\n");
        printf("======================================================================\n\n");
    }

    err = user_create(umgr, "admin", admin_password, "admin@example.com", "Admin", &admin_user);
    if (err != SSO_OK) {
        fprintf(stderr, "[bootstrap] Failed to create admin: %s\n", sso_strerror(err));
        return err;
    }
    printf("[bootstrap] admin id=%lu\n", (unsigned long)admin_user.id);

    /* Create roles */
    role_t admin_role, editor_role, viewer_role, member_role;
    err = role_create(rmgr, "admin",  "Full system access",     SSO_ID_NONE, &admin_role);
    if (err != SSO_OK) return err;
    err = role_create(rmgr, "editor", "Can edit content",       admin_role.id, &editor_role);
    if (err != SSO_OK) return err;
    err = role_create(rmgr, "viewer", "Read-only access",       editor_role.id, &viewer_role);
    if (err != SSO_OK) return err;
    err = role_create(rmgr, "user",   "Regular member",         SSO_ID_NONE, &member_role);
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

        /* Admin page — serve HTML publicly; JS handles auth/role check */
        {"/admin",                  HTTP_GET,  handle_admin_page,       false},

        /* Public — API */
        {"/metrics",                HTTP_GET,  handle_metrics,         false},
        {"/api/v1/health",          HTTP_GET,  handle_health,          false},
        {"/api/v1/auth/login",      HTTP_POST, handle_login,           false},
        {"/api/v1/auth/send_sms",   HTTP_POST, handle_send_sms,        false},
        {"/api/v1/auth/login_by_sms",HTTP_POST, handle_login_by_sms,   false},
        {"/api/v1/auth/register",   HTTP_POST, handle_register,        false},

        /* Auth required */
        {"/api/v1/auth/verify",     HTTP_POST, handle_verify,           false},
        {"/api/v1/auth/refresh",    HTTP_POST, handle_refresh,          true},
        {"/api/v1/auth/logout",     HTTP_POST, handle_logout,           true},
        {"/api/v1/auth/password",   HTTP_POST, handle_change_password,  true},
        {"/api/v1/auth/me",         HTTP_GET,  handle_me,               true},
        {"/api/v1/auth/certs",      HTTP_GET,  handle_certs,            false},
        {"/api/v1/audit/logs",      HTTP_GET,  handle_list_audit_logs,  true},

        /* Permission checks */
        {"/api/v1/check",           HTTP_POST, handle_check_permission,  true},
        {"/api/v1/check/functional",HTTP_POST, handle_check_functional,  true},
        {"/api/v1/check/api",       HTTP_POST, handle_check_api,         true},
        {"/api/v1/check/data",      HTTP_POST, handle_check_data,        true},
        {"/api/v1/check/rbac",      HTTP_POST, handle_check_rbac,        true},
        {"/api/v1/check/location",  HTTP_POST, handle_check_location,    true},
        {"/api/v1/check/lbac",      HTTP_POST, handle_check_lbac,        true},
        {"/api/v1/check/abac",      HTTP_POST, handle_check_abac,        true},

        /* Management — CRUD */
        {"/api/v1/users",           HTTP_GET,  handle_list_users,        true},
        {"/api/v1/users",           HTTP_POST, handle_create_user,       true},
        {"/api/v1/users/:id",       HTTP_GET,  handle_get_user,          true},
        {"/api/v1/users/:id",       HTTP_PUT,  handle_update_user,     true},
        {"/api/v1/users/:id",       HTTP_DELETE, handle_delete_user,     true},
        {"/api/v1/roles",           HTTP_GET,  handle_list_roles,        true},
        {"/api/v1/roles",           HTTP_POST, handle_create_role,       true},
        {"/api/v1/roles/:id",       HTTP_PUT,  handle_update_role,     true},
        {"/api/v1/roles/:id",       HTTP_DELETE, handle_delete_role,     true},
        {"/api/v1/roles/*/assign",  HTTP_POST, handle_assign_role,       true},
        {"/api/v1/roles/*/unassign",HTTP_POST, handle_unassign_role,     true},
        {"/api/v1/policies",        HTTP_GET,  handle_list_policies,     true},
        {"/api/v1/policies",        HTTP_POST, handle_create_policy,     true},
        {"/api/v1/policies/:id",    HTTP_PUT,  handle_update_policy,   true},
        {"/api/v1/policies/:id",    HTTP_DELETE, handle_delete_policy,   true},
        {"/api/v1/policies/*/assign",HTTP_POST, handle_assign_policy,    true},
        {"/api/v1/policies/*/unassign",HTTP_POST, handle_unassign_policy, true},
        {"/api/v1/groups",          HTTP_GET,  handle_list_groups,       true},
        {"/api/v1/groups",          HTTP_POST, handle_create_group,      true},
        {"/api/v1/groups/:id",      HTTP_PUT,  handle_update_group,      true},
        {"/api/v1/groups/:id",      HTTP_DELETE, handle_delete_group,    true},
        {"/api/v1/groups/*/members", HTTP_POST, handle_add_group_member,  true},
        {"/api/v1/groups/*/members/*", HTTP_DELETE, handle_remove_group_member, true},
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
    printf("  Check: POST /api/v1/check/rbac (role membership)\n");
    printf("  Check: POST /api/v1/check/location (location/geo)\n");
    printf("  Check: POST /api/v1/check/lbac (security labels)\n");
    printf("  Check: POST /api/v1/check/abac (attribute-based)\n");
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
    if (argc > 1 && strcmp(argv[1], "--interactive") == 0) {
        return interactive_config();
    }
    return run_demo();
}
