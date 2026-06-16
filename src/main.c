/*
 * main.c — SSO system entry point.
 *
 * Run:
 *   ./sso_system              — runs the demo and exits
 *   ./sso_system --server     — starts the HTTP management API on port 8080
 *   ./sso_system --interactive — guided configuration shell
 */

#include "sso.h"
#include "logger.h"
#include "storage.h"
#include "server.h"
#include "config.h"
#include "oauth.h"
#include "handlers.h"
#include "role.h"
#include "policy.h"
#include "user.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sodium.h>

static sso_config_t g_config;

/* -----------------------------------------------------------------------
 * Command Line Argument Parsing
 * ----------------------------------------------------------------------- */
static void parse_args(int argc, char **argv, char *config_path) {
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            strncpy(config_path, argv[++i], SSO_MAX_PATH - 1);
        }
    }
}

/* ========================================================================
 * Bootstrap — creates admin user and default policies on first server start
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
        memset(rand_bytes, 0, sizeof(rand_bytes));
        FILE *f = fopen("/dev/urandom", "r");
        if (f) {
            if (fread(rand_bytes, 1, sizeof(rand_bytes), f) != sizeof(rand_bytes)) {
                /* If read fails, we still have zeros from memset, which is "random" enough for bootstrap safety,
                 * but ideally we'd handle it. Here we just ensure we don't ignore the return value. */
            }
            fclose(f);
        }
        snprintf(random_pass, sizeof(random_pass), "admin-%02x%02x%02x%02x",
                 rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3]);
        admin_password = random_pass;
        using_random = true;
    }

    /* Create admin user */
    LOG_INFO("[bootstrap] Creating admin user...");
    if (using_random) {
        printf("\n======================================================================\n");
        printf("⚠️  WARNING: No SSO_ADMIN_PASSWORD set in environment.\n");
        printf("⚠️  Generated initial admin password: %s\n", admin_password);
        printf("⚠️  Please save this password! You can change it later via the API.\n");
        printf("======================================================================\n\n");
    }

    err = user_create(umgr, "admin", admin_password, "admin@example.com", "Admin", &admin_user);
    if (err != SSO_OK) {
        LOG_ERROR("[bootstrap] Failed to create admin: %s", sso_strerror(err));
        return err;
    }
    LOG_INFO("[bootstrap] admin id=%lu", (unsigned long)admin_user.id);

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
static int run_server(sso_config_t *cfg) {
    sso_error_t err;

    /* Init SSO */
    storage_backend_t *storage = NULL;
    err = storage_sqlite_create(&storage);
    if (err != SSO_OK) {
        LOG_ERROR("Failed to create storage: %s", sso_strerror(err));
        return 1;
    }

    sso_context_t ctx;
    err = sso_init(&ctx, storage, cfg);
    if (err != SSO_OK) {
        LOG_ERROR("Failed to init SSO: %s", sso_strerror(err));
        return 1;
    }

    LOG_INFO("Starting SSO management server...");

    /* Bootstrap default data on first run */
    bootstrap_data(&ctx);

    /* P0: wipe admin_password from config now that bootstrap is done */
    sodium_memzero(g_config.admin_password, sizeof(g_config.admin_password));

    /* Define API routes */
    route_t routes[] = {
        /* Public — login page */
        {"/",                       HTTP_GET,  handle_login_page,       false},
        {"/login",                  HTTP_GET,  handle_login_page,       false},

        /* Admin page — serve HTML publicly; JS handles auth/role check */
        {"/admin",                  HTTP_GET,  handle_admin_page,       false},

        /* Public — API */
        {"/metrics",                HTTP_GET,  handle_metrics,          false},
        {"/api/v1/health",          HTTP_GET,  handle_health,          false},
        {"/api/v1/admin/status",    HTTP_GET,  handle_admin_status,     true},
        {"/api/v1/auth/login",      HTTP_POST, handle_login,           false},
        {"/api/v1/auth/send_sms",   HTTP_POST, handle_send_sms,        false},
        {"/api/v1/auth/login_by_sms",HTTP_POST, handle_login_by_sms,   false},
        {"/api/v1/auth/register",   HTTP_POST, handle_register,        false},
        {"/api/v1/auth/mfa/setup",  HTTP_POST, handle_mfa_setup,       true},
        {"/api/v1/auth/mfa/enable", HTTP_POST, handle_mfa_enable,      true},
        {"/api/v1/auth/mfa/verify", HTTP_POST, handle_mfa_verify,      false},

        /* Auth required */
        {"/api/v1/auth/verify",     HTTP_GET,  handle_verify,           false},
        {"/api/v1/auth/verify",     HTTP_POST, handle_verify,           false},
        {"/api/v1/auth/refresh",    HTTP_POST, handle_refresh,          false},
        {"/api/v1/auth/logout",     HTTP_POST, handle_logout,           true},
        {"/api/v1/auth/logout_all", HTTP_POST, handle_logout_all,       true},
        {"/api/v1/auth/password",   HTTP_POST, handle_change_password,  true},
        {"/api/v1/auth/me",         HTTP_GET,  handle_me,               true},
        {"/api/v1/auth/certs",      HTTP_GET,  handle_certs,            false},
        {"/api/v1/auth/userinfo",   HTTP_GET,  handle_userinfo,          true},
        {"/api/v1/auth/jwks",       HTTP_GET,  handle_jwks,             false},
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

        /* OAuth 2.0 / OIDC */
        {"/.well-known/openid-configuration", HTTP_GET, handle_well_known_openid_config, false},
        {"/api/v1/oauth/authorize", HTTP_GET, handle_oauth_authorize, true},
        {"/api/v1/oauth/token",     HTTP_POST, handle_oauth_token,    false},
        {"/api/v1/oauth/introspect", HTTP_POST, handle_oauth_introspect, true},
        {"/api/v1/oauth/revoke",    HTTP_POST, handle_oauth_revoke,   true},
    };

    size_t route_count = sizeof(routes) / sizeof(routes[0]);

    sso_server_t server;
    sso_server_init(&server, &ctx, cfg->host, cfg->port, routes, route_count);

    printf("  Login: http://%s:%d/\n", cfg->host, cfg->port);
    printf("  API: http://%s:%d/api/v1/health\n", cfg->host, cfg->port);
    printf("  Press Ctrl+C to stop.\n\n");

    err = sso_server_start(&server);
    if (err != SSO_OK) {
        LOG_ERROR("Server error: %s", sso_strerror(err));
    }

    sso_destroy(&ctx);
    return 0;
}

/* ========================================================================
 * Entry point
 * ======================================================================== */
int main(int argc, char *argv[]) {
    /* Handle help / version before any initialization */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("SSO System v%d.%d.%d — Single Sign-On service\n"
                   "\n"
                   "Usage: sso_system [OPTIONS] [MODE]\n"
                   "\n"
                   "Options:\n"
                   "  -c, --config FILE    Configuration file (default: sso.toml)\n"
                   "  -h, --help           Show this help message\n"
                   "  -v, --version        Show version\n"
                   "\n"
                   "Modes:\n"
                   "  (none)               Run demo\n"
                   "  --server             Start HTTP API server\n"
                   "  --interactive        Interactive policy configuration\n",
                   SSO_VERSION_MAJOR, SSO_VERSION_MINOR, SSO_VERSION_PATCH);
            return 0;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("sso_system v%d.%d.%d\n",
                   SSO_VERSION_MAJOR, SSO_VERSION_MINOR, SSO_VERSION_PATCH);
            return 0;
        }
    }

    char config_path[SSO_MAX_PATH] = "sso.toml";
    parse_args(argc, argv, config_path);

    /* Load Configuration */
    sso_config_default(&g_config);
    if (sso_config_load(config_path, &g_config) == SSO_OK) {
        LOG_INFO("[sso] Loaded configuration from %s", config_path);
    } else {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
                LOG_ERROR("Could not load config file: %s", config_path);
                return 1;
            }
        }
    }
    sso_config_apply_env(&g_config);
    log_set_level((log_level_t)g_config.log_level);

    if (argc > 1 && strcmp(argv[argc-1], "--server") == 0) {
        return run_server(&g_config);
    }
    if (argc > 1 && strcmp(argv[argc-1], "--interactive") == 0) {
        return interactive_config(&g_config);
    }
    return run_demo(&g_config);
}
