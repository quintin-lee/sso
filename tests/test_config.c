#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "config.h"
#include "sso.h"

int tests_run = 0;

static const char *test_config_defaults() {
    printf("  Running test_config_defaults...\n");
    sso_config_t cfg;
    sso_config_default(&cfg);

    ASSERT_STR_EQUAL(cfg.host, "0.0.0.0");
    ASSERT_INT_EQUAL(cfg.port, 8080);
    ASSERT_INT_EQUAL(cfg.thread_pool_size, 8);
    return 0;
}

static const char *test_config_env_override() {
    printf("  Running test_config_env_override...\n");
    sso_config_t cfg;
    sso_config_default(&cfg);

    setenv("SSO_PORT", "7070", 1);
    setenv("SSO_ADMIN_PASSWORD", "env-pass", 1);
    setenv("SSO_DATABASE_TYPE", "postgres", 1);
    setenv("SSO_DATABASE_URL", "postgres://user:pass@host/db", 1);
    
    sso_config_apply_env(&cfg);

    ASSERT_INT_EQUAL(cfg.port, 7070);
    ASSERT_STR_EQUAL(cfg.admin_password, "env-pass");
    ASSERT_STR_EQUAL(cfg.database_type, "postgres");
    ASSERT_STR_EQUAL(cfg.database_url, "postgres://user:pass@host/db");

    unsetenv("SSO_PORT");
    unsetenv("SSO_ADMIN_PASSWORD");
    unsetenv("SSO_DATABASE_TYPE");
    unsetenv("SSO_DATABASE_URL");
    return 0;
}

static const char *test_config_load_fallback() {
    printf("  Running test_config_load_fallback...\n");
    sso_config_t cfg;
    sso_config_default(&cfg);

    FILE *fp = fopen("test_fallback.toml", "w");
    if (!fp) return "Failed to create test_fallback.toml";
    fprintf(fp, "[database]\npath = \"legacy.db\"\n");
    fclose(fp);

    sso_error_t err = sso_config_load("test_fallback.toml", &cfg);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_STR_EQUAL(cfg.path, "legacy.db");
    ASSERT_STR_EQUAL(cfg.database_url, "legacy.db");

    remove("test_fallback.toml");
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_config_defaults);
    mu_run_test(test_config_env_override);
    mu_run_test(test_config_load_fallback);
    return 0;
}

int main(void) {
    const char *result = all_tests();
    if (result != 0) {
        printf("FAILED\n");
    }
    else {
        printf("ALL TESTS PASSED\n");
    }
    printf("Tests run: %d\n", tests_run);

    return result != 0;
}
