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
    
    sso_config_apply_env(&cfg);

    ASSERT_INT_EQUAL(cfg.port, 7070);
    ASSERT_STR_EQUAL(cfg.admin_password, "env-pass");

    unsetenv("SSO_PORT");
    unsetenv("SSO_ADMIN_PASSWORD");
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_config_defaults);
    mu_run_test(test_config_env_override);
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
