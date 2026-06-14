#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "sso.h"

static void test_config_defaults(void **state) {
    (void)state;
    sso_config_t cfg;
    sso_config_default(&cfg);

    assert_string_equal(cfg.host, "0.0.0.0");
    assert_int_equal(cfg.port, 8080);
    assert_int_equal(cfg.thread_pool_size, 8);
    assert_int_equal(cfg.token_ttl_ms, 3600000);
}

static void test_config_load_toml(void **state) {
    (void)state;
    const char *toml_content = 
        "[server]\n"
        "port = 9090\n"
        "host = \"127.0.0.1\"\n"
        "[security]\n"
        "token_secret = \"test-secret-key-12345678901234567890\"\n";
    
    FILE *fp = fopen("test_config.toml", "w");
    fputs(toml_content, fp);
    fclose(fp);

    sso_config_t cfg;
    sso_config_default(&cfg);
    sso_error_t err = sso_config_load("test_config.toml", &cfg);
    
    assert_int_equal(err, SSO_OK);
    assert_int_equal(cfg.port, 9090);
    assert_string_equal(cfg.host, "127.0.0.1");
    assert_string_equal(cfg.token_secret, "test-secret-key-12345678901234567890");

    remove("test_config.toml");
}

static void test_config_env_override(void **state) {
    (void)state;
    sso_config_t cfg;
    sso_config_default(&cfg);

    setenv("SSO_PORT", "7070", 1);
    setenv("SSO_ADMIN_PASSWORD", "env-pass", 1);
    
    sso_config_apply_env(&cfg);

    assert_int_equal(cfg.port, 7070);
    assert_string_equal(cfg.admin_password, "env-pass");

    unsetenv("SSO_PORT");
    unsetenv("SSO_ADMIN_PASSWORD");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_defaults),
        cmocka_unit_test(test_config_load_toml),
        cmocka_unit_test(test_config_env_override),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
