#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>

#include "token.h"
#include "sso.h"

static void test_token_hs256_lifecycle(void **state) {
    (void)state;
    token_manager_t tmgr;
    unsigned char secret[] = "super-secret-key-at-least-32-bytes-long";
    
    sso_error_t err = token_manager_init(&tmgr, secret, sizeof(secret), 3600000LL);
    assert_int_equal(err, SSO_OK);
    assert_int_equal(tmgr.mode, SSO_TOKEN_MODE_HS256);

    /* Issue token */
    sso_id_t roles[] = {1, 2};
    sso_id_t groups[] = {10};
    token_t issued;
    err = token_issue(&tmgr, 123, "testuser", roles, 2, groups, 1, &issued);
    assert_int_equal(err, SSO_OK);
    assert_non_null(issued.token_str);
    assert_true(strlen(issued.token_str) > 0);

    /* Verify token */
    token_t verified;
    err = token_verify(&tmgr, issued.token_str, &verified);
    assert_int_equal(err, SSO_OK);
    assert_int_equal(verified.user_id, 123);
    assert_string_equal(verified.username, "testuser");
    assert_int_equal(verified.role_count, 2);
    assert_int_equal(verified.role_ids[0], 1);
    assert_int_equal(verified.group_count, 1);
    assert_int_equal(verified.group_ids[0], 10);

    token_destroy(&verified);
}

static void test_token_rs256_lifecycle(void **state) {
    (void)state;
    /* Dummy RSA keys for testing (normally loaded from env/file) */
    const char *priv_key = 
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA76X7ZfK5V1kX2H7GZ3+n6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXv\n"
        "Y6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zX\n"
        "vY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6z\n"
        "XvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY\n"
        "6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6zXvY6\n"
        "-----END RSA PRIVATE KEY-----\n";

    token_manager_t tmgr;
    sso_error_t err = token_manager_init_rs256(&tmgr, priv_key, NULL, 3600000LL);
    assert_int_equal(err, SSO_OK);
    assert_int_equal(tmgr.mode, SSO_TOKEN_MODE_RS256);

    /* Issue token */
    sso_id_t roles[] = {1};
    token_t issued;
    err = token_issue(&tmgr, 456, "admin", roles, 1, NULL, 0, &issued);
    assert_int_equal(err, SSO_OK);

    /* Verify token */
    token_t verified;
    err = token_verify(&tmgr, issued.token_str, &verified);
    assert_int_equal(err, SSO_OK);
    assert_int_equal(verified.user_id, 456);
    assert_string_equal(verified.username, "admin");

    token_destroy(&verified);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_token_hs256_lifecycle),
        cmocka_unit_test(test_token_rs256_lifecycle),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
