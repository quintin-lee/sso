#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "minunit.h"
#include "token.h"
#include "user.h"
#include "sso.h"

int tests_run = 0;

static const char *test_token_hs256_lifecycle() {
    printf("  Running test_token_hs256_lifecycle...\n");
    token_manager_t tmgr;
    unsigned char secret[] = "super-secret-key-at-least-32-bytes-long";
    
    sso_error_t err = token_manager_init(&tmgr, secret, sizeof(secret), 3600000LL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(tmgr.mode, SSO_TOKEN_MODE_HS256);

    /* Setup mock user */
    user_t user;
    memset(&user, 0, sizeof(user));
    user.id = 123;
    strcpy(user.username, "testuser");

    /* Issue token */
    sso_id_t roles[] = {1, 2};
    sso_id_t groups[] = {10};
    token_t issued;
    err = token_issue(&tmgr, &user, roles, 2, groups, 1, 3600000LL, &issued);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_NOT_NULL(issued.token_str);

    /* Verify token */
    token_t verified;
    err = token_verify(&tmgr, issued.token_str, &verified);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(verified.user_id, 123);
    ASSERT_INT_EQUAL(verified.role_count, 2);
    ASSERT_INT_EQUAL(verified.role_ids[0], 1);
    ASSERT_INT_EQUAL(verified.group_count, 1);
    ASSERT_INT_EQUAL(verified.group_ids[0], 10);

    token_destroy(&verified);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_token_hs256_lifecycle);
    return 0;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
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
