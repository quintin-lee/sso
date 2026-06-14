#include <stdio.h>
#include <string.h>
#include "minunit.h"
#include "server.h"
#include "sso.h"

int tests_run = 0;

static const char *test_match_exact() {
    printf("  Running test_match_exact...\n");
    ASSERT_TRUE(match_route("/api/v1/users", "/api/v1/users", NULL));
    ASSERT_TRUE(match_route("/", "/", NULL));
    ASSERT_TRUE(match_route("/a/b/c", "/a/b/c", NULL));
    return 0;
}

static const char *test_match_no_match() {
    printf("  Running test_match_no_match...\n");
    ASSERT_TRUE(!match_route("/api/v1/users", "/api/v1/roles", NULL));
    ASSERT_TRUE(!match_route("/api/v1/users", "/api/v1/users/123", NULL));
    ASSERT_TRUE(!match_route("/api/v1/users/:id", "/api/v1/users", NULL));
    return 0;
}

static const char *test_match_wildcard_end() {
    printf("  Running test_match_wildcard_end...\n");
    ASSERT_TRUE(match_route("/api/v1/users/*", "/api/v1/users/123", NULL));
    ASSERT_TRUE(match_route("/api/v1/users/*", "/api/v1/users/abc/def", NULL));
    return 0;
}

static const char *test_match_wildcard_mid() {
    printf("  Running test_match_wildcard_mid...\n");
    ASSERT_TRUE(match_route("/api/v1/roles/*/assign", "/api/v1/roles/5/assign", NULL));
    ASSERT_TRUE(match_route("/api/v1/roles/*/members", "/api/v1/roles/abc/members", NULL));
    ASSERT_TRUE(!match_route("/api/v1/roles/*/assign", "/api/v1/roles/5/revoke", NULL));
    return 0;
}

static const char *test_match_param_segment() {
    printf("  Running test_match_param_segment...\n");
    ASSERT_TRUE(match_route("/api/v1/users/:id", "/api/v1/users/42", NULL));
    ASSERT_TRUE(match_route("/api/v1/users/:id", "/api/v1/users/abc", NULL));
    return 0;
}

static const char *test_match_trailing_slash() {
    printf("  Running test_match_trailing_slash...\n");
    ASSERT_TRUE(match_route("/api/v1/users", "/api/v1/users/", NULL));
    ASSERT_TRUE(match_route("/api/v1/users/", "/api/v1/users", NULL));
    return 0;
}

static const char *test_match_null_inputs() {
    printf("  Running test_match_null_inputs...\n");
    ASSERT_TRUE(!match_route(NULL, "/api/v1/users", NULL));
    ASSERT_TRUE(!match_route("/api/v1/users", NULL, NULL));
    ASSERT_TRUE(!match_route(NULL, NULL, NULL));
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_match_exact);
    mu_run_test(test_match_no_match);
    mu_run_test(test_match_wildcard_end);
    mu_run_test(test_match_wildcard_mid);
    mu_run_test(test_match_param_segment);
    mu_run_test(test_match_trailing_slash);
    mu_run_test(test_match_null_inputs);
    return 0;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    const char *result = all_tests();
    if (result != 0) printf("FAILED\n");
    else printf("ALL TESTS PASSED\n");
    printf("Tests run: %d\n", tests_run);
    return result != 0;
}
