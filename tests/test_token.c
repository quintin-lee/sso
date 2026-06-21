#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "minunit.h"
#include "token.h"
#include "user.h"
#include "sso.h"

int tests_run = 0;

static token_manager_t* setup(void) {
	token_manager_t* tmgr	  = (token_manager_t*)calloc(1, sizeof(token_manager_t));
	unsigned char	 secret[] = "super-secret-key-at-least-32-bytes-long";
	token_manager_init(tmgr, secret, sizeof(secret), 3600000LL);
	return tmgr;
}

static const char* test_token_hs256_lifecycle() {
	printf("  Running test_token_hs256_lifecycle...\n");
	token_manager_t* tmgr = setup();

	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 123;
	strcpy(user.username, "testuser");

	sso_id_t	roles[]	 = {1, 2};
	sso_id_t	groups[] = {10};
	token_t		issued;
	sso_error_t err = token_issue(tmgr, &user, roles, 2, groups, 1, NULL, 3600000LL, NULL, &issued);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_NOT_NULL(issued.token_str);

	token_t verified;
	err = token_verify(tmgr, issued.token_str, &verified);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_INT_EQUAL(verified.user_id, 123);
	ASSERT_INT_EQUAL(verified.role_count, 2);
	ASSERT_INT_EQUAL(verified.role_ids[0], 1);
	ASSERT_INT_EQUAL(verified.group_count, 1);
	ASSERT_INT_EQUAL(verified.group_ids[0], 10);

	token_destroy(&verified);
	token_destroy(&issued);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* test_refresh_token_generation() {
	printf("  Running test_refresh_token_generation...\n");
	token_manager_t* tmgr = setup();

	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 123;
	strcpy(user.username, "testuser");

	token_t		issued;
	sso_error_t err = token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &issued);
	ASSERT_INT_EQUAL(err, SSO_OK);

	/* Verify refresh token is generated and not empty */
	ASSERT_TRUE(strlen(issued.raw_refresh_token) > 0);

	/* It should be a base64url string, so roughly 43 chars for 32 bytes */
	ASSERT_TRUE(strlen(issued.raw_refresh_token) >= 42);

	token_destroy(&issued);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* test_token_expired() {
	printf("  Running test_token_expired...\n");
	token_manager_t* tmgr = setup();

	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 456;
	strcpy(user.username, "expireduser");

	token_t		issued;
	sso_error_t err = token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, -1000LL, NULL, &issued);
	ASSERT_INT_EQUAL(err, SSO_OK);

	token_t verified;
	err = token_verify(tmgr, issued.token_str, &verified);
	ASSERT_INT_EQUAL(err, SSO_ERR_TOKEN_EXPIRED);

	token_destroy(&issued);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* test_token_tampered() {
	printf("  Running test_token_tampered...\n");
	token_manager_t* tmgr = setup();

	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 789;
	strcpy(user.username, "tamperuser");

	token_t issued;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &issued);

	char* tampered = strdup(issued.token_str);
	if (!tampered) {
		token_manager_destroy(tmgr);
		return "OOM strdup";
	}
	tampered[strlen(tampered) - 1] ^= 0x01;

	token_t		verified;
	sso_error_t err = token_verify(tmgr, tampered, &verified);
	ASSERT_INT_EQUAL(err, SSO_ERR_TOKEN_INVALID);

	free(tampered);
	token_destroy(&issued);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* test_token_revoked() {
	printf("  Running test_token_revoked...\n");
	token_manager_t* tmgr = setup();

	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 111;
	strcpy(user.username, "revokeuser");

	token_t issued;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &issued);

	token_revoke(tmgr, issued.jti, issued.expires_at);
	ASSERT_TRUE(token_is_revoked(tmgr, issued.jti));

	token_destroy(&issued);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* test_token_empty_payload() {
	printf("  Running test_token_empty_payload...\n");
	token_manager_t* tmgr = setup();

	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 222;
	strcpy(user.username, "emptyuser");

	token_t		issued;
	sso_error_t err = token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &issued);
	ASSERT_INT_EQUAL(err, SSO_OK);

	token_t verified;
	err = token_verify(tmgr, issued.token_str, &verified);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_INT_EQUAL(verified.role_count, 0);
	ASSERT_INT_EQUAL(verified.group_count, 0);

	token_destroy(&verified);
	token_destroy(&issued);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* all_tests() {
	mu_run_test(test_token_hs256_lifecycle);
	mu_run_test(test_refresh_token_generation);
	mu_run_test(test_token_expired);
	mu_run_test(test_token_tampered);
	mu_run_test(test_token_revoked);
	mu_run_test(test_token_empty_payload);
	return 0;
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;
	const char* result = all_tests();
	if (result != 0) {
		printf("FAILED\n");
	} else {
		printf("ALL TESTS PASSED\n");
	}
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}
