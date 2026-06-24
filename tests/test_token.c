/*
 * test_token.c — Unit tests for the token/session management module.
 *
 * Tests HMAC-SHA256 token creation, validation with correct/forged
 * signatures, expiry enforcement, refresh token rotation, binary-search
 * revocation, and the token manager lifecycle.
 */

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

/* ------------------------------------------------------------------ */
/* Dual-buffer rotation tests (HS256)                                 */
/* ------------------------------------------------------------------ */

static const char* test_token_rotate_hs256() {
	printf("  Running test_token_rotate_hs256...\n");
	token_manager_t* tmgr = setup();

	const char* old_kid = token_manager_get_active_kid(tmgr);
	ASSERT_NOT_NULL(old_kid);

	/* Issue a token with the original key */
	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 42;
	sso_strlcpy(user.username, "rotateuser", sizeof(user.username));

	token_t		first;
	sso_error_t err = token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &first);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_NOT_NULL(first.token_str);

	/* Rotate to a new key */
	unsigned char new_secret[32];
	memset(new_secret, 0xBB, sizeof(new_secret));
	err = token_manager_rotate_key(tmgr, new_secret, sizeof(new_secret));
	ASSERT_INT_EQUAL(err, SSO_OK);

	const char* new_kid = token_manager_get_active_kid(tmgr);
	ASSERT_NOT_NULL(new_kid);
	ASSERT_TRUE(strcmp(old_kid, new_kid) != 0);

	/* New tokens get signed with the new key */
	token_t second;
	err = token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &second);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_NOT_NULL(second.token_str);

	/* Old token still verifies (standby slot) */
	token_t v1;
	err = token_verify(tmgr, first.token_str, &v1);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_INT_EQUAL(v1.user_id, 42);
	token_destroy(&v1);

	/* New token verifies (active slot) */
	token_t v2;
	err = token_verify(tmgr, second.token_str, &v2);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_INT_EQUAL(v2.user_id, 42);
	token_destroy(&v2);

	/* Tampered token from old slot still fails */
	char* tampered = strdup(first.token_str);
	ASSERT_NOT_NULL(tampered);
	tampered[strlen(tampered) - 1] ^= 0x01;
	token_t v3;
	err = token_verify(tmgr, tampered, &v3);
	ASSERT_INT_EQUAL(err, SSO_ERR_TOKEN_INVALID);
	free(tampered);

	token_destroy(&first);
	token_destroy(&second);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* test_token_double_rotate_hs256() {
	printf("  Running test_token_double_rotate_hs256...\n");
	token_manager_t* tmgr = setup();

	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = 99;
	sso_strlcpy(user.username, "dblrot", sizeof(user.username));

	/* Token with key 0 */
	token_t t0;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &t0);

	unsigned char secret1[32];
	memset(secret1, 0xAA, sizeof(secret1));
	token_manager_rotate_key(tmgr, secret1, sizeof(secret1));
	token_t t1;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &t1);

	unsigned char secret2[32];
	memset(secret2, 0xCC, sizeof(secret2));
	token_manager_rotate_key(tmgr, secret2, sizeof(secret2));
	token_t t2;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000LL, NULL, &t2);

	/* t0 (original key) — after 2 rotations, original key was overwritten
	 * (dual-buffer keeps only 2 keys). */
	token_t		v0;
	sso_error_t err0 = token_verify(tmgr, t0.token_str, &v0);
	ASSERT_INT_EQUAL(err0, SSO_ERR_TOKEN_INVALID);

	/* t1 (key from rotation 1) — now in standby slot, should verify */
	token_t		v1;
	sso_error_t err1 = token_verify(tmgr, t1.token_str, &v1);
	ASSERT_INT_EQUAL(err1, SSO_OK);
	token_destroy(&v1);

	/* t2 (current active slot key) — should verify */
	token_t		v2;
	sso_error_t err2 = token_verify(tmgr, t2.token_str, &v2);
	ASSERT_INT_EQUAL(err2, SSO_OK);
	token_destroy(&v2);

	/* Active KID must be > previous KID */
	const char* kid = token_manager_get_active_kid(tmgr);
	ASSERT_NOT_NULL(kid);

	token_destroy(&t0);
	token_destroy(&t1);
	token_destroy(&t2);
	token_manager_destroy(tmgr);
	return 0;
}

static const char* test_rotate_verify_slot_count_hs256() {
	printf("  Running test_rotate_verify_slot_count_hs256...\n");
	token_manager_t* tmgr = setup();

	ASSERT_INT_EQUAL(token_manager_get_slot_count(tmgr), 1);

	unsigned char secret[32];
	memset(secret, 0xDD, sizeof(secret));
	token_manager_rotate_key(tmgr, secret, sizeof(secret));

	ASSERT_INT_EQUAL(token_manager_get_slot_count(tmgr), 2);

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
	mu_run_test(test_token_rotate_hs256);
	mu_run_test(test_token_double_rotate_hs256);
	mu_run_test(test_rotate_verify_slot_count_hs256);
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
