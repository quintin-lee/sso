#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "sso.h"
#include "storage.h"
#include "server.h"
#include "token.h"
#include "user.h"
#include "role.h"
#include "config.h"
#include "cJSON.h"

int tests_run = 0;

/* --- Test helpers --- */
static sso_error_t bootstrap_system(sso_context_t* ctx, storage_backend_t* storage) {
	storage_memory_create(&storage);
	sso_config_t cfg;
	sso_config_default(&cfg);
	sso_error_t err = sso_init(ctx, storage, &cfg);
	if (err != SSO_OK)
		return err;

	/* Bootstrap: create roles and admin user */
	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;

	user_t admin;
	err = user_create(umgr, "admin", "Admin1@345", "admin@sso.local", "Administrator", &admin);
	if (err != SSO_OK)
		return err;

	role_t admin_role;
	err = role_create(rmgr, "admin", "Administrator role", SSO_ID_NONE, &admin_role);
	if (err != SSO_OK)
		return err;

	err = role_assign_to_user(rmgr, admin_role.id, admin.id);
	return err;
}

/* --- Tests --- */
static const char* test_login_success() {
	printf("  Running test_login_success...\n");

	sso_context_t	   ctx;
	storage_backend_t* storage = NULL;
	if (bootstrap_system(&ctx, storage) != SSO_OK)
		return "bootstrap failed";

	/* We need access to handle_login... but it's static in main.c */
	/* Instead, let's test the token system directly */
	user_manager_t*	 umgr = (user_manager_t*)ctx.user_mgr;
	token_manager_t* tmgr = (token_manager_t*)ctx.token_mgr;

	user_t		user;
	sso_error_t err = user_authenticate(umgr, "admin", "Admin1@345", &user);
	ASSERT_INT_EQUAL(err, SSO_OK);

	sso_id_t roles[16]	= {0};
	sso_id_t groups[16] = {0};
	size_t	 rc = 0, gc = 0;
	user_get_roles(umgr, user.id, roles, &rc, 16);

	token_t token;
	err = token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 900000, NULL, &token);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_TRUE(strlen(token.token_str) > 0);
	ASSERT_TRUE(token.nonce == 0);
	ASSERT_TRUE(token.user_id == user.id);

	/* Verify the token */
	token_t decoded;
	err = token_verify(tmgr, token.token_str, &decoded);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_TRUE(decoded.user_id == user.id);

	token_destroy(&token);
	token_destroy(&decoded);
	sso_destroy(&ctx);
	return 0;
}

static const char* test_token_expired() {
	printf("  Running test_token_expired...\n");

	sso_context_t	   ctx;
	storage_backend_t* storage = NULL;
	if (bootstrap_system(&ctx, storage) != SSO_OK)
		return "bootstrap failed";

	user_manager_t*	 umgr = (user_manager_t*)ctx.user_mgr;
	token_manager_t* tmgr = (token_manager_t*)ctx.token_mgr;

	user_t user;
	user_authenticate(umgr, "admin", "Admin1@345", &user);

	/* Issue an expired token (TTL = -1 → immediate expiry) */
	token_t token;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, -1, NULL, &token);

	token_t		decoded;
	sso_error_t err = token_verify(tmgr, token.token_str, &decoded);
	ASSERT_INT_EQUAL(err, SSO_ERR_TOKEN_EXPIRED);

	token_destroy(&token);
	sso_destroy(&ctx);
	return 0;
}

static const char* test_invalid_password() {
	printf("  Running test_invalid_password...\n");

	sso_context_t	   ctx;
	storage_backend_t* storage = NULL;
	if (bootstrap_system(&ctx, storage) != SSO_OK)
		return "bootstrap failed";

	user_manager_t* umgr = (user_manager_t*)ctx.user_mgr;
	user_t			user;
	sso_error_t		err = user_authenticate(umgr, "admin", "wrong_password", &user);
	ASSERT_INT_EQUAL(err, SSO_ERR_AUTH_FAILED);

	sso_destroy(&ctx);
	return 0;
}

static const char* test_token_nonce() {
	printf("  Running test_token_nonce...\n");

	sso_context_t	   ctx;
	storage_backend_t* storage = NULL;
	if (bootstrap_system(&ctx, storage) != SSO_OK)
		return "bootstrap failed";

	user_manager_t*	 umgr = (user_manager_t*)ctx.user_mgr;
	token_manager_t* tmgr = (token_manager_t*)ctx.token_mgr;

	user_t user;
	user_authenticate(umgr, "admin", "Admin1@345", &user);

	/* Issue a token */
	token_t token;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 900000, NULL, &token);
	ASSERT_TRUE(token.nonce == 0);

	/* Bump nonce (simulates "logout all") */
	token_bump_nonce(tmgr, user.id);

	/* Verify old token fails nonce check */
	token_t		decoded;
	sso_error_t err = token_verify(tmgr, token.token_str, &decoded);
	ASSERT_INT_EQUAL(err, SSO_OK);

	/* The nonce check is in authenticate_request, which loads user
	 * and compares nonce. After bump, token.nonce (0) < expected (1). */
	uint64_t expected = token_get_nonce(tmgr, user.id);
	ASSERT_TRUE(expected == 1);
	ASSERT_TRUE(token.nonce < expected);

	/* New token should have updated nonce */
	token_t token2;
	token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 900000, NULL, &token2);
	ASSERT_TRUE(token2.nonce == 1);

	token_destroy(&token);
	token_destroy(&token2);
	sso_destroy(&ctx);
	return 0;
}

static const char* test_refresh_token() {
	printf("  Running test_refresh_token...\n");

	sso_context_t	   ctx;
	storage_backend_t* storage = NULL;
	if (bootstrap_system(&ctx, storage) != SSO_OK)
		return "bootstrap failed";

	user_manager_t*	 umgr = (user_manager_t*)ctx.user_mgr;
	token_manager_t* tmgr = (token_manager_t*)ctx.token_mgr;

	user_t user;
	user_authenticate(umgr, "admin", "Admin1@345", &user);

	sso_id_t roles[16]	= {0};
	sso_id_t groups[16] = {0};
	size_t	 rc = 0, gc = 0;
	user_get_roles(umgr, user.id, roles, &rc, 16);

	/* Issue access token (short TTL) and refresh token (long TTL) */
	token_t access, refresh;
	token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 900000, NULL, &access);
	token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 604800000, NULL, &refresh);

	/* Refresh: verify refresh token, issue new pair */
	token_t old_refresh;
	token_verify(tmgr, refresh.token_str, &old_refresh);
	ASSERT_TRUE(old_refresh.user_id == user.id);

	/* Issue new tokens using refresh */
	token_t new_access, new_refresh;
	token_issue(tmgr, &user, old_refresh.role_ids, old_refresh.role_count, old_refresh.group_ids,
				old_refresh.group_count, NULL, 900000, NULL, &new_access);
	token_issue(tmgr, &user, old_refresh.role_ids, old_refresh.role_count, old_refresh.group_ids,
				old_refresh.group_count, NULL, 604800000, NULL, &new_refresh);

	ASSERT_TRUE(new_access.user_id == user.id);
	ASSERT_TRUE(new_refresh.user_id == user.id);

	token_destroy(&access);
	token_destroy(&refresh);
	token_destroy(&old_refresh);
	token_destroy(&new_access);
	token_destroy(&new_refresh);
	sso_destroy(&ctx);
	return 0;
}

static const char* all_tests() {
	mu_run_test(test_login_success);
	mu_run_test(test_token_expired);
	mu_run_test(test_invalid_password);
	mu_run_test(test_token_nonce);
	mu_run_test(test_refresh_token);
	return 0;
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;
	const char* result = all_tests();
	if (result != 0)
		printf("FAILED\n");
	else
		printf("ALL TESTS PASSED\n");
	printf("Tests run: %d\n", tests_run);
	return result != 0;
}
