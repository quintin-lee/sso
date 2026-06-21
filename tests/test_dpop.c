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
#include "handlers.h"

int tests_run = 0;

static sso_error_t bootstrap_system(sso_context_t* ctx, storage_backend_t* storage) {
	storage_memory_create(&storage);
	sso_config_t cfg;
	sso_config_default(&cfg);
	sso_error_t err = sso_init(ctx, storage, &cfg);
	if (err != SSO_OK)
		return err;

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

static const char* test_dpop_enforcement() {
	printf("  Running test_dpop_enforcement...\n");

	sso_context_t	   ctx;
	storage_backend_t* storage = NULL;
	if (bootstrap_system(&ctx, storage) != SSO_OK)
		return "bootstrap failed";

	user_manager_t*	 umgr = (user_manager_t*)ctx.user_mgr;
	token_manager_t* tmgr = (token_manager_t*)ctx.token_mgr;

	user_t		user;
	sso_error_t err = user_authenticate(umgr, "admin", "Admin1@345", &user);
	ASSERT_INT_EQUAL(err, SSO_OK);

	/* 1. Issue a token bound to a specific JKT */
	const char* fake_jkt = "a1b2c3d4e5f6g7h8i9j0";
	token_t		bound_token;
	err = token_issue(tmgr, &user, NULL, 0, NULL, 0, NULL, 3600000, fake_jkt, &bound_token);
	ASSERT_INT_EQUAL(err, SSO_OK);
	ASSERT_TRUE(strcmp(bound_token.jkt, fake_jkt) == 0);

	sso_server_t fake_server;
	memset(&fake_server, 0, sizeof(fake_server));
	fake_server.sso_ctx = &ctx;

	/* 2. Setup an incoming HTTP request WITH the bound token but NO DPoP proof */
	http_request_t req;
	memset(&req, 0, sizeof(req));
	sso_strlcpy(req.auth_token, bound_token.token_str, sizeof(req.auth_token));
	sso_strlcpy(req.method_str, "GET", sizeof(req.method_str));
	sso_strlcpy(req.path, "/api/v1/users", sizeof(req.path));

	user_t	resolved_user;
	token_t resolved_token;

	/* The gateway should REJECT it because it's bound to a JKT but no proof is present */
	err = authenticate_request(fake_server.sso_ctx, &req, &resolved_user, &resolved_token);
	ASSERT_INT_EQUAL(err, SSO_ERR_AUTH_FAILED);

	/* 3. Setup an incoming HTTP request WITH an invalid/forged DPoP proof */
	sso_strlcpy(req.dpop_proof, "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkhTMjU2In0.e30.signature", sizeof(req.dpop_proof));

	err = authenticate_request(fake_server.sso_ctx, &req, &resolved_user, &resolved_token);
	ASSERT_INT_EQUAL(err, SSO_ERR_AUTH_FAILED);

	token_destroy(&bound_token);
	sso_destroy(&ctx);
	return 0;
}

static const char* all_tests() {
	mu_run_test(test_dpop_enforcement);
	return 0;
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;
	const char* result = all_tests();
	if (result != 0) {
		printf("%s\n", result);
	} else {
		printf("ALL TESTS PASSED\n");
	}
	printf("Tests run: %d\n", tests_run);
	return result != 0;
}
