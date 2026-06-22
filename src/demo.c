/*
 * demo.c — SSO system demo mode: sample data creation and verification.
 *
 * When run without --server or --interactive, creates 3 sample users
 * (admin, alice, bob), 3 roles (admin -> editor -> viewer hierarchy),
 * 2 groups (engineering, finance), and policies across all 7 permission
 * strategies. Then executes a comprehensive suite of permission checks
 * and a 1000-iteration cache stress test to validate the system end-to-end.
 */

#include "sso.h"
#include "server.h"
#include "handlers.h"
#include "logger.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "permission.h"
#include "token.h"
#include "storage.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int run_demo(sso_config_t* cfg) {
	sso_error_t err;
	printf("=== SSO System Demo ===\n\n");

	/* ---- 1. Init SSO context ---- */
	printf("[1] Initialising SSO system...\n");
	storage_backend_t* storage = NULL;
	err						   = storage_sqlite_create(&storage);
	if (err != SSO_OK) {
		LOG_ERROR("Failed to create storage: %s", sso_strerror(err));
		return 1;
	}

	sso_context_t ctx;
	err = sso_init(&ctx, storage, cfg);
	if (err != SSO_OK) {
		LOG_ERROR("Failed to init SSO: %s", sso_strerror(err));
		return 1;
	}
	printf("  OK\n\n");

	user_manager_t*	  umgr = (user_manager_t*)ctx.user_mgr;
	role_manager_t*	  rmgr = (role_manager_t*)ctx.role_mgr;
	group_manager_t*  gmgr = (group_manager_t*)ctx.group_mgr;
	policy_manager_t* pmgr = (policy_manager_t*)ctx.policy_mgr;

	/* ---- 2. Create users ---- */
	printf("[2] Creating users...\n");
	user_t admin_user, alice_user, bob_user;

	err = user_create(umgr, "admin", "admin123", "admin@example.com", "Admin", &admin_user);
	printf("  admin: id=%lu status=%s\n", (unsigned long)admin_user.id, err == SSO_OK ? "OK" : sso_strerror(err));

	err = user_create(umgr, "alice", "alice456", "alice@example.com", "Alice", &alice_user);
	printf("  alice: id=%lu status=%s\n", (unsigned long)alice_user.id, err == SSO_OK ? "OK" : sso_strerror(err));

	err = user_create(umgr, "bob", "bob789", "bob@example.com", "Bob", &bob_user);
	printf("  bob:   id=%lu status=%s\n", (unsigned long)bob_user.id, err == SSO_OK ? "OK" : sso_strerror(err));

	printf("\n");

	/* ---- 3. Create roles ---- */
	printf("[3] Creating roles...\n");
	role_t admin_role, editor_role, viewer_role;

	role_create(rmgr, "admin", "Full system access", SSO_ID_NONE, &admin_role);
	role_create(rmgr, "editor", "Can edit content", admin_role.id, &editor_role);
	role_create(rmgr, "viewer", "Read-only access", editor_role.id, &viewer_role);
	printf("  admin=%lu  editor=%lu  viewer=%lu\n", (unsigned long)admin_role.id, (unsigned long)editor_role.id,
		   (unsigned long)viewer_role.id);

	/* ---- 4. Create groups ---- */
	printf("[4] Creating groups...\n");
	group_t engineering, finance;

	group_create(gmgr, "engineering", "Engineering Department", SSO_ID_NONE, &engineering);
	group_create(gmgr, "finance", "Finance Department", SSO_ID_NONE, &finance);
	printf("  engineering=%lu  finance=%lu\n", (unsigned long)engineering.id, (unsigned long)finance.id);

	/* ---- 5. Assign roles and group memberships ---- */
	printf("[5] Assigning roles and group memberships...\n");
	role_assign_to_user(rmgr, admin_role.id, admin_user.id);
	role_assign_to_user(rmgr, editor_role.id, alice_user.id);
	role_assign_to_user(rmgr, viewer_role.id, bob_user.id);

	group_add_user(gmgr, engineering.id, alice_user.id);
	group_add_user(gmgr, finance.id, bob_user.id);
	printf("  admin   ← admin role\n");
	printf("  alice   ← editor role + engineering group\n");
	printf("  bob     ← viewer role + finance group\n");
	printf("\n");

	/* ---- 6. Create functional permission policy ---- */
	printf("[6] Creating FUNCTIONAL permission policy...\n");
	policy_t func_policy;
	err = policy_create(pmgr, "User Management Functions", PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW,
						100, /* high priority */
						"{"
						"  \"functions\": ["
						"    {\"code\": \"user:create\", \"effect\": \"allow\"},"
						"    {\"code\": \"user:view\",   \"effect\": \"allow\"},"
						"    {\"code\": \"user:delete\", \"effect\": \"deny\"},"
						"    {\"code\": \"report:*\",    \"effect\": \"allow\"}"
						"  ]"
						"}",
						&func_policy);
	printf("  policy id=%lu status=%s\n", (unsigned long)func_policy.id, err == SSO_OK ? "OK" : sso_strerror(err));

	/* ---- 7. Create API permission policy ---- */
	printf("[7] Creating API permission policy...\n");
	policy_t api_policy;
	err = policy_create(pmgr, "API Access Rules", PERM_STRATEGY_API, POLICY_EFFECT_ALLOW, 90,
						"{"
						"  \"endpoints\": ["
						"    {\"method\": \"GET\",    \"path\": \"/api/v1/users\",      \"effect\": \"allow\"},"
						"    {\"method\": \"GET\",    \"path\": \"/api/v1/users/*\",    \"effect\": \"allow\"},"
						"    {\"method\": \"POST\",   \"path\": \"/api/v1/users\",      \"effect\": \"allow\"},"
						"    {\"method\": \"DELETE\", \"path\": \"/api/v1/users/*\",    \"effect\": \"deny\"},"
						"    {\"method\": \"*\",      \"path\": \"/api/v1/public/*\",   \"effect\": \"allow\"}"
						"  ]"
						"}",
						&api_policy);
	printf("  policy id=%lu status=%s\n", (unsigned long)api_policy.id, err == SSO_OK ? "OK" : sso_strerror(err));

	/* ---- 8. Create data permission policy ---- */
	printf("[8] Creating DATA permission policy...\n");
	policy_t data_policy;
	err = policy_create(pmgr, "Order Data Access", PERM_STRATEGY_DATA, POLICY_EFFECT_ALLOW, 80,
						"{"
						"  \"resource_type\": \"order\","
						"  \"conditions\": ["
						"    {\"field\": \"status\", \"op\": \"eq\", \"value\": \"pending\"}"
						"  ],"
						"  \"allowed_fields\": [\"id\", \"title\", \"status\"],"
						"  \"effect\": \"allow\""
						"}",
						&data_policy);
	printf("  policy id=%lu status=%s\n", (unsigned long)data_policy.id, err == SSO_OK ? "OK" : sso_strerror(err));

	/* ---- 9. Create RBAC permission policy ---- */
	printf("\n[9] Creating RBAC permission policy...\n");
	policy_t rbac_policy;
	err = policy_create(pmgr, "Admin Role Access", PERM_STRATEGY_RBAC, POLICY_EFFECT_ALLOW, 70,
						"{"
						"  \"roles\": ["
						"    {\"name\": \"admin\",  \"effect\": \"allow\"},"
						"    {\"name\": \"editor\", \"effect\": \"allow\"}"
						"  ]"
						"}",
						&rbac_policy);
	printf("  policy id=%lu status=%s\n", (unsigned long)rbac_policy.id, err == SSO_OK ? "OK" : sso_strerror(err));

	/* ---- 10. Create Location permission policy ---- */
	printf("\n[10] Creating Location permission policy...\n");
	policy_t loc_policy;
	err = policy_create(pmgr, "Local Network Access", PERM_STRATEGY_LOCATION, POLICY_EFFECT_ALLOW, 60,
						"{"
						"  \"locations\": ["
						"    {\"type\": \"ip_cidr\", \"value\": \"127.0.0.0/8\",  \"effect\": \"allow\"},"
						"    {\"type\": \"ip_cidr\", \"value\": \"10.0.0.0/8\",   \"effect\": \"allow\"},"
						"    {\"type\": \"ip_cidr\", \"value\": \"0.0.0.0/0\",    \"effect\": \"deny\"}"
						"  ]"
						"}",
						&loc_policy);
	printf("  policy id=%lu status=%s\n", (unsigned long)loc_policy.id, err == SSO_OK ? "OK" : sso_strerror(err));

	/* ---- 11. Create LBAC (Label-Based) permission policy ---- */
	printf("\n[11] Creating LBAC (Label-Based) permission policy...\n");
	policy_t lbac_policy;
	err = policy_create(pmgr, "Confidential Data Access", PERM_STRATEGY_LBAC, POLICY_EFFECT_ALLOW, 55,
						"{"
						"  \"labels\": ["
						"    {\"name\": \"CONFIDENTIAL\", \"effect\": \"allow\"},"
						"    {\"name\": \"TOP_SECRET\",   \"effect\": \"allow\"}"
						"  ]"
						"}",
						&lbac_policy);
	printf("  policy id=%lu status=%s\n", (unsigned long)lbac_policy.id, err == SSO_OK ? "OK" : sso_strerror(err));

	/* ---- 12. Create ABAC permission policy ---- */
	printf("\n[12] Creating ABAC permission policy...\n");
	policy_t abac_policy;
	err = policy_create(
			pmgr, "Engineering Department Access", PERM_STRATEGY_ABAC, POLICY_EFFECT_ALLOW, 50,
			"{"
			"  \"conditions\": ["
			"    {\"source\": \"subject\", \"attr\": \"department\", \"op\": \"eq\", \"value\": \"engineering\"}"
			"  ],"
			"  \"logic\": \"and\","
			"  \"effect\": \"allow\""
			"}",
			&abac_policy);
	printf("  policy id=%lu status=%s\n", (unsigned long)abac_policy.id, err == SSO_OK ? "OK" : sso_strerror(err));

	/* ---- 13. Assign policies ---- */
	printf("\n[13] Assigning policies to roles...\n");
	policy_assign_to(pmgr, func_policy.id, POLICY_TARGET_ROLE, admin_role.id);
	policy_assign_to(pmgr, api_policy.id, POLICY_TARGET_ROLE, admin_role.id);
	policy_assign_to(pmgr, data_policy.id, POLICY_TARGET_ROLE, editor_role.id);
	policy_assign_to(pmgr, rbac_policy.id, POLICY_TARGET_ROLE, admin_role.id);
	policy_assign_to(pmgr, loc_policy.id, POLICY_TARGET_ROLE, admin_role.id);
	policy_assign_to(pmgr, lbac_policy.id, POLICY_TARGET_ROLE, admin_role.id);
	policy_assign_to(pmgr, abac_policy.id, POLICY_TARGET_ROLE, admin_role.id);
	printf("  Admin role   ← functional + API + RBAC + Location + LBAC + ABAC policies\n");
	printf("  Editor role  ← data policy\n");
	printf("\n");

	/* ---- 14. Functional permission checks ---- */
	printf("[14] Functional permission checks:\n");
	bool allowed;

	perm_check_function(&ctx, admin_user.id, "user:create", &allowed);
	printf("  admin  user:create  → %s\n", allowed ? "ALLOW" : "DENY");

	perm_check_function(&ctx, admin_user.id, "user:delete", &allowed);
	printf("  admin  user:delete  → %s\n", allowed ? "ALLOW" : "DENY");

	perm_check_function(&ctx, admin_user.id, "report:view", &allowed);
	printf("  admin  report:view  → %s\n", allowed ? "ALLOW" : "DENY");

	printf("\n[15] API permission checks:\n");
	perm_check_api(&ctx, admin_user.id, "GET", "/api/v1/users", &allowed);
	printf("  admin  GET /api/v1/users       → %s\n", allowed ? "ALLOW" : "DENY");

	perm_check_api(&ctx, admin_user.id, "POST", "/api/v1/users", &allowed);
	printf("  admin  POST /api/v1/users      → %s\n", allowed ? "ALLOW" : "DENY");

	perm_check_api(&ctx, admin_user.id, "DELETE", "/api/v1/users/42", &allowed);
	printf("  admin  DELETE /api/v1/users/42 → %s\n", allowed ? "ALLOW" : "DENY");

	printf("\n[16] Data permission checks:\n");
	char** fields	   = NULL;
	size_t field_count = 0;

	/* Test 1: Condition matches (status=pending) */
	bool data_allowed = false;
	perm_check_data(&ctx, alice_user.id, "order",
					"{\"id\":101,\"title\":\"MacBook Pro\",\"status\":\"pending\",\"amount\":1999}", &data_allowed,
					&fields, &field_count);
	printf("  alice  order(pending) → %s  allowed_fields=", data_allowed ? "ALLOW" : "DENY");
	if (fields) {
		printf("[");
		for (size_t i = 0; i < field_count; i++) {
			printf("%s%s", fields[i], i < field_count - 1 ? "," : "");
			free(fields[i]);
		}
		printf("]");
		free(fields);
	}
	printf("\n");

	/* Test 2: Condition fails (status=shipped) */
	perm_check_data(&ctx, alice_user.id, "order",
					"{\"id\":102,\"title\":\"iPad\",\"status\":\"shipped\",\"amount\":799}", &data_allowed, &fields,
					&field_count);
	printf("  alice  order(shipped) → %s\n", data_allowed ? "ALLOW" : "DENY");

	/* ---- 16b. Cache Performance Stress Test ---- */
	printf("\n[16b] Cache Performance Stress Test (1000 iterations)...\n");
	uint64_t start_time = get_time_ms();
	for (int i = 0; i < 1000; i++) {
		perm_check_function(&ctx, admin_user.id, "user:create", &allowed);
	}
	uint64_t duration = get_time_ms() - start_time;
	printf("  1000 functional checks: %lums (%.3fms per check)\n", (unsigned long)duration, (double)duration / 1000.0);
	printf("  OK (Check stderr for telemetry)\n");

	/* ---- 17. RBAC permission check ---- */
	printf("\n[17] RBAC permission checks:\n");
	perm_check_rbac(&ctx, admin_user.id, "admin", &allowed);
	printf("  admin  check_rbac(\"admin\")    → %s\n", allowed ? "ALLOW" : "DENY");
	perm_check_rbac(&ctx, bob_user.id, "admin", &allowed);
	printf("  bob    check_rbac(\"admin\")    → %s\n", allowed ? "ALLOW" : "DENY");
	perm_check_rbac(&ctx, admin_user.id, "viewer", &allowed);
	printf("  admin  check_rbac(\"viewer\")   → %s\n", allowed ? "ALLOW" : "DENY");

	/* ---- 18. Location permission check ---- */
	printf("\n[18] Location permission checks:\n");
	perm_check_location(&ctx, admin_user.id, "127.0.0.1", NULL, &allowed);
	printf("  admin  source=127.0.0.1         → %s\n", allowed ? "ALLOW" : "DENY");
	perm_check_location(&ctx, admin_user.id, "10.0.0.5", NULL, &allowed);
	printf("  admin  source=10.0.0.5          → %s\n", allowed ? "ALLOW" : "DENY");
	perm_check_location(&ctx, admin_user.id, "203.0.113.1", NULL, &allowed);
	printf("  admin  source=203.0.113.1       → %s\n", allowed ? "ALLOW" : "DENY");

	/* ---- 19. LBAC (Label-Based) permission check ---- */
	printf("\n[19] LBAC (Label-Based) permission checks:\n");
	perm_check_lbac(&ctx, admin_user.id, "PUBLIC,CONFIDENTIAL", "CONFIDENTIAL", &allowed);
	printf("  admin  labels=[PUBLIC,CONFIDENTIAL] target=CONFIDENTIAL → %s\n", allowed ? "ALLOW" : "DENY");
	perm_check_lbac(&ctx, admin_user.id, "PUBLIC", "TOP_SECRET", &allowed);
	printf("  admin  labels=[PUBLIC]              target=TOP_SECRET    → %s\n", allowed ? "ALLOW" : "DENY");

	/* ---- 20. ABAC permission check ---- */
	printf("\n[20] ABAC permission checks:\n");
	perm_check_abac(&ctx, admin_user.id, "{\"department\":\"engineering\"}", NULL, NULL, &allowed);
	printf("  admin  dept=engineering         → %s\n", allowed ? "ALLOW" : "DENY");
	perm_check_abac(&ctx, admin_user.id, "{\"department\":\"sales\"}", NULL, NULL, &allowed);
	printf("  admin  dept=sales               → %s\n", allowed ? "ALLOW" : "DENY");

	/* ---- 21. Token authentication ---- */
	printf("\n[21] Token-based authentication:\n");
	token_manager_t* tmgr = (token_manager_t*)ctx.token_mgr;

	user_t auth_user;
	err = user_authenticate(umgr, "admin", "admin123", &auth_user);
	printf("  admin login: %s\n", err == SSO_OK ? "OK" : sso_strerror(err));

	if (err == SSO_OK) {
		sso_id_t roles[8], groups[8];
		size_t	 rc = 0, gc = 0;
		user_get_roles(umgr, auth_user.id, roles, &rc, 8);
		user_get_groups(umgr, auth_user.id, groups, &gc, 8);

		token_t token;
		token_issue(tmgr, &auth_user, roles, rc, groups, gc, NULL, 3600000, NULL, &token);
		printf("  token: %s\n", token.token_str);

		/* Verify token */
		token_t decoded;
		err = token_verify(tmgr, token.token_str, &decoded);
		printf("  token verify: %s  (user=%lu)\n", err == SSO_OK ? "OK" : sso_strerror(err),
			   (unsigned long)decoded.user_id);
		token_destroy(&decoded);
		token_destroy(&token);
	}

	/* ---- 22. Role hierarchy ---- */
	printf("\n[22] Role hierarchy:\n");
	sso_id_t ancestors[8];
	size_t	 depth = 0;
	role_get_ancestors(rmgr, viewer_role.id, ancestors, &depth, 8);
	printf("  viewer ancestors: ");
	for (size_t i = 0; i < depth; i++) {
		role_t r;
		role_get_by_id(rmgr, ancestors[i], &r);
		printf("%s ", r.name);
	}
	printf("\n");

	/* ---- 23. Policy resolution ---- */
	printf("\n[23] Policy resolution for admin:\n");
	policy_t resolved[16];
	size_t	 resolved_count = 0;
	err						= policy_resolve_for_user(pmgr, admin_user.id, resolved, &resolved_count, 16);
	if (err == SSO_OK || resolved_count > 0) {
		for (size_t i = 0; i < resolved_count; i++) {
			printf("  [pri=%d] %s (strategy=%s)\n", resolved[i].priority, resolved[i].name,
				   perm_strategy_name(resolved[i].strategy_type));
		}
	}

	/* ---- Cleanup ---- */
	printf("\n=== Demo complete. ===\n");
	sso_destroy(&ctx);

	return 0;
}
