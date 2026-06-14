#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "minunit.h"
#include "permission.h"
#include "policy.h"
#include "user.h"
#include "role.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

static const char *test_permission_rbac_basic() {
    printf("  Running test_permission_rbac_basic...\n");
    storage_backend_t *storage;
    storage_sqlite_create(&storage);
    storage->open(storage, ":memory:");

    sso_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.storage_backend = storage;

    user_manager_t *umgr; user_manager_create(&umgr, &ctx); ctx.user_mgr = umgr;
    role_manager_t *rmgr; role_manager_create(&rmgr, &ctx); ctx.role_mgr = rmgr;
    policy_manager_t *pmgr; policy_manager_create(&pmgr, &ctx); ctx.policy_mgr = pmgr;
    permission_engine_t *pengine; perm_engine_create(&pengine, &ctx); ctx.perm_engine = pengine;

    user_t user; user_create(umgr, "alice", "p", "a@e.c", "A", &user);
    role_t admin; role_create(rmgr, "admin", "Admin", SSO_ID_NONE, &admin);
    role_assign_to_user(rmgr, admin.id, user.id);

    policy_t pol;
    const char *rules = "{\"roles\":[{\"name\":\"admin\",\"effect\":\"allow\"}]}";
    sso_error_t err = policy_create(pmgr, "Admin Only", PERM_STRATEGY_RBAC, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    ASSERT_INT_EQUAL(err, SSO_OK);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.rbac.role_name, "admin");

    bool allowed = false;
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, true);

    strcpy(ectx.params.rbac.role_name, "editor");
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(allowed, false);

    perm_engine_destroy(pengine);
    policy_manager_destroy(pmgr);
    role_manager_destroy(rmgr);
    user_manager_destroy(umgr);
    storage->close(storage);
    free(storage);
    return 0;
}

static const char *test_permission_api_basic() {
    printf("  Running test_permission_api_basic...\n");
    storage_backend_t *storage;
    storage_sqlite_create(&storage);
    storage->open(storage, ":memory:");

    sso_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.storage_backend = storage;

    user_manager_t *umgr; user_manager_create(&umgr, &ctx); ctx.user_mgr = umgr;
    policy_manager_t *pmgr; policy_manager_create(&pmgr, &ctx); ctx.policy_mgr = pmgr;
    permission_engine_t *pengine; perm_engine_create(&pengine, &ctx); ctx.perm_engine = pengine;

    user_t user; user_create(umgr, "bob", "p", "b@e.c", "B", &user);

    policy_t pol;
    const char *rules = "{\"endpoints\":[{\"method\":\"GET\",\"path\":\"/api/v1/users/*\",\"effect\":\"allow\"}]}";
    sso_error_t err = policy_create(pmgr, "User Reader", PERM_STRATEGY_API, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    ASSERT_INT_EQUAL(err, SSO_OK);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.api.http_method, "GET");
    strcpy(ectx.params.api.request_path, "/api/v1/users/123");

    bool allowed = false;
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, true);

    strcpy(ectx.params.api.http_method, "POST");
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(allowed, false);

    perm_engine_destroy(pengine);
    policy_manager_destroy(pmgr);
    user_manager_destroy(umgr);
    storage->close(storage);
    free(storage);
    return 0;
}

static const char *test_permission_abac_basic() {
    printf("  Running test_permission_abac_basic...\n");
    storage_backend_t *storage;
    storage_sqlite_create(&storage);
    storage->open(storage, ":memory:");

    sso_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.storage_backend = storage;

    user_manager_t *umgr; user_manager_create(&umgr, &ctx); ctx.user_mgr = umgr;
    policy_manager_t *pmgr; policy_manager_create(&pmgr, &ctx); ctx.policy_mgr = pmgr;
    permission_engine_t *pengine; perm_engine_create(&pengine, &ctx); ctx.perm_engine = pengine;

    user_t user; user_create(umgr, "charlie", "p", "c@e.c", "C", &user);

    policy_t pol;
    const char *rules = "{\"conditions\":[{\"source\":\"resource\",\"attr\":\"owner_id\",\"op\":\"eq\",\"value\":\"123\"}],\"logic\":\"and\",\"effect\":\"allow\"}";
    sso_error_t err = policy_create(pmgr, "Owner Only", PERM_STRATEGY_ABAC, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    ASSERT_INT_EQUAL(err, SSO_OK);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.abac.resource_attrs, "{\"owner_id\":123}");

    bool allowed = false;
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, true);

    strcpy(ectx.params.abac.resource_attrs, "{\"owner_id\":456}");
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(allowed, false);

    perm_engine_destroy(pengine);
    policy_manager_destroy(pmgr);
    user_manager_destroy(umgr);
    storage->close(storage);
    free(storage);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_permission_rbac_basic);
    mu_run_test(test_permission_api_basic);
    mu_run_test(test_permission_abac_basic);
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
