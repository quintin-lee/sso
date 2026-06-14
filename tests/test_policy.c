#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "minunit.h"
#include "permission.h"
#include "policy.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

static void setup(storage_backend_t **storage, sso_context_t *ctx,
                  user_manager_t **umgr, role_manager_t **rmgr,
                  policy_manager_t **pmgr, permission_engine_t **pengine) {
    storage_sqlite_create(storage);
    (*storage)->open(*storage, ":memory:");
    memset(ctx, 0, sizeof(*ctx));
    ctx->storage_backend = *storage;
    if (umgr)  { user_manager_create(umgr, ctx); user_manager_set_hash_params(*umgr, 2, 67108864); ctx->user_mgr = *umgr; }
    if (rmgr)  { role_manager_create(rmgr, ctx);  ctx->role_mgr = *rmgr; }
    if (pmgr)  { policy_manager_create(pmgr, ctx); ctx->policy_mgr = *pmgr; }
    if (pengine) { perm_engine_create(pengine, ctx); ctx->perm_engine = *pengine; }
}

static void teardown(storage_backend_t *storage, user_manager_t *umgr,
                     role_manager_t *rmgr, policy_manager_t *pmgr,
                     permission_engine_t *pengine) {
    if (pengine) perm_engine_destroy(pengine);
    if (pmgr)    policy_manager_destroy(pmgr);
    if (rmgr)    role_manager_destroy(rmgr);
    if (umgr)    user_manager_destroy(umgr);
    storage->close(storage);
    free(storage);
}

static const char *test_permission_rbac_basic() {
    printf("  Running test_permission_rbac_basic...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

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

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_api_basic() {
    printf("  Running test_permission_api_basic...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

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

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_abac_basic() {
    printf("  Running test_permission_abac_basic...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

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

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_func_basic() {
    printf("  Running test_permission_func_basic...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

    user_t user; user_create(umgr, "dave", "p", "d@e.c", "D", &user);

    policy_t pol;
    const char *rules = "{\"functions\":[{\"code\":\"user:create\",\"effect\":\"allow\"},{\"code\":\"user:delete\",\"effect\":\"allow\"}],\"effect\":\"allow\"}";
    sso_error_t err = policy_create(pmgr, "User Admin", PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    ASSERT_INT_EQUAL(err, SSO_OK);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.functional.function_code, "user:create");

    bool allowed = false;
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, true);

    strcpy(ectx.params.functional.function_code, "role:delete");
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(allowed, false);

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_lbac_basic() {
    printf("  Running test_permission_lbac_basic...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

    user_t user; user_create(umgr, "eve", "p", "e@e.c", "E", &user);

    policy_t pol;
    const char *rules = "{\"labels\":[{\"name\":\"confidential\",\"effect\":\"allow\"}]}";
    sso_error_t err = policy_create(pmgr, "LBAC Test", PERM_STRATEGY_LBAC, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    ASSERT_INT_EQUAL(err, SSO_OK);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.lbac.user_labels, "confidential,internal");
    strcpy(ectx.params.lbac.resource_label, "confidential");

    bool allowed = false;
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, true);

    strcpy(ectx.params.lbac.resource_label, "top_secret");
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(allowed, false);

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_location_basic() {
    printf("  Running test_permission_location_basic...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

    user_t user; user_create(umgr, "frank", "p", "f@e.c", "F", &user);

    policy_t pol;
    const char *rules = "{\"locations\":[{\"type\":\"ip_cidr\",\"value\":\"10.0.0.0/8\",\"effect\":\"allow\"}]}";
    sso_error_t err = policy_create(pmgr, "Office Only", PERM_STRATEGY_LOCATION, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    ASSERT_INT_EQUAL(err, SSO_OK);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.location.source_ip, "10.1.2.3");

    bool allowed = false;
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, true);

    strcpy(ectx.params.location.source_ip, "192.168.1.1");
    err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(allowed, false);

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_deny_override() {
    printf("  Running test_permission_deny_override...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

    user_t user; user_create(umgr, "grace", "p", "g@e.c", "G", &user);

    policy_t allow_pol;
    const char *allow_rules = "{\"functions\":[{\"code\":\"user:create\",\"effect\":\"allow\"}],\"effect\":\"allow\"}";
    policy_create(pmgr, "Allow Create", PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW, 1, allow_rules, &allow_pol);
    policy_assign_to(pmgr, allow_pol.id, POLICY_TARGET_USER, user.id);

    policy_t deny_pol;
    const char *deny_rules = "{\"functions\":[{\"code\":\"user:create\",\"effect\":\"deny\"}],\"effect\":\"deny\"}";
    policy_create(pmgr, "Deny Create", PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_DENY, 2, deny_rules, &deny_pol);
    policy_assign_to(pmgr, deny_pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.functional.function_code, "user:create");

    bool allowed = true;
    sso_error_t err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, false);

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_disabled_policy() {
    printf("  Running test_permission_disabled_policy...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

    user_t user; user_create(umgr, "heidi", "p", "h@e.c", "H", &user);

    policy_t pol;
    const char *rules = "{\"functions\":[{\"code\":\"user:create\",\"effect\":\"allow\"}],\"effect\":\"allow\"}";
    policy_create(pmgr, "Disabled Pol", PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);
    policy_set_status(pmgr, pol.id, POLICY_STATUS_DISABLED);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.functional.function_code, "user:create");

    bool allowed = true;
    sso_error_t err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, false);

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *test_permission_no_match() {
    printf("  Running test_permission_no_match...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    user_manager_t *umgr;
    role_manager_t *rmgr;
    policy_manager_t *pmgr;
    permission_engine_t *pengine;
    setup(&storage, &ctx, &umgr, &rmgr, &pmgr, &pengine);

    user_t user; user_create(umgr, "ivan", "p", "i@e.c", "I", &user);

    policy_t pol;
    const char *rules = "{\"functions\":[{\"code\":\"user:create\",\"effect\":\"allow\"}],\"effect\":\"allow\"}";
    policy_create(pmgr, "Func Pol", PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW, 0, rules, &pol);
    policy_assign_to(pmgr, pol.id, POLICY_TARGET_USER, user.id);

    eval_context_t ectx;
    memset(&ectx, 0, sizeof(ectx));
    ectx.user_id = user.id;
    strcpy(ectx.params.api.http_method, "GET");
    strcpy(ectx.params.api.request_path, "/api/v1/users");

    bool allowed = true;
    sso_error_t err = perm_engine_evaluate(pengine, &ectx, &allowed, NULL);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(allowed, false);

    teardown(storage, umgr, rmgr, pmgr, pengine);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_permission_rbac_basic);
    mu_run_test(test_permission_api_basic);
    mu_run_test(test_permission_abac_basic);
    mu_run_test(test_permission_func_basic);
    mu_run_test(test_permission_lbac_basic);
    mu_run_test(test_permission_location_basic);
    mu_run_test(test_permission_deny_override);
    mu_run_test(test_permission_disabled_policy);
    mu_run_test(test_permission_no_match);
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
