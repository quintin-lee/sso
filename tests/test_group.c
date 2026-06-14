#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "group.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

static void setup(storage_backend_t **storage, sso_context_t *ctx, group_manager_t **gmgr) {
    storage_sqlite_create(storage);
    (*storage)->open(*storage, ":memory:");
    memset(ctx, 0, sizeof(*ctx));
    ctx->storage_backend = *storage;
    group_manager_create(gmgr, ctx);
    ctx->group_mgr = *gmgr;
}

static void teardown(storage_backend_t *storage, group_manager_t *gmgr) {
    group_manager_destroy(gmgr);
    storage->close(storage);
    free(storage);
}

static const char *test_group_hierarchy_and_membership() {
    printf("  Running test_group_hierarchy_and_membership...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    group_manager_t *gmgr;
    setup(&storage, &ctx, &gmgr);

    group_t engineering;
    sso_error_t err = group_create(gmgr, "Engineering", "Eng dept", SSO_ID_NONE, &engineering);
    ASSERT_INT_EQUAL(err, SSO_OK);

    group_t backend;
    err = group_create(gmgr, "Backend", "Backend team", engineering.id, &backend);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(backend.parent_group_id, engineering.id);

    sso_id_t user_id = 1001;
    err = group_add_user(gmgr, backend.id, user_id);
    ASSERT_INT_EQUAL(err, SSO_OK);

    sso_id_t groups[10];
    size_t count = 0;
    err = storage->get_user_groups(storage, user_id, groups, &count, 10);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(groups[0], backend.id);

    sso_id_t ancestors[10];
    count = 0;
    err = group_get_ancestors(gmgr, backend.id, ancestors, &count, 10);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(ancestors[0], engineering.id);

    teardown(storage, gmgr);
    return 0;
}

static const char *test_duplicate_group_name() {
    printf("  Running test_duplicate_group_name...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    group_manager_t *gmgr;
    setup(&storage, &ctx, &gmgr);

    group_t g1;
    ASSERT_INT_EQUAL(group_create(gmgr, "mygroup", "First", SSO_ID_NONE, &g1), SSO_OK);

    group_t g2;
    ASSERT_INT_EQUAL(group_create(gmgr, "mygroup", "Second", SSO_ID_NONE, &g2), SSO_ERR_ALREADY_EXISTS);

    teardown(storage, gmgr);
    return 0;
}

static const char *test_group_remove_user() {
    printf("  Running test_group_remove_user...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    group_manager_t *gmgr;
    setup(&storage, &ctx, &gmgr);

    group_t g;
    group_create(gmgr, "testgroup", "Test", SSO_ID_NONE, &g);

    sso_id_t uid = 2001;
    group_add_user(gmgr, g.id, uid);

    sso_id_t groups[10];
    size_t count = 0;
    storage->get_user_groups(storage, uid, groups, &count, 10);
    ASSERT_INT_EQUAL(count, 1);

    ASSERT_INT_EQUAL(group_remove_user(gmgr, g.id, uid), SSO_OK);

    count = 0;
    storage->get_user_groups(storage, uid, groups, &count, 10);
    ASSERT_INT_EQUAL(count, 0);

    teardown(storage, gmgr);
    return 0;
}

static const char *test_group_deep_hierarchy() {
    printf("  Running test_group_deep_hierarchy...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    group_manager_t *gmgr;
    setup(&storage, &ctx, &gmgr);

    group_t l1, l2, l3;
    group_create(gmgr, "corp", "Corp", SSO_ID_NONE, &l1);
    group_create(gmgr, "division", "Division", l1.id, &l2);
    group_create(gmgr, "team", "Team", l2.id, &l3);

    sso_id_t ancestors[10];
    size_t count = 0;
    ASSERT_INT_EQUAL(group_get_ancestors(gmgr, l3.id, ancestors, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 2);
    ASSERT_INT_EQUAL(ancestors[0], l2.id);
    ASSERT_INT_EQUAL(ancestors[1], l1.id);

    teardown(storage, gmgr);
    return 0;
}

static const char *test_group_get_members() {
    printf("  Running test_group_get_members...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    group_manager_t *gmgr;
    setup(&storage, &ctx, &gmgr);

    group_t g;
    group_create(gmgr, "team", "Team", SSO_ID_NONE, &g);

    group_add_user(gmgr, g.id, 101);
    group_add_user(gmgr, g.id, 102);
    group_add_user(gmgr, g.id, 103);

    sso_id_t members[10];
    size_t count = 0;
    ASSERT_INT_EQUAL(group_get_members(gmgr, g.id, members, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 3);

    teardown(storage, gmgr);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_group_hierarchy_and_membership);
    mu_run_test(test_duplicate_group_name);
    mu_run_test(test_group_remove_user);
    mu_run_test(test_group_deep_hierarchy);
    mu_run_test(test_group_get_members);
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
