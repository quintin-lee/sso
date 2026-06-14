#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "group.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

static const char *test_group_hierarchy_and_membership() {
    printf("  Running test_group_hierarchy_and_membership...\n");
    storage_backend_t *storage;
    storage_sqlite_create(&storage);
    storage->open(storage, ":memory:");

    sso_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.storage_backend = storage;

    group_manager_t *gmgr;
    group_manager_create(&gmgr, &ctx);
    ctx.group_mgr = gmgr;

    /* 1. Create Parent Group: Engineering */
    group_t engineering;
    sso_error_t err = group_create(gmgr, "Engineering", "Eng dept", SSO_ID_NONE, &engineering);
    ASSERT_INT_EQUAL(err, SSO_OK);

    /* 2. Create Child Group: Backend (parent=Engineering) */
    group_t backend;
    err = group_create(gmgr, "Backend", "Backend team", engineering.id, &backend);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(backend.parent_group_id, engineering.id);

    /* 3. Test Membership */
    sso_id_t user_id = 1001;
    err = group_add_user(gmgr, backend.id, user_id);
    ASSERT_INT_EQUAL(err, SSO_OK);

    /* Verify direct membership */
    sso_id_t groups[10];
    size_t count = 0;
    /* user_get_groups is in user.h/user.c, but we can check via storage directly for unit test isolation or use managers */
    err = storage->get_user_groups(storage, user_id, groups, &count, 10);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(groups[0], backend.id);

    /* 4. Test Ancestors */
    sso_id_t ancestors[10];
    count = 0;
    err = group_get_ancestors(gmgr, backend.id, ancestors, &count, 10);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(ancestors[0], engineering.id);

    group_manager_destroy(gmgr);
    storage->close(storage);
    free(storage);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_group_hierarchy_and_membership);
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
