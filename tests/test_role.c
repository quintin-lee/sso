#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "role.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

static const char *test_role_hierarchy() {
    printf("  Running test_role_hierarchy...\n");
    storage_backend_t *storage;
    storage_sqlite_create(&storage);
    storage->open(storage, ":memory:");

    sso_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.storage_backend = storage;

    role_manager_t *rmgr;
    role_manager_create(&rmgr, &ctx);
    ctx.role_mgr = rmgr;

    /* Create Parent Role: admin */
    role_t admin;
    sso_error_t err = role_create(rmgr, "admin", "Admin role", SSO_ID_NONE, &admin);
    ASSERT_INT_EQUAL(err, SSO_OK);

    /* Create Child Role: editor (parent=admin) */
    role_t editor;
    err = role_create(rmgr, "editor", "Editor role", admin.id, &editor);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(editor.parent_role_id, admin.id);

    /* Get by name */
    role_t found;
    err = role_get_by_name(rmgr, "editor", &found);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(found.id, editor.id);

    /* Test ancestors */
    sso_id_t ancestors[10];
    size_t count = 0;
    err = role_get_ancestors(rmgr, editor.id, ancestors, &count, 10);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(ancestors[0], admin.id);

    role_manager_destroy(rmgr);
    storage->close(storage);
    free(storage);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_role_hierarchy);
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
