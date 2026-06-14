#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "role.h"
#include "user.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

static void setup(storage_backend_t **storage, sso_context_t *ctx,
                  role_manager_t **rmgr, user_manager_t **umgr) {
    storage_sqlite_create(storage);
    (*storage)->open(*storage, ":memory:");
    memset(ctx, 0, sizeof(*ctx));
    ctx->storage_backend = *storage;
    role_manager_create(rmgr, ctx);
    ctx->role_mgr = *rmgr;
    if (umgr) {
        user_manager_create(umgr, ctx);
        user_manager_set_hash_params(*umgr, 2, 67108864); /* INTERACTIVE for speed */
        ctx->user_mgr = *umgr;
    }
}

static void teardown(storage_backend_t *storage, role_manager_t *rmgr, user_manager_t *umgr) {
    if (umgr) user_manager_destroy(umgr);
    role_manager_destroy(rmgr);
    storage->close(storage);
    free(storage);
}

static const char *test_role_hierarchy() {
    printf("  Running test_role_hierarchy...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    role_manager_t *rmgr;
    setup(&storage, &ctx, &rmgr, NULL);

    role_t admin;
    sso_error_t err = role_create(rmgr, "admin", "Admin role", SSO_ID_NONE, &admin);
    ASSERT_INT_EQUAL(err, SSO_OK);

    role_t editor;
    err = role_create(rmgr, "editor", "Editor role", admin.id, &editor);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(editor.parent_role_id, admin.id);

    role_t found;
    err = role_get_by_name(rmgr, "editor", &found);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(found.id, editor.id);

    sso_id_t ancestors[10];
    size_t count = 0;
    err = role_get_ancestors(rmgr, editor.id, ancestors, &count, 10);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(ancestors[0], admin.id);

    teardown(storage, rmgr, NULL);
    return 0;
}

static const char *test_duplicate_role_name() {
    printf("  Running test_duplicate_role_name...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    role_manager_t *rmgr;
    setup(&storage, &ctx, &rmgr, NULL);

    role_t r1;
    ASSERT_INT_EQUAL(role_create(rmgr, "uniquerole", "First", SSO_ID_NONE, &r1), SSO_OK);

    role_t r2;
    ASSERT_INT_EQUAL(role_create(rmgr, "uniquerole", "Second", SSO_ID_NONE, &r2), SSO_ERR_ALREADY_EXISTS);

    teardown(storage, rmgr, NULL);
    return 0;
}

static const char *test_role_delete() {
    printf("  Running test_role_delete...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    role_manager_t *rmgr;
    setup(&storage, &ctx, &rmgr, NULL);

    role_t r;
    role_create(rmgr, "deleterole", "To delete", SSO_ID_NONE, &r);
    ASSERT_INT_EQUAL(role_delete(rmgr, r.id), SSO_OK);

    role_t gone;
    ASSERT_INT_EQUAL(role_get_by_id(rmgr, r.id, &gone), SSO_ERR_NOT_FOUND);

    teardown(storage, rmgr, NULL);
    return 0;
}

static const char *test_role_assign_and_unassign() {
    printf("  Running test_role_assign_and_unassign...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    role_manager_t *rmgr;
    user_manager_t *umgr;
    setup(&storage, &ctx, &rmgr, &umgr);

    user_t user;
    user_create(umgr, "roleuser", "pass", "r@e.com", "Role User", &user);
    role_t role;
    role_create(rmgr, "assignrole", "Assignable", SSO_ID_NONE, &role);

    ASSERT_INT_EQUAL(role_assign_to_user(rmgr, role.id, user.id), SSO_OK);

    sso_id_t role_ids[10];
    size_t count = 0;
    ASSERT_INT_EQUAL(user_get_roles(umgr, user.id, role_ids, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(role_ids[0], role.id);

    ASSERT_INT_EQUAL(role_unassign_from_user(rmgr, role.id, user.id), SSO_OK);
    count = 0;
    sso_error_t err2 = user_get_roles(umgr, user.id, role_ids, &count, 10);
    ASSERT_TRUE(err2 == SSO_OK || err2 == SSO_ERR_NOT_FOUND);
    ASSERT_INT_EQUAL(count, 0);

    teardown(storage, rmgr, umgr);
    return 0;
}

static const char *test_role_deep_hierarchy() {
    printf("  Running test_role_deep_hierarchy...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    role_manager_t *rmgr;
    setup(&storage, &ctx, &rmgr, NULL);

    role_t l1, l2, l3;
    role_create(rmgr, "level1", "Top", SSO_ID_NONE, &l1);
    role_create(rmgr, "level2", "Middle", l1.id, &l2);
    role_create(rmgr, "level3", "Bottom", l2.id, &l3);

    sso_id_t ancestors[10];
    size_t count = 0;
    ASSERT_INT_EQUAL(role_get_ancestors(rmgr, l3.id, ancestors, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 2);
    ASSERT_INT_EQUAL(ancestors[0], l2.id);
    ASSERT_INT_EQUAL(ancestors[1], l1.id);

    sso_id_t children[10];
    count = 0;
    ASSERT_INT_EQUAL(role_get_children(rmgr, l1.id, children, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(children[0], l2.id);

    teardown(storage, rmgr, NULL);
    return 0;
}

static const char *test_role_get_users() {
    printf("  Running test_role_get_users...\n");
    storage_backend_t *storage;
    sso_context_t ctx;
    role_manager_t *rmgr;
    user_manager_t *umgr;
    setup(&storage, &ctx, &rmgr, &umgr);

    user_t u1, u2;
    user_create(umgr, "user1", "p", "u1@e.com", "U1", &u1);
    user_create(umgr, "user2", "p", "u2@e.com", "U2", &u2);
    role_t r;
    role_create(rmgr, "testrole", "Test", SSO_ID_NONE, &r);

    role_assign_to_user(rmgr, r.id, u1.id);
    role_assign_to_user(rmgr, r.id, u2.id);

    sso_id_t user_ids[10];
    size_t count = 0;
    ASSERT_INT_EQUAL(role_get_users(rmgr, r.id, user_ids, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 2);

    teardown(storage, rmgr, umgr);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_role_hierarchy);
    mu_run_test(test_duplicate_role_name);
    mu_run_test(test_role_delete);
    mu_run_test(test_role_assign_and_unassign);
    mu_run_test(test_role_deep_hierarchy);
    mu_run_test(test_role_get_users);
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
