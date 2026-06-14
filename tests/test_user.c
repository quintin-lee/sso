#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "user.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

static const char *test_user_creation_and_auth() {
    printf("  Running test_user_creation_and_auth...\n");
    storage_backend_t *storage;
    storage_sqlite_create(&storage);
    storage->open(storage, ":memory:");

    sso_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.storage_backend = storage;

    user_manager_t *umgr;
    user_manager_create(&umgr, &ctx);
    ctx.user_mgr = umgr;

    /* Create user */
    user_t user;
    sso_error_t err = user_create(umgr, "testuser", "password123", "test@example.com", "Test User", &user);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_STR_EQUAL(user.username, "testuser");

    /* Authenticate */
    user_t authed;
    err = user_authenticate(umgr, "testuser", "password123", &authed);
    ASSERT_INT_EQUAL(err, SSO_OK);
    ASSERT_INT_EQUAL(authed.id, user.id);

    /* Failed auth */
    err = user_authenticate(umgr, "testuser", "wrongpassword", &authed);
    ASSERT_INT_EQUAL(err, SSO_ERR_AUTH_FAILED);

    user_manager_destroy(umgr);
    storage->close(storage);
    free(storage);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_user_creation_and_auth);
    return 0;
}

int main(int argc, char **argv) {
    const char *result = all_tests();
    if (result != 0) printf("FAILED\n");
    else printf("ALL TESTS PASSED\n");
    printf("Tests run: %d\n", tests_run);
    return result != 0;
}
