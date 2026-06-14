#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "user.h"
#include "storage.h"
#include "sso.h"

static void test_user_creation_and_auth(void **state) {
    (void)state;
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
    assert_int_equal(err, SSO_OK);
    assert_string_equal(user.username, "testuser");

    /* Authenticate */
    user_t authed;
    err = user_authenticate(umgr, "testuser", "password123", &authed);
    assert_int_equal(err, SSO_OK);
    assert_int_equal(authed.id, user.id);

    /* Failed auth */
    err = user_authenticate(umgr, "testuser", "wrongpassword", &authed);
    assert_int_equal(err, SSO_ERR_AUTH_FAILED);

    user_manager_destroy(umgr);
    storage->close(storage);
    free(storage);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_user_creation_and_auth),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
