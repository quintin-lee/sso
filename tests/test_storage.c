#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "storage.h"
#include "sso.h"
#include "logger.h"

int tests_run = 0;

#define mu_run_test_arg(test, arg) do { const char *message = test(arg); tests_run++; \
                               if (message) return message; } while (0)

static void fill_user(user_t *u, const char *name) {
    memset(u, 0, sizeof(*u));
    strcpy(u->username, name);
    strcpy(u->password_hash, "hash");
    strcpy(u->email, "x@e.com");
    strcpy(u->display_name, name);
    u->status = USER_STATUS_ACTIVE;
}

static void fill_role(role_t *r, const char *name) {
    memset(r, 0, sizeof(*r));
    strcpy(r->name, name);
    strcpy(r->description, "test");
    r->status = ROLE_STATUS_ACTIVE;
}

static void fill_group(group_t *g, const char *name) {
    memset(g, 0, sizeof(*g));
    strcpy(g->name, name);
    strcpy(g->description, "test");
    g->status = GROUP_STATUS_ACTIVE;
}

/* ==================== Generic Storage Tests ==================== */

static const char *test_generic_user_crud(storage_backend_t *s) {
    printf("    Running user_crud...\n");
    user_t u;
    fill_user(&u, "testuser");
    ASSERT_INT_EQUAL(s->user_create(s, &u), SSO_OK);
    ASSERT_TRUE(u.id != SSO_ID_NONE);

    user_t fetched;
    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.username, "testuser");

    ASSERT_INT_EQUAL(s->user_get_by_name(s, "testuser", &fetched), SSO_OK);
    ASSERT_INT_EQUAL(fetched.id, u.id);

    strcpy(u.email, "updated@e.com");
    ASSERT_INT_EQUAL(s->user_update(s, &u), SSO_OK);

    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.email, "updated@e.com");

    ASSERT_INT_EQUAL(s->user_delete(s, u.id), SSO_OK);
    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_ERR_NOT_FOUND);
    return 0;
}

static const char *test_generic_role_crud(storage_backend_t *s) {
    printf("    Running role_crud...\n");
    role_t r;
    fill_role(&r, "testrole");
    ASSERT_INT_EQUAL(s->role_create(s, &r), SSO_OK);
    ASSERT_TRUE(r.id != SSO_ID_NONE);

    role_t fetched;
    ASSERT_INT_EQUAL(s->role_get_by_id(s, r.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.name, "testrole");

    ASSERT_INT_EQUAL(s->role_get_by_name(s, "testrole", &fetched), SSO_OK);
    ASSERT_INT_EQUAL(fetched.id, r.id);

    ASSERT_INT_EQUAL(s->role_delete(s, r.id), SSO_OK);
    ASSERT_INT_EQUAL(s->role_get_by_id(s, r.id, &fetched), SSO_ERR_NOT_FOUND);
    return 0;
}

static const char *test_generic_group_crud(storage_backend_t *s) {
    printf("    Running group_crud...\n");
    group_t g;
    fill_group(&g, "testgroup");
    ASSERT_INT_EQUAL(s->group_create(s, &g), SSO_OK);
    ASSERT_TRUE(g.id != SSO_ID_NONE);

    group_t fetched;
    ASSERT_INT_EQUAL(s->group_get_by_id(s, g.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.name, "testgroup");

    ASSERT_INT_EQUAL(s->group_delete(s, g.id), SSO_OK);
    ASSERT_INT_EQUAL(s->group_get_by_id(s, g.id, &fetched), SSO_ERR_NOT_FOUND);
    return 0;
}

static const char *test_generic_assignments(storage_backend_t *s) {
    printf("    Running assignments...\n");
    user_t u; fill_user(&u, "assignuser"); ASSERT_INT_EQUAL(s->user_create(s, &u), SSO_OK);
    role_t r; fill_role(&r, "assignrole"); ASSERT_INT_EQUAL(s->role_create(s, &r), SSO_OK);
    group_t g; fill_group(&g, "assigngroup"); ASSERT_INT_EQUAL(s->group_create(s, &g), SSO_OK);

    ASSERT_INT_EQUAL(s->assign_role_to_user(s, r.id, u.id), SSO_OK);
    ASSERT_INT_EQUAL(s->add_user_to_group(s, g.id, u.id), SSO_OK);

    sso_id_t role_ids[10];
    size_t count = 0;
    ASSERT_INT_EQUAL(s->get_user_roles(s, u.id, role_ids, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(role_ids[0], r.id);

    sso_id_t group_ids[10];
    count = 0;
    ASSERT_INT_EQUAL(s->get_user_groups(s, u.id, group_ids, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(group_ids[0], g.id);

    ASSERT_INT_EQUAL(s->unassign_role_from_user(s, r.id, u.id), SSO_OK);
    count = 0;
    sso_error_t err_r = s->get_user_roles(s, u.id, role_ids, &count, 10);
    ASSERT_TRUE(err_r == SSO_OK || err_r == SSO_ERR_NOT_FOUND);
    ASSERT_INT_EQUAL(count, 0);
    return 0;
}

static const char *test_generic_not_found(storage_backend_t *s) {
    printf("    Running not_found...\n");
    user_t u;
    ASSERT_INT_EQUAL(s->user_get_by_id(s, 999999, &u), SSO_ERR_NOT_FOUND);
    ASSERT_INT_EQUAL(s->user_get_by_name(s, "nobody_special", &u), SSO_ERR_NOT_FOUND);

    role_t r;
    ASSERT_INT_EQUAL(s->role_get_by_id(s, 999999, &r), SSO_ERR_NOT_FOUND);

    group_t g;
    ASSERT_INT_EQUAL(s->group_get_by_id(s, 999999, &g), SSO_ERR_NOT_FOUND);
    return 0;
}

static const char *test_generic_duplicate(storage_backend_t *s) {
    printf("    Running duplicate...\n");
    user_t u1; fill_user(&u1, "dupname"); s->user_create(s, &u1);
    user_t u2; fill_user(&u2, "dupname");
    ASSERT_INT_EQUAL(s->user_create(s, &u2), SSO_ERR_ALREADY_EXISTS);

    role_t r1; fill_role(&r1, "duprole"); s->role_create(s, &r1);
    role_t r2; fill_role(&r2, "duprole");
    ASSERT_INT_EQUAL(s->role_create(s, &r2), SSO_ERR_ALREADY_EXISTS);

    group_t g1; fill_group(&g1, "dupg"); s->group_create(s, &g1);
    group_t g2; fill_group(&g2, "dupg");
    ASSERT_INT_EQUAL(s->group_create(s, &g2), SSO_ERR_ALREADY_EXISTS);
    return 0;
}

static const char *test_generic_refresh_tokens(storage_backend_t *s) {
    printf("    Running refresh_tokens...\n");
    refresh_token_t rt;
    memset(&rt, 0, sizeof(rt));
    strcpy(rt.token_hash, "test_rt_hash");
    rt.user_id = 1;
    strcpy(rt.client_id, "test_client");
    rt.expires_at = sso_timestamp_now() + 3600;
    rt.issued_at = sso_timestamp_now();
    rt.revoked = 0;

    ASSERT_INT_EQUAL(s->refresh_token_create(s, &rt), SSO_OK);

    refresh_token_t fetched;
    ASSERT_INT_EQUAL(s->refresh_token_get(s, "test_rt_hash", &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.token_hash, "test_rt_hash");
    ASSERT_INT_EQUAL(fetched.revoked, 0);

    ASSERT_INT_EQUAL(s->refresh_token_revoke(s, "test_rt_hash"), SSO_OK);
    ASSERT_INT_EQUAL(s->refresh_token_get(s, "test_rt_hash", &fetched), SSO_OK);
    ASSERT_INT_EQUAL(fetched.revoked, 1);
    return 0;
}

static const char *test_generic_revoked_jtis(storage_backend_t *s) {
    printf("    Running revoked_jtis...\n");
    const char *jti = "test_jti_uuid_12345";
    sso_timestamp_t expiry = sso_timestamp_now() + 10000;

    ASSERT_TRUE(!s->jti_is_revoked(s, jti));
    ASSERT_INT_EQUAL(s->jti_revoke(s, jti, expiry), SSO_OK);
    ASSERT_TRUE(s->jti_is_revoked(s, jti));

    const char *jti_expired = "test_jti_expired";
    sso_timestamp_t expired_time = sso_timestamp_now() - 1000;
    ASSERT_INT_EQUAL(s->jti_revoke(s, jti_expired, expired_time), SSO_OK);
    ASSERT_TRUE(!s->jti_is_revoked(s, jti_expired));
    return 0;
}

static const char *test_generic_oauth_clients(storage_backend_t *s) {
    printf("    Running oauth_clients...\n");
    oauth_client_t client;
    memset(&client, 0, sizeof(client));
    strcpy(client.client_id, "generic_client");
    strcpy(client.client_secret_hash, "secret_hash");
    strcpy(client.redirect_uris, "http://localhost/callback");
    client.status = 1;

    ASSERT_INT_EQUAL(s->oauth_client_create(s, &client), SSO_OK);
    ASSERT_TRUE(client.id > 0);

    oauth_client_t fetched;
    ASSERT_INT_EQUAL(s->oauth_client_get(s, "generic_client", &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.client_id, "generic_client");

    fetched.token_ttl_ms = 7200000;
    ASSERT_INT_EQUAL(s->oauth_client_update(s, &fetched), SSO_OK);

    oauth_client_t fetched2;
    ASSERT_INT_EQUAL(s->oauth_client_get(s, "generic_client", &fetched2), SSO_OK);
    ASSERT_INT_EQUAL(fetched2.token_ttl_ms, 7200000);

    ASSERT_INT_EQUAL(s->oauth_client_delete(s, "generic_client"), SSO_OK);
    ASSERT_INT_EQUAL(s->oauth_client_get(s, "generic_client", &fetched), SSO_ERR_NOT_FOUND);
    return 0;
}

static const char *run_storage_suite(storage_backend_t *s, const char *dsn) {
    printf("Testing backend: %s (DSN: %s)\n", s->name, dsn ? dsn : "NULL");
    ASSERT_INT_EQUAL(s->open(s, dsn), SSO_OK);

    mu_run_test_arg(test_generic_user_crud, s);
    mu_run_test_arg(test_generic_role_crud, s);
    mu_run_test_arg(test_generic_group_crud, s);
    mu_run_test_arg(test_generic_assignments, s);
    mu_run_test_arg(test_generic_not_found, s);
    mu_run_test_arg(test_generic_duplicate, s);
    mu_run_test_arg(test_generic_refresh_tokens, s);
    mu_run_test_arg(test_generic_revoked_jtis, s);
    mu_run_test_arg(test_generic_oauth_clients, s);

    s->close(s);
    return 0;
}

/* ==================== Main ==================== */

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    storage_backend_t *s;
    const char *result;

    /* Test Memory Backend */
    storage_memory_create(&s);
    result = run_storage_suite(s, NULL);
    free(s);
    if (result != 0) return 1;

    /* Test SQLite Backend */
    storage_sqlite_create(&s);
    result = run_storage_suite(s, ":memory:");
    free(s);
    if (result != 0) return 1;

    /* Test PostgreSQL Backend if URL provided */
    const char *pg_url = getenv("SSO_TEST_PG_URL");
    if (pg_url) {
        storage_postgres_create(&s);
        result = run_storage_suite(s, pg_url);
        free(s);
        if (result != 0) return 1;
    } else {
        printf("Skipping PostgreSQL tests (SSO_TEST_PG_URL not set)\n");
    }

    printf("\nALL STORAGE TESTS PASSED\n");
    printf("Tests run: %d\n", tests_run);
    return 0;
}
