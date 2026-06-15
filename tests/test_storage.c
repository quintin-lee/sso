#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minunit.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "storage.h"
#include "sso.h"

int tests_run = 0;

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

/* ==================== SQLite Backend Tests ==================== */

static const char *test_sqlite_user_crud() {
    printf("  Running test_sqlite_user_crud...\n");
    storage_backend_t *s;
    ASSERT_INT_EQUAL(storage_sqlite_create(&s), SSO_OK);
    ASSERT_INT_EQUAL(s->open(s, ":memory:"), SSO_OK);

    user_t u;
    fill_user(&u, "sqluser");
    ASSERT_INT_EQUAL(s->user_create(s, &u), SSO_OK);
    ASSERT_TRUE(u.id != SSO_ID_NONE);

    user_t fetched;
    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.username, "sqluser");

    ASSERT_INT_EQUAL(s->user_get_by_name(s, "sqluser", &fetched), SSO_OK);
    ASSERT_INT_EQUAL(fetched.id, u.id);

    strcpy(u.email, "updated@e.com");
    ASSERT_INT_EQUAL(s->user_update(s, &u), SSO_OK);

    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.email, "updated@e.com");

    ASSERT_INT_EQUAL(s->user_delete(s, u.id), SSO_OK);
    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_sqlite_role_crud() {
    printf("  Running test_sqlite_role_crud...\n");
    storage_backend_t *s;
    storage_sqlite_create(&s);
    s->open(s, ":memory:");

    role_t r;
    fill_role(&r, "sqlrole");
    ASSERT_INT_EQUAL(s->role_create(s, &r), SSO_OK);
    ASSERT_TRUE(r.id != SSO_ID_NONE);

    role_t fetched;
    ASSERT_INT_EQUAL(s->role_get_by_id(s, r.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.name, "sqlrole");

    ASSERT_INT_EQUAL(s->role_get_by_name(s, "sqlrole", &fetched), SSO_OK);
    ASSERT_INT_EQUAL(fetched.id, r.id);

    ASSERT_INT_EQUAL(s->role_delete(s, r.id), SSO_OK);
    ASSERT_INT_EQUAL(s->role_get_by_id(s, r.id, &fetched), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_sqlite_group_crud() {
    printf("  Running test_sqlite_group_crud...\n");
    storage_backend_t *s;
    storage_sqlite_create(&s);
    s->open(s, ":memory:");

    group_t g;
    fill_group(&g, "sqlgroup");
    ASSERT_INT_EQUAL(s->group_create(s, &g), SSO_OK);
    ASSERT_TRUE(g.id != SSO_ID_NONE);

    group_t fetched;
    ASSERT_INT_EQUAL(s->group_get_by_id(s, g.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.name, "sqlgroup");

    ASSERT_INT_EQUAL(s->group_delete(s, g.id), SSO_OK);
    ASSERT_INT_EQUAL(s->group_get_by_id(s, g.id, &fetched), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_sqlite_assignments() {
    printf("  Running test_sqlite_assignments...\n");
    storage_backend_t *s;
    storage_sqlite_create(&s);
    s->open(s, ":memory:");

    user_t u; fill_user(&u, "assignuser"); s->user_create(s, &u);
    role_t r; fill_role(&r, "assignrole"); s->role_create(s, &r);
    group_t g; fill_group(&g, "assigngroup"); s->group_create(s, &g);

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

    s->close(s);
    free(s);
    return 0;
}

static const char *test_sqlite_not_found() {
    printf("  Running test_sqlite_not_found...\n");
    storage_backend_t *s;
    storage_sqlite_create(&s);
    s->open(s, ":memory:");

    user_t u;
    ASSERT_INT_EQUAL(s->user_get_by_id(s, 99999, &u), SSO_ERR_NOT_FOUND);
    ASSERT_INT_EQUAL(s->user_get_by_name(s, "nobody", &u), SSO_ERR_NOT_FOUND);

    role_t r;
    ASSERT_INT_EQUAL(s->role_get_by_id(s, 99999, &r), SSO_ERR_NOT_FOUND);

    group_t g;
    ASSERT_INT_EQUAL(s->group_get_by_id(s, 99999, &g), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_sqlite_duplicate() {
    printf("  Running test_sqlite_duplicate...\n");
    storage_backend_t *s;
    storage_sqlite_create(&s);
    s->open(s, ":memory:");

    user_t u1; fill_user(&u1, "dupname"); s->user_create(s, &u1);
    user_t u2; fill_user(&u2, "dupname");
    ASSERT_INT_EQUAL(s->user_create(s, &u2), SSO_ERR_ALREADY_EXISTS);

    role_t r1; fill_role(&r1, "duprole"); s->role_create(s, &r1);
    role_t r2; fill_role(&r2, "duprole");
    ASSERT_INT_EQUAL(s->role_create(s, &r2), SSO_ERR_ALREADY_EXISTS);

    group_t g1; fill_group(&g1, "dupg"); s->group_create(s, &g1);
    group_t g2; fill_group(&g2, "dupg");
    ASSERT_INT_EQUAL(s->group_create(s, &g2), SSO_ERR_ALREADY_EXISTS);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_memory_user_crud() {
    printf("  Running test_memory_user_crud...\n");
    storage_backend_t *s;
    ASSERT_INT_EQUAL(storage_memory_create(&s), SSO_OK);
    s->open(s, NULL);

    user_t u;
    fill_user(&u, "memuser");
    ASSERT_INT_EQUAL(s->user_create(s, &u), SSO_OK);
    ASSERT_TRUE(u.id != SSO_ID_NONE);

    user_t fetched;
    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.username, "memuser");

    strcpy(u.email, "mem-updated@e.com");
    ASSERT_INT_EQUAL(s->user_update(s, &u), SSO_OK);

    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.email, "mem-updated@e.com");

    ASSERT_INT_EQUAL(s->user_delete(s, u.id), SSO_OK);
    ASSERT_INT_EQUAL(s->user_get_by_id(s, u.id, &fetched), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_memory_role_crud() {
    printf("  Running test_memory_role_crud...\n");
    storage_backend_t *s;
    storage_memory_create(&s);
    s->open(s, NULL);

    role_t r;
    fill_role(&r, "memrole");
    ASSERT_INT_EQUAL(s->role_create(s, &r), SSO_OK);
    ASSERT_TRUE(r.id != SSO_ID_NONE);

    role_t fetched;
    ASSERT_INT_EQUAL(s->role_get_by_id(s, r.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.name, "memrole");

    ASSERT_INT_EQUAL(s->role_delete(s, r.id), SSO_OK);
    ASSERT_INT_EQUAL(s->role_get_by_id(s, r.id, &fetched), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_memory_group_crud() {
    printf("  Running test_memory_group_crud...\n");
    storage_backend_t *s;
    storage_memory_create(&s);
    s->open(s, NULL);

    group_t g;
    fill_group(&g, "memgroup");
    ASSERT_INT_EQUAL(s->group_create(s, &g), SSO_OK);
    ASSERT_TRUE(g.id != SSO_ID_NONE);

    group_t fetched;
    ASSERT_INT_EQUAL(s->group_get_by_id(s, g.id, &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.name, "memgroup");

    ASSERT_INT_EQUAL(s->group_delete(s, g.id), SSO_OK);
    ASSERT_INT_EQUAL(s->group_get_by_id(s, g.id, &fetched), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_memory_assignments() {
    printf("  Running test_memory_assignments...\n");
    storage_backend_t *s;
    storage_memory_create(&s);
    s->open(s, NULL);

    user_t u; fill_user(&u, "memassign"); s->user_create(s, &u);
    role_t r; fill_role(&r, "memassignrole"); s->role_create(s, &r);
    group_t g; fill_group(&g, "memassigngroup"); s->group_create(s, &g);

    ASSERT_INT_EQUAL(s->assign_role_to_user(s, r.id, u.id), SSO_OK);
    ASSERT_INT_EQUAL(s->add_user_to_group(s, g.id, u.id), SSO_OK);

    sso_id_t role_ids[10];
    size_t count = 0;
    ASSERT_INT_EQUAL(s->get_user_roles(s, u.id, role_ids, &count, 10), SSO_OK);
    ASSERT_INT_EQUAL(count, 1);
    ASSERT_INT_EQUAL(role_ids[0], r.id);

    ASSERT_INT_EQUAL(s->unassign_role_from_user(s, r.id, u.id), SSO_OK);
    count = 0;
    sso_error_t err_r = s->get_user_roles(s, u.id, role_ids, &count, 10);
    ASSERT_TRUE(err_r == SSO_OK || err_r == SSO_ERR_NOT_FOUND);
    ASSERT_INT_EQUAL(count, 0);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_memory_not_found() {
    printf("  Running test_memory_not_found...\n");
    storage_backend_t *s;
    storage_memory_create(&s);
    s->open(s, NULL);

    user_t u;
    ASSERT_INT_EQUAL(s->user_get_by_id(s, 999, &u), SSO_ERR_NOT_FOUND);

    role_t r;
    ASSERT_INT_EQUAL(s->role_get_by_id(s, 999, &r), SSO_ERR_NOT_FOUND);

    group_t g;
    ASSERT_INT_EQUAL(s->group_get_by_id(s, 999, &g), SSO_ERR_NOT_FOUND);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_oauth_clients() {
    storage_backend_t *sb = NULL;
    mu_assert("storage_sqlite_create failed", storage_sqlite_create(&sb) == SSO_OK);
    mu_assert("storage_open failed", sb->open(sb, "file::memory:?cache=shared") == SSO_OK);

    oauth_client_t client;
    memset(&client, 0, sizeof(client));
    strcpy(client.client_id, "test_client_1");
    strcpy(client.client_secret_hash, "$argon2id$v=19$m=65536,t=2,p=1$abc$def");
    strcpy(client.redirect_uris, "http://localhost/callback");
    client.status = 1;

    mu_assert("oauth_client_create failed", sb->oauth_client_create(sb, &client) == SSO_OK);
    mu_assert("ID assigned", client.id > 0);

    oauth_client_t fetched;
    mu_assert("oauth_client_get failed", sb->oauth_client_get(sb, "test_client_1", &fetched) == SSO_OK);
    mu_assert("client_id mismatch", strcmp(fetched.client_id, "test_client_1") == 0);

    fetched.token_ttl_ms = 7200000;
    mu_assert("oauth_client_update failed", sb->oauth_client_update(sb, &fetched) == SSO_OK);

    oauth_client_t fetched2;
    mu_assert("oauth_client_get failed", sb->oauth_client_get(sb, "test_client_1", &fetched2) == SSO_OK);
    mu_assert("TTL mismatch", fetched2.token_ttl_ms == 7200000);

    mu_assert("oauth_client_delete failed", sb->oauth_client_delete(sb, "test_client_1") == SSO_OK);
    mu_assert("oauth_client_get should fail", sb->oauth_client_get(sb, "test_client_1", &fetched) == SSO_ERR_NOT_FOUND);

    sb->close(sb);
    free(sb);
    return 0;
}

static const char *test_sqlite_refresh_tokens() {
    printf("  Running test_sqlite_refresh_tokens...\n");
    storage_backend_t *s;
    ASSERT_INT_EQUAL(storage_sqlite_create(&s), SSO_OK);
    ASSERT_INT_EQUAL(s->open(s, ":memory:"), SSO_OK);

    refresh_token_t rt;
    memset(&rt, 0, sizeof(rt));
    strcpy(rt.token_hash, "hash123");
    rt.user_id = 1;
    strcpy(rt.client_id, "client1");
    rt.expires_at = sso_timestamp_now() + 3600;
    rt.issued_at = sso_timestamp_now();
    rt.revoked = 0;

    ASSERT_INT_EQUAL(s->refresh_token_create(s, &rt), SSO_OK);

    refresh_token_t fetched;
    ASSERT_INT_EQUAL(s->refresh_token_get(s, "hash123", &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.token_hash, "hash123");
    ASSERT_INT_EQUAL(fetched.user_id, 1);
    ASSERT_INT_EQUAL(fetched.revoked, 0);

    ASSERT_INT_EQUAL(s->refresh_token_revoke(s, "hash123"), SSO_OK);
    ASSERT_INT_EQUAL(s->refresh_token_get(s, "hash123", &fetched), SSO_OK);
    ASSERT_INT_EQUAL(fetched.revoked, 1);

    s->close(s);
    free(s);
    return 0;
}

static const char *test_memory_refresh_tokens() {
    printf("  Running test_memory_refresh_tokens...\n");
    storage_backend_t *s;
    ASSERT_INT_EQUAL(storage_memory_create(&s), SSO_OK);
    ASSERT_INT_EQUAL(s->open(s, NULL), SSO_OK);

    refresh_token_t rt;
    memset(&rt, 0, sizeof(rt));
    strcpy(rt.token_hash, "memhash");
    rt.user_id = 2;
    strcpy(rt.client_id, "client2");
    rt.expires_at = sso_timestamp_now() + 3600;
    rt.issued_at = sso_timestamp_now();
    rt.revoked = 0;

    ASSERT_INT_EQUAL(s->refresh_token_create(s, &rt), SSO_OK);

    refresh_token_t fetched;
    ASSERT_INT_EQUAL(s->refresh_token_get(s, "memhash", &fetched), SSO_OK);
    ASSERT_STR_EQUAL(fetched.token_hash, "memhash");
    ASSERT_INT_EQUAL(fetched.revoked, 0);

    ASSERT_INT_EQUAL(s->refresh_token_revoke(s, "memhash"), SSO_OK);
    ASSERT_INT_EQUAL(s->refresh_token_get(s, "memhash", &fetched), SSO_OK);
    ASSERT_INT_EQUAL(fetched.revoked, 1);

    s->close(s);
    free(s);
    return 0;
}

static const char *all_tests() {
    mu_run_test(test_sqlite_user_crud);
    mu_run_test(test_sqlite_role_crud);
    mu_run_test(test_sqlite_group_crud);
    mu_run_test(test_sqlite_assignments);
    mu_run_test(test_sqlite_not_found);
    mu_run_test(test_sqlite_duplicate);
    mu_run_test(test_sqlite_refresh_tokens);
    mu_run_test(test_memory_user_crud);
    mu_run_test(test_memory_role_crud);
    mu_run_test(test_memory_group_crud);
    mu_run_test(test_memory_assignments);
    mu_run_test(test_memory_not_found);
    mu_run_test(test_memory_refresh_tokens);
    mu_run_test(test_oauth_clients);
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
