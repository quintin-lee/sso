/*
 * storage.h — Storage abstraction layer.
 *
 * Defines the storage_backend interface.  Concrete implementations
 * (SQLite, file-based, in-memory) fill this vtable.
 *
 * This makes the SSO system storage-agnostic — you can swap the backend
 * without changing any business logic.
 */

#ifndef SSO_STORAGE_H
#define SSO_STORAGE_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Storage backend — pure virtual table of function pointers.
 *
 * Every function returns SSO_OK on success or an error code on failure.
 * ======================================================================== */
typedef sso_error_t (*storage_open_fn)(storage_backend_t *self, const char *dsn);
typedef void        (*storage_close_fn)(storage_backend_t *self);
typedef sso_error_t (*storage_begin_fn)(storage_backend_t *self);
typedef sso_error_t (*storage_commit_fn)(storage_backend_t *self);
typedef sso_error_t (*storage_rollback_fn)(storage_backend_t *self);
typedef void        (*storage_thread_init_fn)(storage_backend_t *self);
typedef void        (*storage_thread_cleanup_fn)(storage_backend_t *self);

/* User CRUD — create writes back the assigned id */
typedef sso_error_t (*storage_user_create_fn)(storage_backend_t *self, user_t *user);
typedef sso_error_t (*storage_user_get_by_id_fn)(storage_backend_t *self, sso_id_t id, user_t *user);
typedef sso_error_t (*storage_user_get_by_name_fn)(storage_backend_t *self, const char *name, user_t *user);
typedef sso_error_t (*storage_user_get_by_phone_fn)(storage_backend_t *self, const char *phone, user_t *user);
typedef sso_error_t (*storage_user_update_fn)(storage_backend_t *self, const user_t *user);
typedef sso_error_t (*storage_user_delete_fn)(storage_backend_t *self, sso_id_t id);
typedef sso_error_t (*storage_user_list_fn)(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count);

/* SMS */
typedef sso_error_t (*storage_save_sms_code_fn)(storage_backend_t *self, const char *phone, const char *code, sso_timestamp_t expires_at);
typedef sso_error_t (*storage_get_sms_code_fn)(storage_backend_t *self, const char *phone, char *code_out);
typedef sso_error_t (*storage_delete_sms_code_fn)(storage_backend_t *self, const char *phone);

/* Role CRUD */
typedef sso_error_t (*storage_role_create_fn)(storage_backend_t *self, role_t *role);
typedef sso_error_t (*storage_role_get_by_id_fn)(storage_backend_t *self, sso_id_t id, role_t *role);
typedef sso_error_t (*storage_role_get_by_name_fn)(storage_backend_t *self, const char *name, role_t *role);
typedef sso_error_t (*storage_role_update_fn)(storage_backend_t *self, const role_t *role);
typedef sso_error_t (*storage_role_delete_fn)(storage_backend_t *self, sso_id_t id);
typedef sso_error_t (*storage_role_list_fn)(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count);

/* Group CRUD */
typedef sso_error_t (*storage_group_create_fn)(storage_backend_t *self, group_t *group);
typedef sso_error_t (*storage_group_get_by_id_fn)(storage_backend_t *self, sso_id_t id, group_t *group);
typedef sso_error_t (*storage_group_get_by_name_fn)(storage_backend_t *self, const char *name, group_t *group);
typedef sso_error_t (*storage_group_update_fn)(storage_backend_t *self, const group_t *group);
typedef sso_error_t (*storage_group_delete_fn)(storage_backend_t *self, sso_id_t id);
typedef sso_error_t (*storage_group_list_fn)(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count);

/* Policy CRUD */
typedef sso_error_t (*storage_policy_create_fn)(storage_backend_t *self, policy_t *policy);
typedef sso_error_t (*storage_policy_get_by_id_fn)(storage_backend_t *self, sso_id_t id, policy_t *policy);
typedef sso_error_t (*storage_policy_get_by_name_fn)(storage_backend_t *self, const char *name, policy_t *policy);
typedef sso_error_t (*storage_policy_update_fn)(storage_backend_t *self, const policy_t *policy);
typedef sso_error_t (*storage_policy_delete_fn)(storage_backend_t *self, sso_id_t id);
typedef sso_error_t (*storage_policy_list_fn)(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count);

/* Assignment tables */
typedef sso_error_t (*storage_assign_role_user_fn)(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id);
typedef sso_error_t (*storage_unassign_role_user_fn)(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id);
typedef sso_error_t (*storage_get_user_roles_fn)(storage_backend_t *self, sso_id_t user_id, sso_id_t *role_ids, size_t *count, size_t max);
typedef sso_error_t (*storage_get_role_users_fn)(storage_backend_t *self, sso_id_t role_id, sso_id_t *user_ids, size_t *count, size_t max);

typedef sso_error_t (*storage_assign_role_group_fn)(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id);
typedef sso_error_t (*storage_unassign_role_group_fn)(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id);

typedef sso_error_t (*storage_add_user_group_fn)(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id);
typedef sso_error_t (*storage_remove_user_group_fn)(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id);
typedef sso_error_t (*storage_get_user_groups_fn)(storage_backend_t *self, sso_id_t user_id, sso_id_t *group_ids, size_t *count, size_t max);
typedef sso_error_t (*storage_get_group_users_fn)(storage_backend_t *self, sso_id_t group_id, sso_id_t *user_ids, size_t *count, size_t max);

typedef sso_error_t (*storage_assign_policy_fn)(storage_backend_t *self, sso_id_t policy_id,
                                                policy_target_type_t target_type, sso_id_t target_id);
typedef sso_error_t (*storage_unassign_policy_fn)(storage_backend_t *self, sso_id_t policy_id,
                                                  policy_target_type_t target_type, sso_id_t target_id);
typedef sso_error_t (*storage_get_policy_targets_fn)(storage_backend_t *self, sso_id_t policy_id,
                                                     policy_target_type_t target_type,
                                                     sso_id_t *target_ids, size_t *count, size_t max);
typedef sso_error_t (*storage_get_target_policies_fn)(storage_backend_t *self,
                                                      policy_target_type_t target_type, sso_id_t target_id,
                                                      sso_id_t *policy_ids, size_t *count, size_t max);

/* Role / Group hierarchy helpers */
typedef sso_error_t (*storage_role_get_parent_fn)(storage_backend_t *self, sso_id_t role_id, sso_id_t *parent_id);
typedef sso_error_t (*storage_group_get_parent_fn)(storage_backend_t *self, sso_id_t group_id, sso_id_t *parent_id);

/* Efficient bulk query: get all role IDs for a user (direct + inherited via hierarchy)
 * in a single operation.  Returns SSO_ERR_NOT_FOUND if no roles found. */
typedef sso_error_t (*storage_get_user_roles_with_ancestors_fn)(storage_backend_t *self,
                                                                 sso_id_t user_id,
                                                                 sso_id_t *role_ids,
                                                                 size_t *count, size_t max);

typedef struct {
    char token_hash[128];
    sso_id_t user_id;
    char client_id[64];
    sso_timestamp_t expires_at;
    sso_timestamp_t issued_at;
    int revoked;
} refresh_token_t;

typedef sso_error_t (*storage_refresh_token_create_fn)(storage_backend_t *self, const refresh_token_t *rt);
typedef sso_error_t (*storage_refresh_token_get_fn)(storage_backend_t *self, const char *token_hash, refresh_token_t *out);
typedef sso_error_t (*storage_refresh_token_revoke_fn)(storage_backend_t *self, const char *token_hash);

typedef sso_error_t (*storage_jti_revoke_fn)(storage_backend_t *self, const char *jti, sso_timestamp_t expires_at);
typedef bool (*storage_jti_is_revoked_fn)(storage_backend_t *self, const char *jti);

/* OAuth authorization code */
typedef struct {
    char              code[128];
    char              client_id[64];
    sso_id_t          user_id;
    char              redirect_uri[512];
    char              scope[256];
    char              nonce[128];
    char              code_challenge[256];
    char              code_challenge_method[16];
    sso_timestamp_t   expires_at;
    int               used;      /* 0 = unused, 1 = consumed */
} oauth_auth_code_t;

typedef sso_error_t (*storage_oauth_code_create_fn)(storage_backend_t *self, const oauth_auth_code_t *code);
typedef sso_error_t (*storage_oauth_code_get_fn)(storage_backend_t *self, const char *code, oauth_auth_code_t *out);
typedef sso_error_t (*storage_oauth_code_mark_used_fn)(storage_backend_t *self, const char *code);
typedef sso_error_t (*storage_oauth_code_cleanup_fn)(storage_backend_t *self);

typedef struct {
    sso_id_t id;
    char client_id[64];
    char client_secret_hash[128];
    char redirect_uris[512];
    char app_name[128];
    char app_description[256];
    char app_logo_url[256];
    char allowed_scopes[256];
    char allowed_grant_types[128];
    long token_ttl_ms;
    int status;
    sso_timestamp_t created_at;
    sso_timestamp_t updated_at;
} oauth_client_t;

typedef sso_error_t (*storage_oauth_client_create_fn)(storage_backend_t *self, oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_get_fn)(storage_backend_t *self, const char *client_id, oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_update_fn)(storage_backend_t *self, const oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_delete_fn)(storage_backend_t *self, const char *client_id);
typedef sso_error_t (*storage_oauth_client_list_fn)(storage_backend_t *self, int offset, int limit, oauth_client_t *clients, size_t *count, size_t max);

/* ========================================================================
 * Storage backend struct — concrete implementations fill these pointers.
 * ======================================================================== */
struct storage_backend {
    /* Metadata */
    char name[32];

    /* Lifecycle */
    storage_open_fn                 open;
    storage_close_fn                close;
    storage_begin_fn                begin;
    storage_commit_fn               commit;
    storage_rollback_fn             rollback;
    storage_thread_init_fn          thread_init;
    storage_thread_cleanup_fn       thread_cleanup;

    /* User */
    storage_user_create_fn          user_create;
    storage_user_get_by_id_fn       user_get_by_id;
    storage_user_get_by_name_fn     user_get_by_name;
    storage_user_get_by_phone_fn    user_get_by_phone;
    storage_user_update_fn          user_update;
    storage_user_delete_fn          user_delete;
    storage_user_list_fn            user_list;

    /* SMS */
    storage_save_sms_code_fn        save_sms_code;
    storage_get_sms_code_fn         get_sms_code;
    storage_delete_sms_code_fn      delete_sms_code;

    /* Role */
    storage_role_create_fn          role_create;
    storage_role_get_by_id_fn       role_get_by_id;
    storage_role_get_by_name_fn     role_get_by_name;
    storage_role_update_fn          role_update;
    storage_role_delete_fn          role_delete;
    storage_role_list_fn            role_list;

    /* Group */
    storage_group_create_fn         group_create;
    storage_group_get_by_id_fn      group_get_by_id;
    storage_group_get_by_name_fn    group_get_by_name;
    storage_group_update_fn         group_update;
    storage_group_delete_fn         group_delete;
    storage_group_list_fn           group_list;

    /* Policy */
    storage_policy_create_fn        policy_create;
    storage_policy_get_by_id_fn     policy_get_by_id;
    storage_policy_get_by_name_fn   policy_get_by_name;
    storage_policy_update_fn        policy_update;
    storage_policy_delete_fn        policy_delete;
    storage_policy_list_fn          policy_list;

    /* Assignments */
    storage_assign_role_user_fn         assign_role_to_user;
    storage_unassign_role_user_fn       unassign_role_from_user;
    storage_get_user_roles_fn           get_user_roles;
    storage_get_role_users_fn           get_role_users;

    storage_assign_role_group_fn        assign_role_to_group;
    storage_unassign_role_group_fn      unassign_role_from_group;

    storage_add_user_group_fn           add_user_to_group;
    storage_remove_user_group_fn        remove_user_from_group;
    storage_get_user_groups_fn          get_user_groups;
    storage_get_group_users_fn          get_group_users;

    storage_assign_policy_fn            assign_policy;
    storage_unassign_policy_fn          unassign_policy;
    storage_get_policy_targets_fn       get_policy_targets;
    storage_get_target_policies_fn      get_target_policies;

    /* Hierarchy */
    storage_role_get_parent_fn                  role_get_parent;
    storage_group_get_parent_fn                 group_get_parent;
    storage_get_user_roles_with_ancestors_fn    get_user_roles_with_ancestors;

    /* OAuth authorization codes */
    storage_oauth_code_create_fn      oauth_code_create;
    storage_oauth_code_get_fn         oauth_code_get;
    storage_oauth_code_mark_used_fn   oauth_code_mark_used;
    storage_oauth_code_cleanup_fn     oauth_code_cleanup;

    storage_oauth_client_create_fn    oauth_client_create;
    storage_oauth_client_get_fn       oauth_client_get;
    storage_oauth_client_update_fn    oauth_client_update;
    storage_oauth_client_delete_fn    oauth_client_delete;
    storage_oauth_client_list_fn      oauth_client_list;

    storage_refresh_token_create_fn refresh_token_create;
    storage_refresh_token_get_fn    refresh_token_get;
    storage_refresh_token_revoke_fn refresh_token_revoke;

    storage_jti_revoke_fn           jti_revoke;
    storage_jti_is_revoked_fn       jti_is_revoked;

    /* Opaque backend-private data (e.g. sqlite3*, FILE*, hashtable*) */
    void *handle;
};

/* -----------------------------------------------------------------------
 * Built-in storage backends (declared here, defined in src/).
 * ----------------------------------------------------------------------- */

/* SQLite3 backend — requires libsqlite3 at link time. */
sso_error_t storage_sqlite_create(storage_backend_t **backend);

/* In-memory backend (volatile, useful for testing). */
sso_error_t storage_memory_create(storage_backend_t **backend);

/* PostgreSQL backend — requires libpq at link time. */
sso_error_t storage_postgres_create(storage_backend_t **backend);

/* Redis backend — requires libhiredis at link time (skeleton). */
sso_error_t storage_redis_create(storage_backend_t **backend);

#ifdef __cplusplus
}
#endif

#endif /* SSO_STORAGE_H */
