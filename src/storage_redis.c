#include "storage.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

/*
 * storage_redis.c — Redis storage backend (skeleton).
 *
 * All operations return SSO_ERR_NOT_IMPLEMENTED.
 * This file provides the vtable stub so that the storage backend selection
 * in main.c can recognise "redis" as a valid database_type.  A full
 * implementation must fill every function pointer with real Redis commands
 * via libhiredis.
 */

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

static sso_error_t redis_open(storage_backend_t *self, const char *dsn) {
    (void)self; (void)dsn;
    LOG_WARN("[storage_redis] open() not implemented");
    return SSO_ERR_NOT_IMPLEMENTED;
}

static void redis_close(storage_backend_t *self) {
    (void)self;
}

static sso_error_t redis_begin(storage_backend_t *self) {
    (void)self;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_commit(storage_backend_t *self) {
    (void)self;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_rollback(storage_backend_t *self) {
    (void)self;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static void redis_thread_init(storage_backend_t *self) {
    (void)self;
}

static void redis_thread_cleanup(storage_backend_t *self) {
    (void)self;
}

/* ========================================================================
 * User CRUD
 * ======================================================================== */

static sso_error_t redis_user_create(storage_backend_t *self, user_t *user) {
    (void)self; (void)user;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_user_get_by_id(storage_backend_t *self, sso_id_t id, user_t *user) {
    (void)self; (void)id; (void)user;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_user_get_by_name(storage_backend_t *self, const char *name, user_t *user) {
    (void)self; (void)name; (void)user;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_user_get_by_phone(storage_backend_t *self, const char *phone, user_t *user) {
    (void)self; (void)phone; (void)user;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_user_update(storage_backend_t *self, const user_t *user) {
    (void)self; (void)user;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_user_delete(storage_backend_t *self, sso_id_t id) {
    (void)self; (void)id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_user_list(storage_backend_t *self, const char *q, int status,
                                   int offset, int limit, sso_id_t *ids,
                                   size_t *count, size_t *total_count) {
    (void)self; (void)q; (void)status; (void)offset; (void)limit;
    (void)ids; (void)count; (void)total_count;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * SMS code storage
 * ======================================================================== */

static sso_error_t redis_save_sms_code(storage_backend_t *self, const char *phone,
                                       const char *code, sso_timestamp_t expires_at) {
    (void)self; (void)phone; (void)code; (void)expires_at;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_sms_code(storage_backend_t *self, const char *phone, char *code_out) {
    (void)self; (void)phone; (void)code_out;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_delete_sms_code(storage_backend_t *self, const char *phone) {
    (void)self; (void)phone;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * Role CRUD
 * ======================================================================== */

static sso_error_t redis_role_create(storage_backend_t *self, role_t *role) {
    (void)self; (void)role;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_role_get_by_id(storage_backend_t *self, sso_id_t id, role_t *role) {
    (void)self; (void)id; (void)role;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_role_get_by_name(storage_backend_t *self, const char *name, role_t *role) {
    (void)self; (void)name; (void)role;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_role_update(storage_backend_t *self, const role_t *role) {
    (void)self; (void)role;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_role_delete(storage_backend_t *self, sso_id_t id) {
    (void)self; (void)id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_role_list(storage_backend_t *self, const char *q, int status,
                                   int offset, int limit, sso_id_t *ids,
                                   size_t *count, size_t *total_count) {
    (void)self; (void)q; (void)status; (void)offset; (void)limit;
    (void)ids; (void)count; (void)total_count;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * Group CRUD
 * ======================================================================== */

static sso_error_t redis_group_create(storage_backend_t *self, group_t *group) {
    (void)self; (void)group;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_group_get_by_id(storage_backend_t *self, sso_id_t id, group_t *group) {
    (void)self; (void)id; (void)group;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_group_get_by_name(storage_backend_t *self, const char *name, group_t *group) {
    (void)self; (void)name; (void)group;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_group_update(storage_backend_t *self, const group_t *group) {
    (void)self; (void)group;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_group_delete(storage_backend_t *self, sso_id_t id) {
    (void)self; (void)id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_group_list(storage_backend_t *self, const char *q, int status,
                                    int offset, int limit, sso_id_t *ids,
                                    size_t *count, size_t *total_count) {
    (void)self; (void)q; (void)status; (void)offset; (void)limit;
    (void)ids; (void)count; (void)total_count;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * Policy CRUD
 * ======================================================================== */

static sso_error_t redis_policy_create(storage_backend_t *self, policy_t *policy) {
    (void)self; (void)policy;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_policy_get_by_id(storage_backend_t *self, sso_id_t id, policy_t *policy) {
    (void)self; (void)id; (void)policy;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_policy_get_by_name(storage_backend_t *self, const char *name, policy_t *policy) {
    (void)self; (void)name; (void)policy;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_policy_update(storage_backend_t *self, const policy_t *policy) {
    (void)self; (void)policy;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_policy_delete(storage_backend_t *self, sso_id_t id) {
    (void)self; (void)id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_policy_list(storage_backend_t *self, const char *q, int status,
                                     int offset, int limit, sso_id_t *ids,
                                     size_t *count, size_t *total_count) {
    (void)self; (void)q; (void)status; (void)offset; (void)limit;
    (void)ids; (void)count; (void)total_count;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * Assignment helpers
 * ======================================================================== */

static sso_error_t redis_assign_role_to_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    (void)self; (void)role_id; (void)user_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_unassign_role_from_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    (void)self; (void)role_id; (void)user_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_user_roles(storage_backend_t *self, sso_id_t user_id,
                                        sso_id_t *role_ids, size_t *count, size_t max) {
    (void)self; (void)user_id; (void)role_ids; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_role_users(storage_backend_t *self, sso_id_t role_id,
                                        sso_id_t *user_ids, size_t *count, size_t max) {
    (void)self; (void)role_id; (void)user_ids; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_assign_role_to_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    (void)self; (void)role_id; (void)group_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_unassign_role_from_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    (void)self; (void)role_id; (void)group_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_add_user_to_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    (void)self; (void)group_id; (void)user_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_remove_user_from_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    (void)self; (void)group_id; (void)user_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_user_groups(storage_backend_t *self, sso_id_t user_id,
                                         sso_id_t *group_ids, size_t *count, size_t max) {
    (void)self; (void)user_id; (void)group_ids; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_group_users(storage_backend_t *self, sso_id_t group_id,
                                         sso_id_t *user_ids, size_t *count, size_t max) {
    (void)self; (void)group_id; (void)user_ids; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_assign_policy(storage_backend_t *self, sso_id_t policy_id,
                                       policy_target_type_t target_type, sso_id_t target_id) {
    (void)self; (void)policy_id; (void)target_type; (void)target_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_unassign_policy(storage_backend_t *self, sso_id_t policy_id,
                                         policy_target_type_t target_type, sso_id_t target_id) {
    (void)self; (void)policy_id; (void)target_type; (void)target_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_policy_targets(storage_backend_t *self, sso_id_t policy_id,
                                            policy_target_type_t target_type,
                                            sso_id_t *target_ids, size_t *count, size_t max) {
    (void)self; (void)policy_id; (void)target_type; (void)target_ids; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_target_policies(storage_backend_t *self,
                                             policy_target_type_t target_type, sso_id_t target_id,
                                             sso_id_t *policy_ids, size_t *count, size_t max) {
    (void)self; (void)target_type; (void)target_id; (void)policy_ids; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * Hierarchy helpers
 * ======================================================================== */

static sso_error_t redis_role_get_parent(storage_backend_t *self, sso_id_t role_id, sso_id_t *parent_id) {
    (void)self; (void)role_id; (void)parent_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_group_get_parent(storage_backend_t *self, sso_id_t group_id, sso_id_t *parent_id) {
    (void)self; (void)group_id; (void)parent_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_get_user_roles_with_ancestors(storage_backend_t *self, sso_id_t user_id,
                                                        sso_id_t *role_ids, size_t *count, size_t max) {
    (void)self; (void)user_id; (void)role_ids; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * OAuth authorization codes
 * ======================================================================== */

static sso_error_t redis_oauth_code_create(storage_backend_t *self, const oauth_auth_code_t *code) {
    (void)self; (void)code;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_oauth_code_get(storage_backend_t *self, const char *code, oauth_auth_code_t *out) {
    (void)self; (void)code; (void)out;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_oauth_code_mark_used(storage_backend_t *self, const char *code) {
    (void)self; (void)code;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_oauth_code_cleanup(storage_backend_t *self) {
    (void)self;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * OAuth client CRUD
 * ======================================================================== */

static sso_error_t redis_oauth_client_create(storage_backend_t *self, oauth_client_t *client) {
    (void)self; (void)client;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_oauth_client_get(storage_backend_t *self, const char *client_id, oauth_client_t *client) {
    (void)self; (void)client_id; (void)client;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_oauth_client_update(storage_backend_t *self, const oauth_client_t *client) {
    (void)self; (void)client;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_oauth_client_delete(storage_backend_t *self, const char *client_id) {
    (void)self; (void)client_id;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_oauth_client_list(storage_backend_t *self, int offset, int limit,
                                            oauth_client_t *clients, size_t *count, size_t max) {
    (void)self; (void)offset; (void)limit; (void)clients; (void)count; (void)max;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * Refresh tokens
 * ======================================================================== */

static sso_error_t redis_refresh_token_create(storage_backend_t *self, const refresh_token_t *rt) {
    (void)self; (void)rt;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_refresh_token_get(storage_backend_t *self, const char *token_hash, refresh_token_t *out) {
    (void)self; (void)token_hash; (void)out;
    return SSO_ERR_NOT_IMPLEMENTED;
}

static sso_error_t redis_refresh_token_revoke(storage_backend_t *self, const char *token_hash) {
    (void)self; (void)token_hash;
    return SSO_ERR_NOT_IMPLEMENTED;
}

/* ========================================================================
 * Vtable setup
 * ======================================================================== */

sso_error_t storage_redis_create(storage_backend_t **backend) {
    if (!backend) return SSO_ERR_INVALID_PARAM;

    *backend = (storage_backend_t *)calloc(1, sizeof(storage_backend_t));
    if (!*backend) return SSO_ERR_OUT_OF_MEMORY;

    strncpy((*backend)->name, "redis", sizeof((*backend)->name) - 1);
    (*backend)->name[sizeof((*backend)->name) - 1] = '\0';

    /* Lifecycle */
    (*backend)->open            = redis_open;
    (*backend)->close           = redis_close;
    (*backend)->begin           = redis_begin;
    (*backend)->commit          = redis_commit;
    (*backend)->rollback        = redis_rollback;
    (*backend)->thread_init     = redis_thread_init;
    (*backend)->thread_cleanup  = redis_thread_cleanup;

    /* User */
    (*backend)->user_create         = redis_user_create;
    (*backend)->user_get_by_id      = redis_user_get_by_id;
    (*backend)->user_get_by_name    = redis_user_get_by_name;
    (*backend)->user_get_by_phone   = redis_user_get_by_phone;
    (*backend)->user_update         = redis_user_update;
    (*backend)->user_delete         = redis_user_delete;
    (*backend)->user_list           = redis_user_list;

    /* SMS */
    (*backend)->save_sms_code       = redis_save_sms_code;
    (*backend)->get_sms_code        = redis_get_sms_code;
    (*backend)->delete_sms_code     = redis_delete_sms_code;

    /* Role */
    (*backend)->role_create         = redis_role_create;
    (*backend)->role_get_by_id      = redis_role_get_by_id;
    (*backend)->role_get_by_name    = redis_role_get_by_name;
    (*backend)->role_update         = redis_role_update;
    (*backend)->role_delete         = redis_role_delete;
    (*backend)->role_list           = redis_role_list;

    /* Group */
    (*backend)->group_create        = redis_group_create;
    (*backend)->group_get_by_id     = redis_group_get_by_id;
    (*backend)->group_get_by_name   = redis_group_get_by_name;
    (*backend)->group_update        = redis_group_update;
    (*backend)->group_delete        = redis_group_delete;
    (*backend)->group_list          = redis_group_list;

    /* Policy */
    (*backend)->policy_create       = redis_policy_create;
    (*backend)->policy_get_by_id    = redis_policy_get_by_id;
    (*backend)->policy_get_by_name  = redis_policy_get_by_name;
    (*backend)->policy_update       = redis_policy_update;
    (*backend)->policy_delete       = redis_policy_delete;
    (*backend)->policy_list         = redis_policy_list;

    /* Assignments */
    (*backend)->assign_role_to_user         = redis_assign_role_to_user;
    (*backend)->unassign_role_from_user     = redis_unassign_role_from_user;
    (*backend)->get_user_roles              = redis_get_user_roles;
    (*backend)->get_role_users              = redis_get_role_users;
    (*backend)->assign_role_to_group        = redis_assign_role_to_group;
    (*backend)->unassign_role_from_group    = redis_unassign_role_from_group;
    (*backend)->add_user_to_group           = redis_add_user_to_group;
    (*backend)->remove_user_from_group      = redis_remove_user_from_group;
    (*backend)->get_user_groups             = redis_get_user_groups;
    (*backend)->get_group_users             = redis_get_group_users;
    (*backend)->assign_policy               = redis_assign_policy;
    (*backend)->unassign_policy             = redis_unassign_policy;
    (*backend)->get_policy_targets          = redis_get_policy_targets;
    (*backend)->get_target_policies         = redis_get_target_policies;

    /* Hierarchy */
    (*backend)->role_get_parent              = redis_role_get_parent;
    (*backend)->group_get_parent             = redis_group_get_parent;
    (*backend)->get_user_roles_with_ancestors = redis_get_user_roles_with_ancestors;

    /* OAuth codes */
    (*backend)->oauth_code_create   = redis_oauth_code_create;
    (*backend)->oauth_code_get      = redis_oauth_code_get;
    (*backend)->oauth_code_mark_used = redis_oauth_code_mark_used;
    (*backend)->oauth_code_cleanup  = redis_oauth_code_cleanup;

    /* OAuth clients */
    (*backend)->oauth_client_create = redis_oauth_client_create;
    (*backend)->oauth_client_get    = redis_oauth_client_get;
    (*backend)->oauth_client_update = redis_oauth_client_update;
    (*backend)->oauth_client_delete = redis_oauth_client_delete;
    (*backend)->oauth_client_list   = redis_oauth_client_list;

    /* Refresh tokens */
    (*backend)->refresh_token_create = redis_refresh_token_create;
    (*backend)->refresh_token_get    = redis_refresh_token_get;
    (*backend)->refresh_token_revoke = redis_refresh_token_revoke;

    (*backend)->handle = NULL;

    return SSO_OK;
}
