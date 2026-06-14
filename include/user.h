/*
 * user.h — User management module.
 *
 * Manages user accounts: creation, authentication, status lifecycle.
 * Users can be assigned roles and be members of groups.
 */

#ifndef SSO_USER_H
#define SSO_USER_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Data structure
 * ======================================================================== */
struct user {
    sso_id_t          id;
    char              username[SSO_MAX_USERNAME];
    char              phone[SSO_MAX_PHONE];
    char              password_hash[SSO_MAX_PASSWORD_HASH];
    char              email[SSO_MAX_EMAIL];
    char              display_name[SSO_MAX_DISPLAY_NAME];
    user_status_t     status;
    sso_timestamp_t   created_at;
    sso_timestamp_t   updated_at;
    char              attributes[SSO_MAX_ATTRIBUTES]; /* extensible JSON */
};

/* ========================================================================
 * User manager (opaque, accessed through sso_context)
 * ======================================================================== */
typedef struct user_manager user_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */
sso_error_t user_manager_create(user_manager_t **mgr, sso_context_t *ctx);
void        user_manager_destroy(user_manager_t *mgr);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */

/* Create a new user.  password is the raw password (will be hashed internally). */
sso_error_t user_create(user_manager_t *mgr, const char *username,
                        const char *password, const char *email,
                        const char *display_name, user_t *out);

/* Create a new user by phone (no password required). */
sso_error_t user_create_by_phone(user_manager_t *mgr, const char *phone, user_t *out);

/* Lookup by ID, username, or phone. */
sso_error_t user_get_by_id(user_manager_t *mgr, sso_id_t id, user_t *out);
sso_error_t user_get_by_username(user_manager_t *mgr, const char *username, user_t *out);
sso_error_t user_get_by_phone(user_manager_t *mgr, const char *phone, user_t *out);

/* Update user fields (id must be set; pass NULL/0 for fields not being updated). */
sso_error_t user_update(user_manager_t *mgr, const user_t *user);

/* Delete user (also removes role/group assignments). */
sso_error_t user_delete(user_manager_t *mgr, sso_id_t id);

/* List user IDs with searching and pagination.
 * q: optional search string (matches username, display_name, email, phone)
 * status: optional status filter (-1 for all)
 * offset/limit: for pagination
 * total_count: out parameter for total matches in database
 */
sso_error_t user_list(user_manager_t *mgr, const char *q, int status,
                      int offset, int limit,
                      sso_id_t *ids, size_t *count, size_t *total_count);

/* -----------------------------------------------------------------------
 * Authentication
 * ----------------------------------------------------------------------- */

/* Authenticate a user by username + raw password.  Returns SSO_OK + user data
 * on success, SSO_ERR_AUTH_FAILED on bad credentials. */
sso_error_t user_authenticate(user_manager_t *mgr, const char *username,
                              const char *password, user_t *out);

/* Set a new password for the user. */
sso_error_t user_set_password(user_manager_t *mgr, sso_id_t user_id,
                              const char *new_password);

/* Lock / unlock / activate a user account. */
sso_error_t user_set_status(user_manager_t *mgr, sso_id_t user_id,
                            user_status_t status);

/* -----------------------------------------------------------------------
 * Role & Group membership queries
 * ----------------------------------------------------------------------- */

/* Get all roles assigned to a user. */
sso_error_t user_get_roles(user_manager_t *mgr, sso_id_t user_id,
                           sso_id_t *role_ids, size_t *count, size_t max);

/* Get all groups the user belongs to (direct + inherited). */
sso_error_t user_get_groups(user_manager_t *mgr, sso_id_t user_id,
                            sso_id_t *group_ids, size_t *count, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* SSO_USER_H */
