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

/**
 * @struct user
 * @brief Represents a user account in the SSO system.
 */
struct user {
    sso_id_t          id;                               /**< Unique 64-bit user ID */
    char              username[SSO_MAX_USERNAME];       /**< Unique username string */
    char              phone[SSO_MAX_PHONE];             /**< Optional phone number */
    char              password_hash[SSO_MAX_PASSWORD_HASH]; /**< Argon2id password hash */
    char              email[SSO_MAX_EMAIL];             /**< Optional email address */
    char              display_name[SSO_MAX_DISPLAY_NAME]; /**< Display/Full name */
    user_status_t     status;                           /**< User account status (active, inactive, locked) */
    sso_timestamp_t   created_at;                       /**< Timestamp when the user was created */
    sso_timestamp_t   updated_at;                       /**< Timestamp of last user update */
    char              attributes[SSO_MAX_ATTRIBUTES];   /**< Extensible JSON attributes for ABAC rules */
    int               mfa_enabled;                      /**< 1 if MFA/TOTP is enabled, 0 otherwise */
    char              mfa_secret[SSO_MAX_MFA_SECRET];   /**< Base32 encoded MFA TOTP secret key */
};

/**
 * @brief User manager structure (opaque, accessed through sso_context).
 */
typedef struct user_manager user_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new user manager instance.
 * 
 * @param mgr Out-pointer to hold the address of the created manager.
 * @param ctx Context back-pointer.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t user_manager_create(user_manager_t **mgr, sso_context_t *ctx);

/**
 * @brief Destroys the user manager instance.
 * 
 * @param mgr Manager instance to destroy.
 */
void        user_manager_destroy(user_manager_t *mgr);

/**
 * @brief Overrides default password hashing limits for Argon2id.
 * 
 * Call this before executing user_create or user_set_password.
 * 
 * @param mgr User manager instance.
 * @param opslimit Iteration count / CPU limit.
 * @param memlimit Memory requirement limit.
 */
void        user_manager_set_hash_params(user_manager_t *mgr,
                                         unsigned long opslimit,
                                         unsigned long memlimit);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new user with password.
 * 
 * Hashes the password using Argon2id before saving it to storage.
 * 
 * @param mgr User manager instance.
 * @param username Unique login name.
 * @param password Raw plaintext password.
 * @param email Optional email.
 * @param display_name Optional display name.
 * @param out Pointer to output user structure to populate.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t user_create(user_manager_t *mgr, const char *username,
                        const char *password, const char *email,
                        const char *display_name, user_t *out);

/**
 * @brief Creates a new user by phone (no password required).
 * 
 * @param mgr User manager instance.
 * @param phone Phone number.
 * @param out Output user structure to populate.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t user_create_by_phone(user_manager_t *mgr, const char *phone, user_t *out);

/**
 * @brief Resolves a user account by its ID.
 * 
 * @param mgr User manager instance.
 * @param id User ID.
 * @param out Output structure to populate.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t user_get_by_id(user_manager_t *mgr, sso_id_t id, user_t *out);

/**
 * @brief Resolves a user account by username.
 * 
 * @param mgr User manager.
 * @param username Username string.
 * @param out Output structure to populate.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t user_get_by_username(user_manager_t *mgr, const char *username, user_t *out);

/**
 * @brief Resolves a user account by phone.
 * 
 * @param mgr User manager.
 * @param phone Phone number string.
 * @param out Output structure.
 */
sso_error_t user_get_by_phone(user_manager_t *mgr, const char *phone, user_t *out);

/**
 * @brief Updates user fields in database.
 * 
 * ID must be set in user structure. Pass NULL or 0 for fields that should remain unchanged.
 * 
 * @param mgr User manager.
 * @param user Pointer to user structure containing updates.
 */
sso_error_t user_update(user_manager_t *mgr, const user_t *user);

/**
 * @brief Deletes a user by ID.
 * 
 * Automatically removes related role and group assignments.
 * 
 * @param mgr User manager.
 * @param id User ID to delete.
 */
sso_error_t user_delete(user_manager_t *mgr, sso_id_t id);

/**
 * @brief Lists user IDs matching search filters with pagination.
 * 
 * @param mgr User manager.
 * @param q Optional search string (username, display name, email, or phone).
 * @param status Status filter (-1 for all statuses).
 * @param offset Pagination offset.
 * @param limit Pagination limit.
 * @param ids Output array for matching user IDs.
 * @param count Output number of IDs returned.
 * @param total_count Output total number of matching records in database.
 */
sso_error_t user_list(user_manager_t *mgr, const char *q, int status,
                      int offset, int limit,
                      sso_id_t *ids, size_t *count, size_t *total_count);

/* -----------------------------------------------------------------------
 * Authentication
 * ----------------------------------------------------------------------- */

/**
 * @brief Authenticate username and password credentials.
 * 
 * Checks the plaintext password against the stored Argon2id hash.
 * 
 * @param mgr User manager.
 * @param username Username.
 * @param password Plaintext password.
 * @param out Output authenticated user details.
 * @return SSO_OK on success, SSO_ERR_AUTH_FAILED on mismatch, or error code.
 */
sso_error_t user_authenticate(user_manager_t *mgr, const char *username,
                              const char *password, user_t *out);

/**
 * @brief Sets a new password for the user.
 * 
 * @param mgr User manager.
 * @param user_id User ID.
 * @param new_password Plaintext password.
 */
sso_error_t user_set_password(user_manager_t *mgr, sso_id_t user_id,
                              const char *new_password);

/**
 * @brief Set status of user account (active, inactive, locked).
 * 
 * @param mgr User manager.
 * @param user_id User ID.
 * @param status Target status value.
 */
sso_error_t user_set_status(user_manager_t *mgr, sso_id_t user_id,
                            user_status_t status);

/* -----------------------------------------------------------------------
 * Role & Group membership queries
 * ----------------------------------------------------------------------- */

/**
 * @brief Gets the list of role IDs assigned to the user.
 * 
 * @param mgr User manager.
 * @param user_id User ID.
 * @param role_ids Output array for role IDs.
 * @param count Output size of returned role IDs.
 * @param max Maximum capacity of output array.
 */
sso_error_t user_get_roles(user_manager_t *mgr, sso_id_t user_id,
                           sso_id_t *role_ids, size_t *count, size_t max);

/**
 * @brief Gets all group IDs the user belongs to (including nested parent groups).
 * 
 * @param mgr User manager.
 * @param user_id User ID.
 * @param group_ids Output array for group IDs.
 * @param count Output size of returned group IDs.
 * @param max Maximum capacity of output array.
 */
sso_error_t user_get_groups(user_manager_t *mgr, sso_id_t user_id,
                            sso_id_t *group_ids, size_t *count, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* SSO_USER_H */
