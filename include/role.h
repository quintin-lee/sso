/*
 * role.h — Role management module.
 *
 * Roles form a hierarchy (parent_role_id).  Permissions assigned to a
 * parent role are inherited by its children.  Roles can be assigned to
 * users (via assignment table) or to groups.
 */

#ifndef SSO_ROLE_H
#define SSO_ROLE_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct role
 * @brief Represents a role in the RBAC hierarchy.
 */
struct role {
    sso_id_t          id;                               /**< Unique 64-bit role ID */
    char              name[SSO_MAX_ROLE_NAME];          /**< Unique role name string */
    char              description[SSO_MAX_DESCRIPTION]; /**< Description of the role */
    sso_id_t          parent_role_id;                   /**< Parent role ID for hierarchical inheritance (0 = root) */
    role_status_t     status;                           /**< Active or inactive status */
    sso_timestamp_t   created_at;                       /**< Timestamp when role was created */
    sso_timestamp_t   updated_at;                       /**< Timestamp of last role update */
};

/**
 * @brief Role manager structure (opaque).
 */
typedef struct role_manager role_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new role manager instance.
 * 
 * @param mgr Out-pointer to hold the address of the created manager.
 * @param ctx Context back-pointer.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t role_manager_create(role_manager_t **mgr, sso_context_t *ctx);

/**
 * @brief Destroys the role manager instance.
 * 
 * @param mgr Manager instance.
 */
void        role_manager_destroy(role_manager_t *mgr);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new role in the database.
 * 
 * @param mgr Role manager.
 * @param name Unique role name.
 * @param description Description of the role.
 * @param parent_role_id Parent role ID (0 if none).
 * @param out Output role structure to populate.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t role_create(role_manager_t *mgr, const char *name,
                        const char *description, sso_id_t parent_role_id,
                        role_t *out);

/**
 * @brief Resolves a role by its ID.
 * 
 * @param mgr Role manager.
 * @param id Role ID.
 * @param out Output structure.
 */
sso_error_t role_get_by_id(role_manager_t *mgr, sso_id_t id, role_t *out);

/**
 * @brief Resolves a role by its name.
 * 
 * @param mgr Role manager.
 * @param name Role name string.
 * @param out Output structure.
 */
sso_error_t role_get_by_name(role_manager_t *mgr, const char *name, role_t *out);

/**
 * @brief Updates role fields in database.
 * 
 * ID must be set in role structure.
 * 
 * @param mgr Role manager.
 * @param role Pointer to role structure containing updates.
 */
sso_error_t role_update(role_manager_t *mgr, const role_t *role);

/**
 * @brief Deletes a role by ID.
 * 
 * Automatically removes assignments associated with this role.
 * 
 * @param mgr Role manager.
 * @param id Role ID to delete.
 */
sso_error_t role_delete(role_manager_t *mgr, sso_id_t id);

/**
 * @brief Lists role IDs matching search filters with pagination.
 * 
 * @param mgr Role manager.
 * @param q Optional search term (matches name or description).
 * @param status Status filter (-1 for all).
 * @param offset Pagination offset.
 * @param limit Pagination limit.
 * @param ids Output array for matching role IDs.
 * @param count Output size of returned IDs.
 * @param total_count Output total count of matches in database.
 */
sso_error_t role_list(role_manager_t *mgr, const char *q, int status,
                      int offset, int limit,
                      sso_id_t *ids, size_t *count, size_t *total_count);

/* -----------------------------------------------------------------------
 * Hierarchy
 * ----------------------------------------------------------------------- */

/**
 * @brief Retrieves the chain of ancestor role IDs.
 * 
 * Walk parent links up the hierarchy. ids[0] contains the immediate parent.
 * 
 * @param mgr Role manager.
 * @param role_id Target role ID.
 * @param ids Output array to populate with ancestor IDs.
 * @param depth Output count of retrieved ancestor role levels.
 * @param max Max capacity of output array.
 */
sso_error_t role_get_ancestors(role_manager_t *mgr, sso_id_t role_id,
                               sso_id_t *ids, size_t *depth, size_t max);

/**
 * @brief Gets direct children role IDs of a role.
 * 
 * @param mgr Role manager.
 * @param role_id Target role ID.
 * @param child_ids Output array for child IDs.
 * @param count Output size of children IDs.
 * @param max Max capacity of child_ids array.
 */
sso_error_t role_get_children(role_manager_t *mgr, sso_id_t role_id,
                              sso_id_t *child_ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Assignment (role ↔ user, role ↔ group)
 * ----------------------------------------------------------------------- */

/**
 * @brief Assigns a role to a user.
 * 
 * @param mgr Role manager.
 * @param role_id Role ID.
 * @param user_id User ID.
 */
sso_error_t role_assign_to_user(role_manager_t *mgr, sso_id_t role_id, sso_id_t user_id);

/**
 * @brief Unassigns a role from a user.
 * 
 * @param mgr Role manager.
 * @param role_id Role ID.
 * @param user_id User ID.
 */
sso_error_t role_unassign_from_user(role_manager_t *mgr, sso_id_t role_id, sso_id_t user_id);

/**
 * @brief Assigns a role to a group.
 * 
 * @param mgr Role manager.
 * @param role_id Role ID.
 * @param group_id Group ID.
 */
sso_error_t role_assign_to_group(role_manager_t *mgr, sso_id_t role_id, sso_id_t group_id);

/**
 * @brief Unassigns a role from a group.
 * 
 * @param mgr Role manager.
 * @param role_id Role ID.
 * @param group_id Group ID.
 */
sso_error_t role_unassign_from_group(role_manager_t *mgr, sso_id_t role_id, sso_id_t group_id);

/**
 * @brief Lists all user IDs that possess the given role.
 * 
 * @param mgr Role manager.
 * @param role_id Role ID.
 * @param user_ids Output array for user IDs.
 * @param count Output count of user IDs.
 * @param max Max capacity of output array.
 */
sso_error_t role_get_users(role_manager_t *mgr, sso_id_t role_id,
                           sso_id_t *user_ids, size_t *count, size_t max);

/**
 * @brief Lists all policy IDs attached to the role.
 * 
 * @param mgr Role manager.
 * @param role_id Role ID.
 * @param policy_ids Output array for policy IDs.
 * @param count Output count of policy IDs.
 * @param max Max capacity of output array.
 */
sso_error_t role_get_policies(role_manager_t *mgr, sso_id_t role_id,
                              sso_id_t *policy_ids, size_t *count, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* SSO_ROLE_H */
