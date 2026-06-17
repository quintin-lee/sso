/*
 * group.h — Group management module.
 *
 * Groups are organizational units (e.g. "Engineering", "Finance").
 * Groups can be nested (parent_group_id).  Users inherit all roles
 * and policies assigned to the groups they belong to.
 */

#ifndef SSO_GROUP_H
#define SSO_GROUP_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct group
 * @brief Represents a user group for role/policy aggregation.
 */
struct group {
    sso_id_t          id;                               /**< Unique 64-bit group ID */
    char              name[SSO_MAX_GROUP_NAME];          /**< Unique group name string */
    char              description[SSO_MAX_DESCRIPTION]; /**< Description of the group */
    sso_id_t          parent_group_id;                  /**< Parent group ID (0 = root level) */
    group_status_t    status;                           /**< Active or inactive status */
    sso_timestamp_t   created_at;                       /**< Timestamp when group was created */
    sso_timestamp_t   updated_at;                       /**< Timestamp of last group update */
};

/**
 * @brief Group manager structure (opaque).
 */
typedef struct group_manager group_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new group manager instance.
 * 
 * @param mgr Out-pointer to hold the address of the created manager.
 * @param ctx Context back-pointer.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t group_manager_create(group_manager_t **mgr, sso_context_t *ctx);

/**
 * @brief Destroys the group manager instance.
 * 
 * @param mgr Manager instance.
 */
void        group_manager_destroy(group_manager_t *mgr);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new group.
 * 
 * @param mgr Group manager.
 * @param name Unique group name.
 * @param description Description of the group.
 * @param parent_group_id Parent group ID (0 if none).
 * @param out Output group structure to populate.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t group_create(group_manager_t *mgr, const char *name,
                         const char *description, sso_id_t parent_group_id,
                         group_t *out);

/**
 * @brief Resolves a group by its ID.
 * 
 * @param mgr Group manager.
 * @param id Group ID.
 * @param out Output structure.
 */
sso_error_t group_get_by_id(group_manager_t *mgr, sso_id_t id, group_t *out);

/**
 * @brief Resolves a group by name.
 * 
 * @param mgr Group manager.
 * @param name Group name.
 * @param out Output structure.
 */
sso_error_t group_get_by_name(group_manager_t *mgr, const char *name, group_t *out);

/**
 * @brief Updates group fields in database.
 * 
 * ID must be set in group structure.
 * 
 * @param mgr Group manager.
 * @param group Pointer to group structure containing updates.
 */
sso_error_t group_update(group_manager_t *mgr, const group_t *group);

/**
 * @brief Deletes a group by ID.
 * 
 * Removes memberships and assignments associated with the group.
 * 
 * @param mgr Group manager.
 * @param id Group ID to delete.
 */
sso_error_t group_delete(group_manager_t *mgr, sso_id_t id);

/**
 * @brief Lists group IDs matching filters with pagination.
 * 
 * @param mgr Group manager.
 * @param q Optional search term (matches name or description).
 * @param status Status filter (-1 for all).
 * @param offset Pagination offset.
 * @param limit Pagination limit.
 * @param ids Output array for matching group IDs.
 * @param count Output size of returned IDs.
 * @param total_count Output total count of matches in database.
 */
sso_error_t group_list(group_manager_t *mgr, const char *q, int status,
                       int offset, int limit,
                       sso_id_t *ids, size_t *count, size_t *total_count);

/* -----------------------------------------------------------------------
 * Hierarchy
 * ----------------------------------------------------------------------- */

/**
 * @brief Retrieves the chain of parent group IDs.
 * 
 * Walk parent links up the hierarchy. ids[0] contains the immediate parent.
 * 
 * @param mgr Group manager.
 * @param group_id Target group ID.
 * @param ids Output array to populate with parent IDs.
 * @param depth Output count of ancestor group levels.
 * @param max Max capacity of output array.
 */
sso_error_t group_get_ancestors(group_manager_t *mgr, sso_id_t group_id,
                                sso_id_t *ids, size_t *depth, size_t max);

/**
 * @brief Gets direct children group IDs of a group.
 * 
 * @param mgr Group manager.
 * @param group_id Target group ID.
 * @param child_ids Output array for child IDs.
 * @param count Output size of child group IDs.
 * @param max Max capacity of child_ids array.
 */
sso_error_t group_get_children(group_manager_t *mgr, sso_id_t group_id,
                               sso_id_t *child_ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Membership
 * ----------------------------------------------------------------------- */

/**
 * @brief Adds a user to a group.
 * 
 * @param mgr Group manager.
 * @param group_id Group ID.
 * @param user_id User ID.
 */
sso_error_t group_add_user(group_manager_t *mgr, sso_id_t group_id, sso_id_t user_id);

/**
 * @brief Removes a user from a group.
 * 
 * @param mgr Group manager.
 * @param group_id Group ID.
 * @param user_id User ID.
 */
sso_error_t group_remove_user(group_manager_t *mgr, sso_id_t group_id, sso_id_t user_id);

/**
 * @brief Lists all user IDs belonging to a group.
 * 
 * @param mgr Group manager.
 * @param group_id Group ID.
 * @param user_ids Output array for user IDs.
 * @param count Output count of user IDs.
 * @param max Max capacity of user_ids array.
 */
sso_error_t group_get_members(group_manager_t *mgr, sso_id_t group_id,
                              sso_id_t *user_ids, size_t *count, size_t max);

/**
 * @brief Lists all policy IDs attached to a group.
 * 
 * @param mgr Group manager.
 * @param group_id Group ID.
 * @param policy_ids Output array for policy IDs.
 * @param count Output count of policy IDs.
 * @param max Max capacity of policy_ids array.
 */
sso_error_t group_get_policies(group_manager_t *mgr, sso_id_t group_id,
                               sso_id_t *policy_ids, size_t *count, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* SSO_GROUP_H */
