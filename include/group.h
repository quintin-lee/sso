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

/* ========================================================================
 * Data structure
 * ======================================================================== */
struct group {
    sso_id_t          id;
    char              name[SSO_MAX_GROUP_NAME];
    char              description[SSO_MAX_DESCRIPTION];
    sso_id_t          parent_group_id;      /* 0 = top-level group */
    sso_timestamp_t   created_at;
    sso_timestamp_t   updated_at;
};

/* ========================================================================
 * Group manager (opaque)
 * ======================================================================== */
typedef struct group_manager group_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */
sso_error_t group_manager_create(group_manager_t **mgr, sso_context_t *ctx);
void        group_manager_destroy(group_manager_t *mgr);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */
sso_error_t group_create(group_manager_t *mgr, const char *name,
                         const char *description, sso_id_t parent_group_id,
                         group_t *out);
sso_error_t group_get_by_id(group_manager_t *mgr, sso_id_t id, group_t *out);
sso_error_t group_get_by_name(group_manager_t *mgr, const char *name, group_t *out);
sso_error_t group_update(group_manager_t *mgr, const group_t *group);
sso_error_t group_delete(group_manager_t *mgr, sso_id_t id);
sso_error_t group_list(group_manager_t *mgr, sso_id_t *ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Hierarchy
 * ----------------------------------------------------------------------- */
sso_error_t group_get_ancestors(group_manager_t *mgr, sso_id_t group_id,
                                sso_id_t *ids, size_t *depth, size_t max);
sso_error_t group_get_children(group_manager_t *mgr, sso_id_t group_id,
                               sso_id_t *child_ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Membership
 * ----------------------------------------------------------------------- */
sso_error_t group_add_user(group_manager_t *mgr, sso_id_t group_id, sso_id_t user_id);
sso_error_t group_remove_user(group_manager_t *mgr, sso_id_t group_id, sso_id_t user_id);
sso_error_t group_get_members(group_manager_t *mgr, sso_id_t group_id,
                              sso_id_t *user_ids, size_t *count, size_t max);

/* List policies attached to a group. */
sso_error_t group_get_policies(group_manager_t *mgr, sso_id_t group_id,
                               sso_id_t *policy_ids, size_t *count, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* SSO_GROUP_H */
