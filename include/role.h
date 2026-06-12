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

/* ========================================================================
 * Data structure
 * ======================================================================== */
struct role {
    sso_id_t          id;
    char              name[SSO_MAX_ROLE_NAME];
    char              description[SSO_MAX_DESCRIPTION];
    sso_id_t          parent_role_id;       /* 0 = top-level role */
    sso_timestamp_t   created_at;
    sso_timestamp_t   updated_at;
};

/* ========================================================================
 * Role manager (opaque)
 * ======================================================================== */
typedef struct role_manager role_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */
sso_error_t role_manager_create(role_manager_t **mgr, sso_context_t *ctx);
void        role_manager_destroy(role_manager_t *mgr);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */
sso_error_t role_create(role_manager_t *mgr, const char *name,
                        const char *description, sso_id_t parent_role_id,
                        role_t *out);
sso_error_t role_get_by_id(role_manager_t *mgr, sso_id_t id, role_t *out);
sso_error_t role_get_by_name(role_manager_t *mgr, const char *name, role_t *out);
sso_error_t role_update(role_manager_t *mgr, const role_t *role);
sso_error_t role_delete(role_manager_t *mgr, sso_id_t id);
sso_error_t role_list(role_manager_t *mgr, sso_id_t *ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Hierarchy
 * ----------------------------------------------------------------------- */

/* Get the chain of ancestor roles (parent, grandparent, …).  Returns
 * the count in *depth.  ids[0] is the immediate parent. */
sso_error_t role_get_ancestors(role_manager_t *mgr, sso_id_t role_id,
                               sso_id_t *ids, size_t *depth, size_t max);

/* Get all direct children of a role. */
sso_error_t role_get_children(role_manager_t *mgr, sso_id_t role_id,
                              sso_id_t *child_ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Assignment (role ↔ user, role ↔ group)
 * ----------------------------------------------------------------------- */
sso_error_t role_assign_to_user(role_manager_t *mgr, sso_id_t role_id, sso_id_t user_id);
sso_error_t role_unassign_from_user(role_manager_t *mgr, sso_id_t role_id, sso_id_t user_id);
sso_error_t role_assign_to_group(role_manager_t *mgr, sso_id_t role_id, sso_id_t group_id);
sso_error_t role_unassign_from_group(role_manager_t *mgr, sso_id_t role_id, sso_id_t group_id);

/* List all users who have a given role. */
sso_error_t role_get_users(role_manager_t *mgr, sso_id_t role_id,
                           sso_id_t *user_ids, size_t *count, size_t max);

/* List policies attached to a role. */
sso_error_t role_get_policies(role_manager_t *mgr, sso_id_t role_id,
                              sso_id_t *policy_ids, size_t *count, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* SSO_ROLE_H */
