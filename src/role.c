/*
 * role.c — Role manager implementation.
 *
 * Roles form a hierarchy.  Ancestor traversal walks up parent_role_id
 * chain to collect inherited policies.
 */

#include "sso.h"
#include "role.h"
#include "storage.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct role_manager {
    sso_context_t *ctx;
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */
sso_error_t role_manager_create(role_manager_t **mgr, sso_context_t *ctx) {
    if (!mgr || !ctx) return SSO_ERR_INVALID_PARAM;
    *mgr = (role_manager_t *)calloc(1, sizeof(role_manager_t));
    if (!*mgr) return SSO_ERR_OUT_OF_MEMORY;
    (*mgr)->ctx = ctx;
    return SSO_OK;
}

void role_manager_destroy(role_manager_t *mgr) {
    free(mgr);
}

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */
sso_error_t role_create(role_manager_t *mgr, const char *name,
                        const char *description, sso_id_t parent_role_id,
                        role_t *out) {
    if (!mgr || !name) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->role_create) return SSO_ERR_NOT_IMPLEMENTED;

    role_t role;
    memset(&role, 0, sizeof(role));
    strncpy(role.name, name, SSO_MAX_ROLE_NAME - 1);
    if (description) strncpy(role.description, description, SSO_MAX_DESCRIPTION - 1);
    role.parent_role_id = parent_role_id;
    role.created_at = sso_timestamp_now();
    role.updated_at = role.created_at;

    sso_error_t err = sb->role_create(sb, &role);
    if (err == SSO_OK && out) *out = role;
    return err;
}

sso_error_t role_get_by_id(role_manager_t *mgr, sso_id_t id, role_t *out) {
    if (!mgr || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->role_get_by_id) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->role_get_by_id(sb, id, out);
}

sso_error_t role_get_by_name(role_manager_t *mgr, const char *name, role_t *out) {
    if (!mgr || !name || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->role_get_by_name) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->role_get_by_name(sb, name, out);
}

sso_error_t role_update(role_manager_t *mgr, const role_t *role) {
    if (!mgr || !role) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->role_update) return SSO_ERR_NOT_IMPLEMENTED;
    role_t updated = *role;
    updated.updated_at = sso_timestamp_now();
    return sb->role_update(sb, &updated);
}

sso_error_t role_delete(role_manager_t *mgr, sso_id_t id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->role_delete) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->role_delete(sb, id);
}

sso_error_t role_list(role_manager_t *mgr, sso_id_t *ids, size_t *count, size_t max) {
    if (!mgr || !ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->role_list) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->role_list(sb, ids, count, max);
}

/* -----------------------------------------------------------------------
 * Hierarchy
 * ----------------------------------------------------------------------- */
sso_error_t role_get_ancestors(role_manager_t *mgr, sso_id_t role_id,
                               sso_id_t *ids, size_t *depth, size_t max) {
    if (!mgr || !ids || !depth) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->role_get_parent) return SSO_ERR_NOT_IMPLEMENTED;

    size_t d = 0;
    sso_id_t current = role_id;
    while (d < max) {
        sso_id_t parent = SSO_ID_NONE;
        sso_error_t err = sb->role_get_parent(sb, current, &parent);
        if (err != SSO_OK || parent == SSO_ID_NONE) break;
        ids[d++] = parent;
        current = parent;
    }
    *depth = d;
    return SSO_OK;
}

sso_error_t role_get_children(role_manager_t *mgr, sso_id_t role_id,
                              sso_id_t *child_ids, size_t *count, size_t max) {
    if (!mgr || !child_ids || !count) return SSO_ERR_INVALID_PARAM;
    /* Full scan — in production, add a direct query to the storage backend */
    sso_id_t all[256];
    size_t all_count = 0;
    sso_error_t err = role_list(mgr, all, &all_count, 256);
    if (err != SSO_OK) return err;

    size_t n = 0;
    for (size_t i = 0; i < all_count && n < max; i++) {
        role_t r;
        if (role_get_by_id(mgr, all[i], &r) == SSO_OK && r.parent_role_id == role_id) {
            child_ids[n++] = all[i];
        }
    }
    *count = n;
    return SSO_OK;
}

/* -----------------------------------------------------------------------
 * Assignments
 * ----------------------------------------------------------------------- */
sso_error_t role_assign_to_user(role_manager_t *mgr, sso_id_t role_id, sso_id_t user_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->assign_role_to_user) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->assign_role_to_user(sb, role_id, user_id);
}

sso_error_t role_unassign_from_user(role_manager_t *mgr, sso_id_t role_id, sso_id_t user_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->unassign_role_from_user) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->unassign_role_from_user(sb, role_id, user_id);
}

sso_error_t role_assign_to_group(role_manager_t *mgr, sso_id_t role_id, sso_id_t group_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->assign_role_to_group) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->assign_role_to_group(sb, role_id, group_id);
}

sso_error_t role_unassign_from_group(role_manager_t *mgr, sso_id_t role_id, sso_id_t group_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->unassign_role_from_group) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->unassign_role_from_group(sb, role_id, group_id);
}

sso_error_t role_get_users(role_manager_t *mgr, sso_id_t role_id,
                           sso_id_t *user_ids, size_t *count, size_t max) {
    if (!mgr || !user_ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_role_users) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->get_role_users(sb, role_id, user_ids, count, max);
}

sso_error_t role_get_policies(role_manager_t *mgr, sso_id_t role_id,
                              sso_id_t *policy_ids, size_t *count, size_t max) {
    if (!mgr || !policy_ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_target_policies) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->get_target_policies(sb, POLICY_TARGET_ROLE, role_id, policy_ids, count, max);
}
