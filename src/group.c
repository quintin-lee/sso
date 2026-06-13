/*
 * group.c — Group manager implementation.
 *
 * Groups are organizational units with optional hierarchy.  Users in a
 * group inherit all roles and policies assigned to that group (and its
 * ancestors).
 */

#include "sso.h"
#include "group.h"
#include "storage.h"
#include "permission.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct group_manager {
    sso_context_t *ctx;
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */
sso_error_t group_manager_create(group_manager_t **mgr, sso_context_t *ctx) {
    if (!mgr || !ctx) return SSO_ERR_INVALID_PARAM;
    *mgr = (group_manager_t *)calloc(1, sizeof(group_manager_t));
    if (!*mgr) return SSO_ERR_OUT_OF_MEMORY;
    (*mgr)->ctx = ctx;
    return SSO_OK;
}

void group_manager_destroy(group_manager_t *mgr) {
    free(mgr);
}

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */
sso_error_t group_create(group_manager_t *mgr, const char *name,
                         const char *description, sso_id_t parent_group_id,
                         group_t *out) {
    if (!mgr || !name) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->group_create) return SSO_ERR_NOT_IMPLEMENTED;

    group_t group;
    memset(&group, 0, sizeof(group));
    strncpy(group.name, name, SSO_MAX_GROUP_NAME - 1);
    if (description) strncpy(group.description, description, SSO_MAX_DESCRIPTION - 1);
    group.parent_group_id = parent_group_id;
    group.created_at = sso_timestamp_now();
    group.updated_at = group.created_at;

    sso_error_t err = sb->group_create(sb, &group);
    if (err == SSO_OK && out) *out = group;
    return err;
}

sso_error_t group_get_by_id(group_manager_t *mgr, sso_id_t id, group_t *out) {
    if (!mgr || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->group_get_by_id) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->group_get_by_id(sb, id, out);
}

sso_error_t group_get_by_name(group_manager_t *mgr, const char *name, group_t *out) {
    if (!mgr || !name || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->group_get_by_name) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->group_get_by_name(sb, name, out);
}

sso_error_t group_update(group_manager_t *mgr, const group_t *group) {
    if (!mgr || !group) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->group_update) return SSO_ERR_NOT_IMPLEMENTED;
    group_t updated = *group;
    updated.updated_at = sso_timestamp_now();
    sso_error_t err = sb->group_update(sb, &updated);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_all((permission_engine_t *)mgr->ctx->perm_engine);
    }
    return err;
}

sso_error_t group_delete(group_manager_t *mgr, sso_id_t id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->group_delete) return SSO_ERR_NOT_IMPLEMENTED;
    sso_error_t err = sb->group_delete(sb, id);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_all((permission_engine_t *)mgr->ctx->perm_engine);
    }
    return err;
}

sso_error_t group_list(group_manager_t *mgr, sso_id_t *ids, size_t *count, size_t max) {
    if (!mgr || !ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->group_list) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->group_list(sb, ids, count, max);
}

/* -----------------------------------------------------------------------
 * Hierarchy
 * ----------------------------------------------------------------------- */
sso_error_t group_get_ancestors(group_manager_t *mgr, sso_id_t group_id,
                                sso_id_t *ids, size_t *depth, size_t max) {
    if (!mgr || !ids || !depth) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->group_get_parent) return SSO_ERR_NOT_IMPLEMENTED;

    size_t d = 0;
    sso_id_t current = group_id;
    while (d < max) {
        sso_id_t parent = SSO_ID_NONE;
        sso_error_t err = sb->group_get_parent(sb, current, &parent);
        if (err != SSO_OK || parent == SSO_ID_NONE) break;
        ids[d++] = parent;
        current = parent;
    }
    *depth = d;
    return SSO_OK;
}

sso_error_t group_get_children(group_manager_t *mgr, sso_id_t group_id,
                               sso_id_t *child_ids, size_t *count, size_t max) {
    if (!mgr || !child_ids || !count) return SSO_ERR_INVALID_PARAM;
    sso_id_t all[256];
    size_t all_count = 0;
    sso_error_t err = group_list(mgr, all, &all_count, 256);
    if (err != SSO_OK) return err;

    size_t n = 0;
    for (size_t i = 0; i < all_count && n < max; i++) {
        group_t g;
        if (group_get_by_id(mgr, all[i], &g) == SSO_OK && g.parent_group_id == group_id) {
            child_ids[n++] = all[i];
        }
    }
    *count = n;
    return SSO_OK;
}

/* -----------------------------------------------------------------------
 * Membership
 * ----------------------------------------------------------------------- */
sso_error_t group_add_user(group_manager_t *mgr, sso_id_t group_id, sso_id_t user_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->add_user_to_group) return SSO_ERR_NOT_IMPLEMENTED;
    sso_error_t err = sb->add_user_to_group(sb, group_id, user_id);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_user((permission_engine_t *)mgr->ctx->perm_engine, user_id);
    }
    return err;
}

sso_error_t group_remove_user(group_manager_t *mgr, sso_id_t group_id, sso_id_t user_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->remove_user_from_group) return SSO_ERR_NOT_IMPLEMENTED;
    sso_error_t err = sb->remove_user_from_group(sb, group_id, user_id);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_user((permission_engine_t *)mgr->ctx->perm_engine, user_id);
    }
    return err;
}

sso_error_t group_get_members(group_manager_t *mgr, sso_id_t group_id,
                              sso_id_t *user_ids, size_t *count, size_t max) {
    if (!mgr || !user_ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_group_users) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->get_group_users(sb, group_id, user_ids, count, max);
}

sso_error_t group_get_policies(group_manager_t *mgr, sso_id_t group_id,
                               sso_id_t *policy_ids, size_t *count, size_t max) {
    if (!mgr || !policy_ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_target_policies) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->get_target_policies(sb, POLICY_TARGET_GROUP, group_id, policy_ids, count, max);
}
