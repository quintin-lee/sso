/*
 * policy.c — Policy manager implementation.
 *
 * Policies are the fundamental unit of access control.  Each policy has a
 * strategy_type that determines how its rules are evaluated.  Policies are
 * assigned to roles, groups, or individual users.
 *
 * Policy resolution for a user aggregates:
 *   1. Policies assigned directly to the user
 *   2. Policies assigned to any role the user holds (including ancestor roles)
 *   3. Policies assigned to any group the user belongs to (including ancestor groups)
 */

#include "sso.h"
#include "policy.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "storage.h"
#include "permission.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct policy_manager {
    sso_context_t *ctx;
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */
sso_error_t policy_manager_create(policy_manager_t **mgr, sso_context_t *ctx) {
    if (!mgr || !ctx) return SSO_ERR_INVALID_PARAM;
    *mgr = (policy_manager_t *)calloc(1, sizeof(policy_manager_t));
    if (!*mgr) return SSO_ERR_OUT_OF_MEMORY;
    (*mgr)->ctx = ctx;
    return SSO_OK;
}

void policy_manager_destroy(policy_manager_t *mgr) {
    free(mgr);
}

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */
sso_error_t policy_create(policy_manager_t *mgr, const char *name,
                          perm_strategy_type_t strategy, policy_effect_t effect,
                          int priority, const char *rules_json,
                          policy_t *out) {
    if (!mgr || !name || !rules_json) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->policy_create) return SSO_ERR_NOT_IMPLEMENTED;

    policy_t policy;
    memset(&policy, 0, sizeof(policy));
    strncpy(policy.name, name, SSO_MAX_POLICY_NAME - 1);
    policy.strategy_type = strategy;
    policy.effect = effect;
    policy.priority = priority;
    strncpy(policy.rules, rules_json, SSO_MAX_RULES_JSON - 1);
    policy.status = POLICY_STATUS_ENABLED;
    policy.created_at = sso_timestamp_now();
    policy.updated_at = policy.created_at;

    sso_error_t err = sb->policy_create(sb, &policy);
    if (err == SSO_OK && out) *out = policy;
    return err;
}

sso_error_t policy_get_by_id(policy_manager_t *mgr, sso_id_t id, policy_t *out) {
    if (!mgr || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->policy_get_by_id) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->policy_get_by_id(sb, id, out);
}

sso_error_t policy_get_by_name(policy_manager_t *mgr, const char *name, policy_t *out) {
    if (!mgr || !name || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->policy_get_by_name) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->policy_get_by_name(sb, name, out);
}

sso_error_t policy_update(policy_manager_t *mgr, const policy_t *policy) {
    if (!mgr || !policy) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->policy_update) return SSO_ERR_NOT_IMPLEMENTED;
    policy_t updated = *policy;
    updated.updated_at = sso_timestamp_now();
    sso_error_t err = sb->policy_update(sb, &updated);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_policy((permission_engine_t *)mgr->ctx->perm_engine, policy->id);
    }
    return err;
}

sso_error_t policy_delete(policy_manager_t *mgr, sso_id_t id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->policy_delete) return SSO_ERR_NOT_IMPLEMENTED;
    sso_error_t err = sb->policy_delete(sb, id);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_policy((permission_engine_t *)mgr->ctx->perm_engine, id);
    }
    return err;
}

sso_error_t policy_list(policy_manager_t *mgr, sso_id_t *ids, size_t *count, size_t max) {
    if (!mgr || !ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->policy_list) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->policy_list(sb, ids, count, max);
}

/* -----------------------------------------------------------------------
 * Assignments
 * ----------------------------------------------------------------------- */
sso_error_t policy_assign_to(policy_manager_t *mgr, sso_id_t policy_id,
                             policy_target_type_t target_type, sso_id_t target_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->assign_policy) return SSO_ERR_NOT_IMPLEMENTED;
    sso_error_t err = sb->assign_policy(sb, policy_id, target_type, target_id);
    if (err == SSO_OK) {
        if (target_type == POLICY_TARGET_USER) {
            perm_engine_cache_invalidate_user((permission_engine_t *)mgr->ctx->perm_engine, target_id);
        } else {
            /* Roles/Groups affect multiple users, clear all results */
            perm_engine_cache_invalidate_all((permission_engine_t *)mgr->ctx->perm_engine);
        }
    }
    return err;
}

sso_error_t policy_unassign_from(policy_manager_t *mgr, sso_id_t policy_id,
                                 policy_target_type_t target_type, sso_id_t target_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->unassign_policy) return SSO_ERR_NOT_IMPLEMENTED;
    sso_error_t err = sb->unassign_policy(sb, policy_id, target_type, target_id);
    if (err == SSO_OK) {
        if (target_type == POLICY_TARGET_USER) {
            perm_engine_cache_invalidate_user((permission_engine_t *)mgr->ctx->perm_engine, target_id);
        } else {
            perm_engine_cache_invalidate_all((permission_engine_t *)mgr->ctx->perm_engine);
        }
    }
    return err;
}

sso_error_t policy_get_targets(policy_manager_t *mgr, sso_id_t policy_id,
                               policy_target_type_t target_type,
                               sso_id_t *target_ids, size_t *count, size_t max) {
    if (!mgr || !target_ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_policy_targets) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->get_policy_targets(sb, policy_id, target_type, target_ids, count, max);
}

/* -----------------------------------------------------------------------
 * Policy resolution — collect all policies for a user
 * ----------------------------------------------------------------------- */

/* Helper: collect policies for a single target (role or group), including ancestry. */
static sso_error_t collect_policies_for_target(policy_manager_t *mgr,
                                                policy_target_type_t target_type,
                                                sso_id_t target_id,
                                                policy_t *policies,
                                                size_t *count, size_t max) {
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_target_policies) return SSO_ERR_NOT_IMPLEMENTED;

    sso_id_t policy_ids[64];
    size_t pcount = 0;
    sso_error_t err = sb->get_target_policies(sb, target_type, target_id,
                                              policy_ids, &pcount, 64);
    if (err != SSO_OK) return err;

    for (size_t i = 0; i < pcount && *count < max; i++) {
        if (policy_get_by_id(mgr, policy_ids[i], &policies[*count]) == SSO_OK) {
            (*count)++;
        }
    }
    return SSO_OK;
}

sso_error_t policy_resolve_for_user(policy_manager_t *mgr, sso_id_t user_id,
                                    policy_t *policies, size_t *count, size_t max) {
    if (!mgr || !policies || !count) return SSO_ERR_INVALID_PARAM;
    *count = 0;

    user_manager_t *umgr = (user_manager_t *)mgr->ctx->user_mgr;
    if (!umgr) return SSO_ERR_GENERAL;

    /* 1. Policies assigned directly to the user */
    collect_policies_for_target(mgr, POLICY_TARGET_USER, user_id,
                                policies, count, max);

    /* 2. Policies via roles (including ancestor roles) */
    sso_id_t role_ids[64];
    size_t rcount = 0;
    if (user_get_roles(umgr, user_id, role_ids, &rcount, 64) == SSO_OK) {
        for (size_t i = 0; i < rcount && *count < max; i++) {
            /* Direct role */
            collect_policies_for_target(mgr, POLICY_TARGET_ROLE, role_ids[i],
                                        policies, count, max);

            /* Ancestor roles */
            role_manager_t *rmgr = (role_manager_t *)mgr->ctx->role_mgr;
            if (rmgr) {
                sso_id_t ancestors[16];
                size_t depth = 0;
                if (role_get_ancestors(rmgr, role_ids[i], ancestors, &depth, 16) == SSO_OK) {
                    for (size_t a = 0; a < depth && *count < max; a++) {
                        collect_policies_for_target(mgr, POLICY_TARGET_ROLE, ancestors[a],
                                                    policies, count, max);
                    }
                }
            }
        }
    }

    /* 3. Policies via groups (including ancestor groups) */
    sso_id_t group_ids[64];
    size_t gcount = 0;
    if (user_get_groups(umgr, user_id, group_ids, &gcount, 64) == SSO_OK) {
        for (size_t i = 0; i < gcount && *count < max; i++) {
            /* Direct group */
            collect_policies_for_target(mgr, POLICY_TARGET_GROUP, group_ids[i],
                                        policies, count, max);

            /* Ancestor groups */
            group_manager_t *gmgr = (group_manager_t *)mgr->ctx->group_mgr;
            if (gmgr) {
                sso_id_t ancestors[16];
                size_t depth = 0;
                if (group_get_ancestors(gmgr, group_ids[i], ancestors, &depth, 16) == SSO_OK) {
                    for (size_t a = 0; a < depth && *count < max; a++) {
                        collect_policies_for_target(mgr, POLICY_TARGET_GROUP, ancestors[a],
                                                    policies, count, max);
                    }
                }
            }
        }
    }

    /* 4. Sort by priority descending (simple insertion sort) */
    if (*count > 1) {
        for (size_t i = 1; i < *count; i++) {
            policy_t key;
            memcpy(&key, &policies[i], sizeof(policy_t));
            ssize_t j = (ssize_t)i - 1;
            while (j >= 0 && policies[j].priority < key.priority) {
                memcpy(&policies[j + 1], &policies[j], sizeof(policy_t));
                j--;
            }
            memcpy(&policies[j + 1], &key, sizeof(policy_t));
        }
    }

    return *count > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* -----------------------------------------------------------------------
 * Validation & Status
 * ----------------------------------------------------------------------- */
sso_error_t policy_validate_rules(policy_manager_t *mgr, const policy_t *policy) {
    if (!mgr || !policy) return SSO_ERR_INVALID_PARAM;
    /* Strategy validation is done by the permission engine */
    (void)mgr;
    return SSO_OK;
}

sso_error_t policy_set_status(policy_manager_t *mgr, sso_id_t policy_id,
                              policy_status_t status) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    policy_t policy;
    sso_error_t err = policy_get_by_id(mgr, policy_id, &policy);
    if (err != SSO_OK) return err;
    policy.status = status;
    return policy_update(mgr, &policy);
}
