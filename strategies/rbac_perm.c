/*
 * rbac_perm.c — RBAC (Role-Based Access Control) permission strategy.
 *
 * Evaluates whether a user has a specific role membership.
 * Rules are a JSON array of role names with allow/deny semantics.
 *
 * Rule format (JSON):
 *   {
 *     "roles": [
 *       {"name": "admin",   "effect": "allow"},
 *       {"name": "viewer",  "effect": "deny"},
 *       {"name": "auditor", "effect": "allow"}
 *     ]
 *   }
 *
 * This version uses pre-compilation for production performance.
 */

#include "sso.h"
#include "policy.h"
#include "role.h"
#include "user.h"
#include "storage.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Pre-compiled RBAC rule structure
 * ----------------------------------------------------------------------- */
typedef struct {
    char    role_name[64];
    bool    is_allow;
} rbac_rule_item_t;

typedef struct {
    rbac_rule_item_t *items;
    size_t            count;
} rbac_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Helper: check if a user ID holds a named role.
 * ----------------------------------------------------------------------- */
static bool user_has_role(sso_context_t *sso_ctx, sso_id_t user_id,
                          const char *role_name) {
    if (!sso_ctx || !role_name) return false;

    storage_backend_t *sb = (storage_backend_t *)sso_ctx->storage_backend;
    role_manager_t *rmgr = (role_manager_t *)sso_ctx->role_mgr;
    if (!sb || !rmgr) return false;

    /* Look up the target role by name to get its numeric ID. */
    role_t target_role;
    if (role_get_by_name(rmgr, role_name, &target_role) != SSO_OK) {
        return false;
    }

    if (!sb->get_user_roles_with_ancestors) {
        return false;
    }

    sso_id_t user_role_ids[128];
    size_t count = 128;
    sso_error_t err = sb->get_user_roles_with_ancestors(sb, user_id,
                                                         user_role_ids,
                                                         &count, 128);
    if (err != SSO_OK) return false;

    for (size_t i = 0; i < count; i++) {
        if (user_role_ids[i] == target_role.id) {
            return true;
        }
    }

    return false;
}

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t rbac_init(permission_strategy_t *self, sso_context_t *ctx) {
    self->userdata = ctx; 
    return SSO_OK;
}

static void rbac_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t rbac_compile(permission_strategy_t *self,
                                const char *rules_json,
                                void **compiled_rule) {
    (void)self;
    if (!rules_json || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    const cJSON *roles_arr = cJSON_GetObjectItem(root, "roles");
    if (!cJSON_IsArray(roles_arr)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    size_t count = (size_t)cJSON_GetArraySize(roles_arr);
    rbac_compiled_rule_t *compiled = (rbac_compiled_rule_t *)malloc(sizeof(rbac_compiled_rule_t));
    if (!compiled) {
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    compiled->count = count;
    compiled->items = (rbac_rule_item_t *)calloc(count, sizeof(rbac_rule_item_t));
    if (!compiled->items) {
        free(compiled);
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        const cJSON *item = cJSON_GetArrayItem(roles_arr, (int)i);
        const cJSON *name = cJSON_GetObjectItem(item, "name");
        const cJSON *effect = cJSON_GetObjectItem(item, "effect");

        if (cJSON_IsString(name)) {
            strncpy(compiled->items[i].role_name, name->valuestring, 63);
        }
        if (cJSON_IsString(effect)) {
            compiled->items[i].is_allow = (strcmp(effect->valuestring, "allow") == 0);
        } else {
            compiled->items[i].is_allow = true; 
        }
    }

    cJSON_Delete(root);
    *compiled_rule = compiled;
    return SSO_OK;
}

static void rbac_free_compiled(permission_strategy_t *self,
                               void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    rbac_compiled_rule_t *compiled = (rbac_compiled_rule_t *)compiled_rule;
    free(compiled->items);
    free(compiled);
}

static sso_error_t rbac_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    if (!ctx || !policy || !result || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    const char *role_name = ctx->params.rbac.role_name;
    if (!role_name || role_name[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    sso_context_t *sso_ctx = (sso_context_t *)self->userdata;
    if (!sso_ctx) return SSO_ERR_NOT_FOUND;

    rbac_compiled_rule_t *compiled = (rbac_compiled_rule_t *)compiled_rule;

    for (size_t i = 0; i < compiled->count; i++) {
        if (strcmp(compiled->items[i].role_name, role_name) == 0) {
            if (user_has_role(sso_ctx, ctx->user_id, role_name)) {
                *result = compiled->items[i].is_allow;
                return SSO_OK;
            }
            return SSO_ERR_NOT_FOUND;
        }
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t rbac_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;

    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    const cJSON *roles = cJSON_GetObjectItem(root, "roles");
    if (!cJSON_IsArray(roles)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    cJSON_Delete(root);
    return SSO_OK;
}

/* ========================================================================
 * Strategy vtable
 * ======================================================================== */
permission_strategy_t rbac_perm_strategy = {
    .type          = PERM_STRATEGY_RBAC,
    .name          = "rbac",
    .init          = rbac_init,
    .destroy       = rbac_destroy,
    .compile_rules = rbac_compile,
    .free_compiled_rules = rbac_free_compiled,
    .evaluate      = rbac_evaluate,
    .validate_rules = rbac_validate,
    .userdata      = NULL,
};
