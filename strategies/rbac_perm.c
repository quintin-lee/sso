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
 * Evaluation:
 *   Look up role_name from eval_context in the policy's role list.
 *   - If user holds the role → return the rule's effect (allow/deny)
 *   - If user does not hold the role → skip this rule
 *   - If no rule matches the checked role → SSO_ERR_NOT_FOUND
 *
 * The engine handles DENY-overrides at a higher level.
 */

#include "sso.h"
#include "policy.h"
#include "role.h"
#include "user.h"
#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Helper: check if a user ID holds a named role.
 * Uses the storage backend's get_user_roles_with_ancestors for an
 * efficient single-query lookup that avoids N+1 hierarchy walks.
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

    /* Use the bulk query to get all role IDs (direct + inherited)
     * for this user in a single operation. */
    if (!sb->get_user_roles_with_ancestors) {
        /* Fallback if the backend doesn't support this interface. */
        return false;
    }

    sso_id_t user_role_ids[128];
    size_t count = 128;
    sso_error_t err = sb->get_user_roles_with_ancestors(sb, user_id,
                                                         user_role_ids,
                                                         &count, 128);
    if (err != SSO_OK) return false;

    /* Check if the target role ID appears in the result set. */
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
    self->userdata = ctx; /* store sso_context for role/user lookups */
    return SSO_OK;
}

static void rbac_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t rbac_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *role_name = ctx->params.rbac.role_name;
    if (!role_name || role_name[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    sso_context_t *sso_ctx = (sso_context_t *)self->userdata;
    if (!sso_ctx) return SSO_ERR_NOT_FOUND;

    /* Parse rules JSON — find matching role name and return its effect */
    const char *p = policy->rules;
    const char *search_key = "\"name\"";
    const char *name_pos;

    while ((name_pos = strstr(p, search_key)) != NULL) {
        /* Move past "name": to the value */
        const char *val = name_pos + strlen(search_key);
        while (*val && *val != ':') val++;
        if (*val == ':') val++;
        while (*val && (*val == ' ' || *val == '\t' || *val == '\n')) val++;
        if (*val == '"') val++;

        /* Find end of name value */
        const char *val_end = val;
        while (*val_end && *val_end != '"') val_end++;

        /* Extract and compare role name */
        size_t name_len = (size_t)(val_end - val);
        char extracted[64];
        size_t copy_len = name_len < sizeof(extracted) - 1 ? name_len : sizeof(extracted) - 1;
        strncpy(extracted, val, copy_len);
        extracted[copy_len] = '\0';

        if (strcmp(extracted, role_name) == 0) {
            /* Found matching role — find its effect */
            const char *eff = strstr(name_pos, "\"effect\"");
            if (!eff) { p = val_end + 1; continue; }

            const char *eff_val = eff + strlen("\"effect\"");
            while (*eff_val && (*eff_val == ' ' || *eff_val == '\t' || *eff_val == '\n'
                   || *eff_val == ':')) eff_val++;
            if (*eff_val == '"') eff_val++;

            bool is_allow = (strncmp(eff_val, "allow", 5) == 0);

            /* Now check if the user actually holds this role */
            if (user_has_role(sso_ctx, ctx->user_id, role_name)) {
                *result = is_allow;
                return SSO_OK;
            }
            /* User doesn't have the role — this rule doesn't apply */
            return SSO_ERR_NOT_FOUND;
        }

        p = val_end + 1;
    }

    return SSO_ERR_NOT_FOUND; /* no matching role rule found */
}

static sso_error_t rbac_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;

    if (strstr(rules_json, "\"roles\"") == NULL) {
        return SSO_ERR_RULE_INVALID;
    }

    if (rules_json[0] != '{') return SSO_ERR_RULE_INVALID;

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
    .evaluate      = rbac_evaluate,
    .validate_rules = rbac_validate,
    .userdata      = NULL,
};
