/*
 * permission.c — Permission engine and strategy registry.
 *
 * The engine maintains a small array of registered strategy pointers.
 * On evaluate(), it resolves the applicable policies via policy_manager
 * and iterates them in priority order, dispatching each to the correct
 * strategy's evaluate().  DENY-overrides semantics: any single DENY
 * causes the entire result to be DENY.
 *
 * Thread-safety: the registry is read-mostly after init.  This implementation
 * does NOT add locking; a production version should use an RW-lock.
 */

#include "sso.h"
#include "permission.h"
#include "policy.h"
#include "user.h"
#include "role.h"
#include "group.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ========================================================================
 * Built-in strategy declarations (defined in strategies/ dir)
 * ======================================================================== */
extern permission_strategy_t func_perm_strategy;
extern permission_strategy_t api_perm_strategy;
extern permission_strategy_t data_perm_strategy;
extern permission_strategy_t rbac_perm_strategy;
extern permission_strategy_t lbac_perm_strategy;
extern permission_strategy_t abac_perm_strategy;

/* ========================================================================
 * Engine structure (private)
 * ======================================================================== */
#define MAX_STRATEGIES 16

struct permission_engine {
    sso_context_t          *ctx;
    permission_strategy_t  *strategies[MAX_STRATEGIES];
    size_t                  strategy_count;
};

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

sso_error_t perm_engine_create(permission_engine_t **engine, sso_context_t *ctx) {
    if (!engine || !ctx) return SSO_ERR_INVALID_PARAM;

    *engine = (permission_engine_t *)calloc(1, sizeof(permission_engine_t));
    if (!*engine) return SSO_ERR_OUT_OF_MEMORY;

    (*engine)->ctx = ctx;
    (*engine)->strategy_count = 0;

    sso_error_t err;

    /* Register the six built-in strategies */
    if ((err = perm_engine_register_strategy(*engine, &func_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &api_perm_strategy))  != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &data_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &rbac_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &lbac_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &abac_perm_strategy)) != SSO_OK) {
        perm_engine_destroy(*engine);
        return err;
    }

    return SSO_OK;
}

void perm_engine_destroy(permission_engine_t *engine) {
    if (!engine) return;
    for (size_t i = 0; i < engine->strategy_count; i++) {
        if (engine->strategies[i] && engine->strategies[i]->destroy) {
            engine->strategies[i]->destroy(engine->strategies[i]);
        }
    }
    free(engine);
}

/* ========================================================================
 * Strategy registry
 * ======================================================================== */

sso_error_t perm_engine_register_strategy(permission_engine_t *engine,
                                          permission_strategy_t *strategy) {
    if (!engine || !strategy) return SSO_ERR_INVALID_PARAM;

    /* Check for duplicates */
    for (size_t i = 0; i < engine->strategy_count; i++) {
        if (engine->strategies[i]->type == strategy->type) {
            return SSO_ERR_STRATEGY_CONFLICT;
        }
    }

    if (engine->strategy_count >= MAX_STRATEGIES) {
        return SSO_ERR_OUT_OF_MEMORY;
    }

    engine->strategies[engine->strategy_count++] = strategy;

    /* Call init if provided */
    if (strategy->init) {
        return strategy->init(strategy, engine->ctx);
    }

    return SSO_OK;
}

sso_error_t perm_engine_unregister_strategy(permission_engine_t *engine,
                                            perm_strategy_type_t type) {
    if (!engine) return SSO_ERR_INVALID_PARAM;

    for (size_t i = 0; i < engine->strategy_count; i++) {
        if (engine->strategies[i]->type == type) {
            if (engine->strategies[i]->destroy) {
                engine->strategies[i]->destroy(engine->strategies[i]);
            }
            /* Shift remaining strategies down */
            for (size_t j = i; j < engine->strategy_count - 1; j++) {
                engine->strategies[j] = engine->strategies[j + 1];
            }
            engine->strategy_count--;
            return SSO_OK;
        }
    }

    return SSO_ERR_STRATEGY_NOT_FOUND;
}

permission_strategy_t *perm_engine_get_strategy(permission_engine_t *engine,
                                                perm_strategy_type_t type) {
    if (!engine) return NULL;
    for (size_t i = 0; i < engine->strategy_count; i++) {
        if (engine->strategies[i]->type == type) {
            return engine->strategies[i];
        }
    }
    return NULL;
}

/* ========================================================================
 * Evaluation — core decision logic
 * ======================================================================== */

sso_error_t perm_engine_evaluate_policy(permission_engine_t *engine,
                                        const policy_t *policy,
                                        eval_context_t *ctx,
                                        bool *result) {
    if (!engine || !policy || !ctx || !result) return SSO_ERR_INVALID_PARAM;

    /* Skip disabled policies */
    if (policy->status == POLICY_STATUS_DISABLED) {
        *result = true; /* neutral — skip this policy */
        return SSO_OK;
    }

    /* Find the strategy for this policy */
    permission_strategy_t *strategy =
        perm_engine_get_strategy(engine, policy->strategy_type);
    if (!strategy) {
        return SSO_ERR_STRATEGY_NOT_FOUND;
    }

    if (!strategy->evaluate) {
        return SSO_ERR_NOT_IMPLEMENTED;
    }

    /* Strategy evaluate sets *result = true for ALLOW, false for DENY.
     * Returns SSO_OK if the policy's rules apply to this request.
     * Returns SSO_ERR_NOT_FOUND if no rule matches (policy is neutral). */
    bool strategy_result = false;
    sso_error_t err = strategy->evaluate(strategy, ctx, policy, &strategy_result);
    if (err == SSO_ERR_NOT_FOUND) {
        return SSO_ERR_NOT_FOUND; /* policy didn't match — neutral, propagate to caller */
    }
    if (err != SSO_OK) return err;

    /* Strategy matched a rule — use its result directly:
     *   true  → ALLOW (access is granted by this policy)
     *   false → DENY (this policy explicitly denies) */
    *result = strategy_result;
    return SSO_OK;
}

sso_error_t perm_engine_evaluate(permission_engine_t *engine,
                                 eval_context_t *ctx,
                                 bool *result) {
    if (!engine || !ctx || !result) return SSO_ERR_INVALID_PARAM;
    if (!ctx->user && ctx->user_id == 0) return SSO_ERR_INVALID_PARAM;

    *result = false; /* default: deny */
    sso_error_t err;

    /* 1. Resolve all policies applicable to this user */
    policy_manager_t *pmgr = (policy_manager_t *)engine->ctx->policy_mgr;
    if (!pmgr) return SSO_ERR_GENERAL;

    policy_t policies[64];
    size_t policy_count = 0;
    size_t max_policies = 64;

    err = policy_resolve_for_user(pmgr, ctx->user_id, policies, &policy_count, max_policies);
    if (err != SSO_OK && err != SSO_ERR_NOT_FOUND) return err;

    if (policy_count == 0) {
        /* No policies apply → default-deny */
        return SSO_OK;
    }

    /* 2. Evaluate each policy.  DENY-overrides: one DENY → result is DENY. */
    bool any_allowed = false;

    for (size_t i = 0; i < policy_count; i++) {
        bool policy_result = false;
        err = perm_engine_evaluate_policy(engine, &policies[i], ctx, &policy_result);
        if (err == SSO_ERR_NOT_FOUND) {
            continue; /* neutral — policy didn't match this request, skip */
        }
        if (err != SSO_OK) continue; /* skip broken policies */

        if (!policy_result) {
            /* This policy explicitly denies — DENY overrides */
            *result = false;
            return SSO_OK;
        }

        /* Policy matched and allowed */
        any_allowed = true;
    }

    *result = any_allowed;
    return SSO_OK;
}

/* ========================================================================
 * Convenience one-shot checkers
 * ======================================================================== */

sso_error_t perm_check_function(sso_context_t *ctx, sso_id_t user_id,
                                const char *function_code, bool *allowed) {
    if (!ctx || !function_code || !allowed) return SSO_ERR_INVALID_PARAM;

    /* Fetch user */
    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    /* Set up eval context */
    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    strncpy(ectx.params.functional.function_code, function_code,
            sizeof(ectx.params.functional.function_code) - 1);

    /* Evaluate */
    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed);
    eval_context_destroy(&ectx);
    return err;
}

sso_error_t perm_check_api(sso_context_t *ctx, sso_id_t user_id,
                           const char *method, const char *path, bool *allowed) {
    if (!ctx || !method || !path || !allowed) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    strncpy(ectx.params.api.http_method, method, sizeof(ectx.params.api.http_method) - 1);
    strncpy(ectx.params.api.request_path, path, sizeof(ectx.params.api.request_path) - 1);

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed);
    eval_context_destroy(&ectx);
    return err;
}

sso_error_t perm_check_data(sso_context_t *ctx, sso_id_t user_id,
                            const char *resource_type, const char *record_json,
                            bool *allowed, char ***field_filter, size_t *field_count) {
    if (!ctx || !resource_type || !allowed) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    strncpy(ectx.params.data.resource_type, resource_type,
            sizeof(ectx.params.data.resource_type) - 1);
    if (record_json) {
        ectx.params.data.record = strdup(record_json);
        ectx.params.data.record_len = strlen(record_json);
    }
    ectx.params.data.field_filter = NULL;
    ectx.params.data.field_filter_count = 0;

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed);

    /* Pass back field filter if the data strategy populated it */
    if (err == SSO_OK && field_filter && field_count) {
        *field_filter = ectx.params.data.field_filter;
        *field_count = ectx.params.data.field_filter_count;
        /* Zero the context copy so eval_context_destroy doesn't free it */
        ectx.params.data.field_filter = NULL;
        ectx.params.data.field_filter_count = 0;
        eval_context_destroy(&ectx);
    } else {
        eval_context_destroy(&ectx);
    }

    return err;
}

sso_error_t perm_check_rbac(sso_context_t *ctx, sso_id_t user_id,
                            const char *role_name, bool *allowed) {
    if (!ctx || !role_name || !allowed) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    strncpy(ectx.params.rbac.role_name, role_name,
            sizeof(ectx.params.rbac.role_name) - 1);

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed);
    eval_context_destroy(&ectx);
    return err;
}

sso_error_t perm_check_lbac(sso_context_t *ctx, sso_id_t user_id,
                            const char *source_ip, const char *geo_country,
                            bool *allowed) {
    if (!ctx || !source_ip || !allowed) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    strncpy(ectx.params.lbac.source_ip, source_ip,
            sizeof(ectx.params.lbac.source_ip) - 1);
    if (geo_country) {
        strncpy(ectx.params.lbac.geo_country, geo_country,
                sizeof(ectx.params.lbac.geo_country) - 1);
    }

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed);
    eval_context_destroy(&ectx);
    return err;
}

sso_error_t perm_check_abac(sso_context_t *ctx, sso_id_t user_id,
                            const char *subject_attrs,
                            const char *resource_attrs,
                            const char *action,
                            bool *allowed) {
    if (!ctx || !allowed) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    if (subject_attrs) {
        strncpy(ectx.params.abac.subject_attrs, subject_attrs,
                sizeof(ectx.params.abac.subject_attrs) - 1);
    }
    if (resource_attrs) {
        strncpy(ectx.params.abac.resource_attrs, resource_attrs,
                sizeof(ectx.params.abac.resource_attrs) - 1);
    }
    if (action) {
        strncpy(ectx.params.abac.action, action,
                sizeof(ectx.params.abac.action) - 1);
    }

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed);
    eval_context_destroy(&ectx);
    return err;
}
