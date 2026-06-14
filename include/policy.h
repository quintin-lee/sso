/*
 * policy.h — Policy configuration module.
 *
 * A policy is a named set of rules evaluated by the strategy's evaluate()
 * function.  Policies can be attached to roles, groups, or individual users.
 *
 * Rules are stored as strategy-specific JSON so each strategy can interpret
 * them in its own way (functional allow/deny lists, API path patterns,
 * data-scope conditions, etc.).
 *
 * When multiple policies apply to a user, the effective permission is
 * determined by priority + DENY-overrides semantics (a single DENY wins).
 */

#ifndef SSO_POLICY_H
#define SSO_POLICY_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Data structure
 * ======================================================================== */
struct policy {
    sso_id_t              id;
    char                  name[SSO_MAX_POLICY_NAME];
    perm_strategy_type_t  strategy_type;   /* which strategy evaluates this */
    policy_effect_t       effect;           /* allow or deny               */
    int                   priority;         /* higher = evaluated first     */
    char                  rules[SSO_MAX_RULES_JSON]; /* strategy-specific  */
    void                 *compiled_rules;   /* pre-compiled AST or object   */
    policy_status_t       status;           /* enabled / disabled           */
    sso_timestamp_t       created_at;
    sso_timestamp_t       updated_at;
};

/* ========================================================================
 * Policy manager (opaque)
 * ======================================================================== */
typedef struct policy_manager policy_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */
sso_error_t policy_manager_create(policy_manager_t **mgr, sso_context_t *ctx);
void        policy_manager_destroy(policy_manager_t *mgr);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */
sso_error_t policy_create(policy_manager_t *mgr, const char *name,
                          perm_strategy_type_t strategy, policy_effect_t effect,
                          int priority, const char *rules_json,
                          policy_t *out);
sso_error_t policy_get_by_id(policy_manager_t *mgr, sso_id_t id, policy_t *out);
sso_error_t policy_get_by_name(policy_manager_t *mgr, const char *name, policy_t *out);
sso_error_t policy_update(policy_manager_t *mgr, const policy_t *policy);
sso_error_t policy_delete(policy_manager_t *mgr, sso_id_t id);
sso_error_t policy_list(policy_manager_t *mgr, const char *q, int status,
                        int offset, int limit,
                        sso_id_t *ids, size_t *count, size_t *total_count);

/* -----------------------------------------------------------------------
 * Assignment (policy ↔ role / group / user)
 * ----------------------------------------------------------------------- */

/* Attach a policy to a role, group, or user. */
sso_error_t policy_assign_to(policy_manager_t *mgr, sso_id_t policy_id,
                             policy_target_type_t target_type, sso_id_t target_id);
sso_error_t policy_unassign_from(policy_manager_t *mgr, sso_id_t policy_id,
                                 policy_target_type_t target_type, sso_id_t target_id);

/* Get all targets of a given type that a policy is assigned to. */
sso_error_t policy_get_targets(policy_manager_t *mgr, sso_id_t policy_id,
                               policy_target_type_t target_type,
                               sso_id_t *target_ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Policy resolution — gather all policies applicable to a user
 * ----------------------------------------------------------------------- */

/* Collect every policy that applies to a given user (direct, via role, via group,
 * including role/group ancestry).  Returns sorted by priority descending. */
sso_error_t policy_resolve_for_user(policy_manager_t *mgr, sso_id_t user_id,
                                    policy_t *policies, size_t *count, size_t max);

/* Validate rules against the policy's declared strategy. */
sso_error_t policy_validate_rules(policy_manager_t *mgr, const policy_t *policy);

/* Enable / disable a policy. */
sso_error_t policy_set_status(policy_manager_t *mgr, sso_id_t policy_id,
                              policy_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* SSO_POLICY_H */
