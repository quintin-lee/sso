/*
 * permission.h — Permission engine and strategy registry.
 *
 * The permission engine is the central decision point.  It owns the
 * registry of permission_strategy_t instances and dispatches evaluation
 * requests to the correct strategy based on the policy's strategy_type.
 *
 * Registration:
 *   perm_engine_register_strategy(engine, &func_perm_strategy);
 *   perm_engine_register_strategy(engine, &api_perm_strategy);
 *   perm_engine_register_strategy(engine, &data_perm_strategy);
 *
 * Evaluation flow:
 *   1. Caller prepares an eval_context_t with user + request details.
 *   2. perm_engine_evaluate() resolves all applicable policies.
 *   3. For each policy, the engine looks up the matching strategy.
 *   4. The strategy's evaluate() interprets the policy's rules JSON.
 *   5. DENY-overrides: if any matching policy returns DENY, result is DENY.
 *   6. If no policy matches, the default effect is DENY (fail-closed).
 */

#ifndef SSO_PERMISSION_H
#define SSO_PERMISSION_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Permission engine (opaque)
 * ======================================================================== */
typedef struct permission_engine permission_engine_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/* Create the permission engine.  Strategies must be registered after creation
 * and before any evaluate calls. */
sso_error_t perm_engine_create(permission_engine_t **engine, sso_context_t *ctx);

/* Destroy the engine and all registered strategies. */
void        perm_engine_destroy(permission_engine_t *engine);

/* -----------------------------------------------------------------------
 * Strategy registry
 * ----------------------------------------------------------------------- */

/* Register a strategy.  Ownership remains with the caller — the engine
 * holds a pointer.  Returns SSO_ERR_STRATEGY_CONFLICT if a strategy with
 * the same type is already registered. */
sso_error_t perm_engine_register_strategy(permission_engine_t *engine,
                                          permission_strategy_t *strategy);

/* Unregister a strategy by type.  Returns SSO_ERR_STRATEGY_NOT_FOUND if
 * the strategy is not registered. */
sso_error_t perm_engine_unregister_strategy(permission_engine_t *engine,
                                            perm_strategy_type_t type);

/* Look up a registered strategy by type. */
permission_strategy_t *perm_engine_get_strategy(permission_engine_t *engine,
                                                perm_strategy_type_t type);

/* -----------------------------------------------------------------------
 * Cache management
 * ----------------------------------------------------------------------- */

/* Clear the decision cache for a specific user. Call this when a user's roles
 * or groups change to ensure immediate consistency. */
void        perm_engine_cache_invalidate_user(permission_engine_t *engine, sso_id_t user_id);

/* Clear the compiled rule cache for a specific policy. Call this when
 * a policy's rules JSON is updated. */
void        perm_engine_cache_invalidate_policy(permission_engine_t *engine, sso_id_t policy_id);

/* Clear all caches (compiled rules and results). */
void        perm_engine_cache_invalidate_all(permission_engine_t *engine);

/* -----------------------------------------------------------------------
 * Evaluation
 * ----------------------------------------------------------------------- */

/* High-level evaluation: given an eval_context, resolve every applicable
 * policy and run each through its strategy.  Returns:
 *   SSO_OK           → *result is valid (true = ALLOW, false = DENY)
 *   SSO_ERR_*        → evaluation failed; result is DENY
 *
 * Semantics: DENY-overrides — if ANY evaluated policy denies, the result
 * is DENY, regardless of how many ALLOWs exist.  If no policy matches,
 * the result is DENY (default-deny / fail-closed).
 */
sso_error_t perm_engine_evaluate(permission_engine_t *engine,
                                 eval_context_t *ctx,
                                 bool *result,
                                 char **decision_trace);

/* Fine-grained: evaluate only a single policy through its strategy.
 * Useful for policy-testing UIs and dry-run scenarios. */
sso_error_t perm_engine_evaluate_policy(permission_engine_t *engine,
                                        const policy_t *policy,
                                        eval_context_t *ctx,
                                        bool *result,
                                        char **decision_trace);

/* -----------------------------------------------------------------------
 * Convenience: one-shot check for common cases
 * ----------------------------------------------------------------------- */

/* Functional permission check — does user have function "user:create"? */
sso_error_t perm_check_function(sso_context_t *ctx, sso_id_t user_id,
                                const char *function_code, bool *allowed);

/* API permission check — can the user call POST /api/v1/users? */
sso_error_t perm_check_api(sso_context_t *ctx, sso_id_t user_id,
                           const char *method, const char *path, bool *allowed);

/* Data permission check — what data access does the user have for "order"? */
sso_error_t perm_check_data(sso_context_t *ctx, sso_id_t user_id,
                            const char *resource_type, const char *record_json,
                            bool *allowed, char ***field_filter, size_t *field_count);

/* RBAC permission check — does the user hold the named role? */
sso_error_t perm_check_rbac(sso_context_t *ctx, sso_id_t user_id,
                            const char *role_name, bool *allowed);

/* LOCATION permission check — does the source IP match allowed location rules? */
sso_error_t perm_check_location(sso_context_t *ctx, sso_id_t user_id,
                                const char *source_ip, const char *geo_country,
                                bool *allowed);

/* LBAC (Label-Based) permission check — check security labels */
sso_error_t perm_check_lbac(sso_context_t *ctx, sso_id_t user_id,
                            const char *user_labels, const char *resource_label,
                            bool *allowed);

/* ABAC permission check — evaluate attribute-based conditions */
sso_error_t perm_check_abac(sso_context_t *ctx, sso_id_t user_id,
                            const char *subject_attrs,
                            const char *resource_attrs,
                            const char *action,
                            bool *allowed);

#ifdef __cplusplus
}
#endif

#endif /* SSO_PERMISSION_H */
