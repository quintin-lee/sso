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
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Permission engine structure (opaque).
 */
typedef struct permission_engine permission_engine_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new permission engine instance.
 * 
 * Strategies must be registered after creation and before evaluating.
 * 
 * @param engine Out-pointer to hold the address of the created engine.
 * @param ctx Context back-pointer.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t perm_engine_create(permission_engine_t **engine, sso_context_t *ctx);

/**
 * @brief Destroys the permission engine.
 * 
 * Unregisters and cleans up all active strategies and caches.
 * 
 * @param engine Engine instance to destroy.
 */
void        perm_engine_destroy(permission_engine_t *engine);

/* -----------------------------------------------------------------------
 * Strategy registry
 * ----------------------------------------------------------------------- */

/**
 * @brief Registers a permission evaluation strategy.
 * 
 * @param engine Engine instance.
 * @param strategy Pointer to strategy object.
 * @return SSO_OK, or SSO_ERR_STRATEGY_CONFLICT if type already registered.
 */
sso_error_t perm_engine_register_strategy(permission_engine_t *engine,
                                          permission_strategy_t *strategy);

/**
 * @brief Unregisters a strategy by its type.
 * 
 * @param engine Engine instance.
 * @param type Strategy type.
 * @return SSO_OK, or SSO_ERR_STRATEGY_NOT_FOUND.
 */
sso_error_t perm_engine_unregister_strategy(permission_engine_t *engine,
                                            perm_strategy_type_t type);

/**
 * @brief Looks up a registered strategy by type.
 * 
 * @param engine Engine instance.
 * @param type Strategy type.
 * @return Pointer to registered strategy, or NULL if not found.
 */
permission_strategy_t *perm_engine_get_strategy(permission_engine_t *engine,
                                                perm_strategy_type_t type);

/* -----------------------------------------------------------------------
 * Cache management
 * ----------------------------------------------------------------------- */

/**
 * @brief Invalidates cached evaluation results for a specific user.
 * 
 * Call this immediately when a user's role/group assignments are modified.
 * 
 * @param engine Engine instance.
 * @param user_id User ID.
 */
void        perm_engine_cache_invalidate_user(permission_engine_t *engine, sso_id_t user_id);

/**
 * @brief Invalidates cached compiled AST/objects for a specific policy.
 * 
 * Call this immediately when a policy's rules configuration is updated.
 * 
 * @param engine Engine instance.
 * @param policy_id Policy ID.
 */
void        perm_engine_cache_invalidate_policy(permission_engine_t *engine, sso_id_t policy_id);

/**
 * @brief Invalidates all caches (compiled rules and resolved results).
 * 
 * @param engine Engine instance.
 */
void        perm_engine_cache_invalidate_all(permission_engine_t *engine);

/* -----------------------------------------------------------------------
 * Metrics
 * ----------------------------------------------------------------------- */

/**
 * @brief Retrieves Prometheus-compatible evaluation engine metrics.
 * 
 * @param engine Engine instance.
 * @param buf Output string buffer.
 * @param max Buffer capacity.
 */
sso_error_t perm_engine_get_metrics(permission_engine_t *engine, char *buf, size_t max);

/* -----------------------------------------------------------------------
 * Evaluation
 * ----------------------------------------------------------------------- */

/**
 * @brief High-level permission check for an evaluation context.
 * 
 * Resolves all policies applicable to the user (via direct, role, group hierarchies),
 * compiles/validates them, executes them through respective strategies in priority order,
 * and enforces DENY-overrides semantics. Defaults to DENY if no policies match.
 * 
 * @param engine Engine instance.
 * @param ctx Evaluation parameters (subject, resource, action, env attributes).
 * @param result Output decision value (true = ALLOW, false = DENY).
 * @param decision_trace Output trace path explanation, caller must free.
 * @return SSO_OK on successful evaluation, or error code on failure.
 */
sso_error_t perm_engine_evaluate(permission_engine_t *engine,
                                 eval_context_t *ctx,
                                 bool *result,
                                 char **decision_trace);

/**
 * @brief Fine-grained check: evaluate a single policy against the context.
 * 
 * bypasses normal policy resolution. Useful for testing policy rules.
 * 
 * @param engine Engine instance.
 * @param policy Policy to evaluate.
 * @param ctx Evaluation context.
 * @param result Output decision.
 * @param decision_trace Output trace description, caller must free.
 */
sso_error_t perm_engine_evaluate_policy(permission_engine_t *engine,
                                        const policy_t *policy,
                                        eval_context_t *ctx,
                                        bool *result,
                                        char **decision_trace);

/* -----------------------------------------------------------------------
 * Convenience: one-shot check for common cases
 * ----------------------------------------------------------------------- */

/**
 * @brief One-shot functional permission check.
 * 
 * Checks whether user has permission to execute code block (e.g. "user:create").
 * 
 * @param ctx SSO context.
 * @param user_id User ID.
 * @param function_code Code identifier string.
 * @param allowed Output decision.
 */
sso_error_t perm_check_function(sso_context_t *ctx, sso_id_t user_id,
                                const char *function_code, bool *allowed);

/**
 * @brief One-shot API path matching check.
 * 
 * @param ctx SSO context.
 * @param user_id User ID.
 * @param method HTTP method (GET, POST, etc.).
 * @param path Request path (e.g. "/api/v1/users").
 * @param allowed Output decision.
 */
sso_error_t perm_check_api(sso_context_t *ctx, sso_id_t user_id,
                           const char *method, const char *path, bool *allowed);

/**
 * @brief One-shot data filtering scope check.
 * 
 * Evaluates row/column filters on a record, returning allowed status and field filters.
 * 
 * @param ctx SSO context.
 * @param user_id User ID.
 * @param resource_type Resource name.
 * @param record_json Record data JSON.
 * @param allowed Output decision.
 * @param field_filter Output list of blacklisted column/field name strings.
 * @param field_count Size of field_filter array.
 */
sso_error_t perm_check_data(sso_context_t *ctx, sso_id_t user_id,
                            const char *resource_type, const char *record_json,
                            bool *allowed, char ***field_filter, size_t *field_count);

/**
 * @brief One-shot Role-membership check.
 * 
 * @param ctx SSO context.
 * @param user_id User ID.
 * @param role_name Role name string.
 * @param allowed Output decision.
 */
sso_error_t perm_check_rbac(sso_context_t *ctx, sso_id_t user_id,
                            const char *role_name, bool *allowed);

/**
 * @brief One-shot Location/IP scope check.
 * 
 * @param ctx SSO context.
 * @param user_id User ID.
 * @param source_ip Requester IP address.
 * @param geo_country Geolocation country name.
 * @param allowed Output decision.
 */
sso_error_t perm_check_location(sso_context_t *ctx, sso_id_t user_id,
                                const char *source_ip, const char *geo_country,
                                bool *allowed);

/**
 * @brief One-shot Label-Based Access Control (LBAC) check.
 * 
 * @param ctx SSO context.
 * @param user_id User ID.
 * @param user_labels User clearance labels.
 * @param resource_label Resource sensitivity label.
 * @param allowed Output decision.
 */
sso_error_t perm_check_lbac(sso_context_t *ctx, sso_id_t user_id,
                            const char *user_labels, const char *resource_label,
                            bool *allowed);

/**
 * @brief One-shot Attribute-Based Access Control (ABAC) check.
 * 
 * @param ctx SSO context.
 * @param user_id User ID.
 * @param subject_attrs Subject attributes JSON.
 * @param resource_attrs Resource attributes JSON.
 * @param action Action string.
 * @param allowed Output decision.
 */
sso_error_t perm_check_abac(sso_context_t *ctx, sso_id_t user_id,
                            const char *subject_attrs,
                            const char *resource_attrs,
                            const char *action,
                            bool *allowed);

/* -----------------------------------------------------------------------
 * Admin audit log — key CRUD operations from the admin pages
 * ----------------------------------------------------------------------- */

/**
 * @brief Writes an admin CRUD operation entry to the unified audit log.
 *
 * Logs: timestamp, actor (user_id + username), client_ip, operation,
 * resource type, resource ID, status (success/failure), and details.
 *
 * Uses the same audit log file and mutex as permission check logs.
 *
 * @param cfg SSO config (for audit_log_path).
 * @param actor_user_id ID of the admin who performed the action.
 * @param actor_username Username of the admin.
 * @param client_ip Requester IP address.
 * @param operation Operation name (e.g. "create_user", "delete_policy").
 * @param resource Resource type (e.g. "users", "roles", "policies").
 * @param resource_id ID of the affected resource (0 if N/A).
 * @param status "success" or "failure".
 * @param details Human-readable description of the operation.
 */
void admin_audit_log(sso_config_t *cfg,
                     sso_id_t actor_user_id, const char *actor_username,
                     const char *client_ip,
                     const char *operation, const char *resource,
                     sso_id_t resource_id,
                     const char *status, const char *details);

#ifdef __cplusplus
}
#endif

#endif /* SSO_PERMISSION_H */
