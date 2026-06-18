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

/**
 * @struct policy
 * @brief Defines access rules and evaluation parameters.
 */
struct policy {
    sso_id_t              id;                               /**< Unique 64-bit policy ID */
    char                  name[SSO_MAX_POLICY_NAME];        /**< Unique policy name string */
    perm_strategy_type_t  strategy_type;                    /**< Target evaluation strategy type */
    policy_effect_t       effect;                           /**< ALLOW or DENY effect */
    int                   priority;                         /**< Priority value (higher priority evaluated first) */
    char                  rules[SSO_MAX_RULES_JSON];        /**< Strategy-specific rule configuration (JSON string) */
    void                 *compiled_rules;                   /**< Cached pre-compiled AST/struct representation */
    policy_status_t       status;                           /**< Enabled or disabled status */
    sso_timestamp_t       created_at;                       /**< Timestamp when policy was created */
    sso_timestamp_t       updated_at;                       /**< Timestamp of last policy update */
};

/**
 * @brief Policy manager structure (opaque).
 */
typedef struct policy_manager policy_manager_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new policy manager instance.
 * 
 * @param mgr Out-pointer to hold the address of the created manager.
 * @param ctx Context back-pointer.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t policy_manager_create(policy_manager_t **mgr, sso_context_t *ctx);

/**
 * @brief Destroys the policy manager instance.
 * 
 * @param mgr Manager instance.
 */
void        policy_manager_destroy(policy_manager_t *mgr);

/* -----------------------------------------------------------------------
 * CRUD
 * ----------------------------------------------------------------------- */

/**
 * @brief Creates a new policy.
 * 
 * @param mgr Policy manager.
 * @param name Unique policy name.
 * @param strategy Evaluation strategy.
 * @param effect Effect (ALLOW or DENY).
 * @param priority Execution priority.
 * @param rules_json Plaintext JSON rules configuration.
 * @param out Output policy structure.
 * @return SSO_OK on success, or error code on failure.
 */
sso_error_t policy_create(policy_manager_t *mgr, const char *name,
                          perm_strategy_type_t strategy, policy_effect_t effect,
                          int priority, const char *rules_json,
                          policy_t *out);

/**
 * @brief Resolves a policy by ID.
 * 
 * @param mgr Policy manager.
 * @param id Policy ID.
 * @param out Output structure.
 */
sso_error_t policy_get_by_id(policy_manager_t *mgr, sso_id_t id, policy_t *out);

/**
 * @brief Resolves a policy by name.
 * 
 * @param mgr Policy manager.
 * @param name Policy name string.
 * @param out Output structure.
 */
sso_error_t policy_get_by_name(policy_manager_t *mgr, const char *name, policy_t *out);

/**
 * @brief Updates policy fields in database.
 * 
 * ID must be set in policy structure.
 * 
 * @param mgr Policy manager.
 * @param policy Pointer to policy structure containing updates.
 */
sso_error_t policy_update(policy_manager_t *mgr, const policy_t *policy);

/**
 * @brief Deletes a policy by ID.
 * 
 * Removes all attachments to targets (roles, groups, users).
 * 
 * @param mgr Policy manager.
 * @param id Policy ID to delete.
 */
sso_error_t policy_delete(policy_manager_t *mgr, sso_id_t id);

/**
 * @brief Lists policy IDs matching filters with pagination.
 * 
 * @param mgr Policy manager.
 * @param q Optional search term (matches name).
 * @param status Status filter (-1 for all).
 * @param offset Pagination offset.
 * @param limit Pagination limit.
 * @param ids Output array for matching policy IDs.
 * @param count Output size of returned IDs.
 * @param total_count Output total count of matches in database.
 */
sso_error_t policy_list(policy_manager_t *mgr, const char *q, int status,
                        int offset, int limit,
                        sso_id_t *ids, size_t *count, size_t *total_count);

/* -----------------------------------------------------------------------
 * Assignment (policy ↔ role / group / user)
 * ----------------------------------------------------------------------- */

/**
 * @brief Attaches a policy to a target (user, role, or group).
 * 
 * @param mgr Policy manager.
 * @param policy_id Policy ID.
 * @param target_type Type of target (user, role, or group).
 * @param target_id Target ID.
 */
sso_error_t policy_assign_to(policy_manager_t *mgr, sso_id_t policy_id,
                             policy_target_type_t target_type, sso_id_t target_id);

/**
 * @brief Detaches a policy from a target.
 * 
 * @param mgr Policy manager.
 * @param policy_id Policy ID.
 * @param target_type Type of target (user, role, or group).
 * @param target_id Target ID.
 */
sso_error_t policy_unassign_from(policy_manager_t *mgr, sso_id_t policy_id,
                                 policy_target_type_t target_type, sso_id_t target_id);

/**
 * @brief Gets all policies directly assigned to a specific target (user/role/group).
 *
 * @param mgr Policy manager.
 * @param target_type Type of target (POLICY_TARGET_USER, POLICY_TARGET_ROLE, or POLICY_TARGET_GROUP).
 * @param target_id Target ID.
 * @param policies Output array of policy_t structs.
 * @param count Output count of policies found.
 * @param max Max capacity of policies array.
 */
sso_error_t policy_get_direct_policies(policy_manager_t *mgr,
                                        policy_target_type_t target_type,
                                        sso_id_t target_id,
                                        policy_t *policies,
                                        size_t *count, size_t max);

/**
 * @brief Gets all target IDs of a given type that the policy is assigned to.
 * 
 * @param mgr Policy manager.
 * @param policy_id Policy ID.
 * @param target_type Type of targets to fetch.
 * @param target_ids Output array for target IDs.
 * @param count Output count of target IDs.
 * @param max Max capacity of target_ids array.
 */
sso_error_t policy_get_targets(policy_manager_t *mgr, sso_id_t policy_id,
                               policy_target_type_t target_type,
                               sso_id_t *target_ids, size_t *count, size_t max);

/* -----------------------------------------------------------------------
 * Policy resolution — gather all policies applicable to a user
 * ----------------------------------------------------------------------- */

/**
 * @brief Resolves all active policies applicable to a user.
 * 
 * Traverses user assignments, group memberships (and parent groups), and roles
 * (and parent roles) to aggregate all applicable policies.
 * 
 * @param mgr Policy manager.
 * @param user_id User ID.
 * @param policies Output array to populate with resolved policy structures (sorted by priority descending).
 * @param count Output size of resolved policies.
 * @param max Max capacity of policies array.
 */
sso_error_t policy_resolve_for_user(policy_manager_t *mgr, sso_id_t user_id,
                                    policy_t *policies, size_t *count, size_t max);

/**
 * @brief Validates rules JSON syntax against the policy's strategy parser.
 * 
 * @param mgr Policy manager.
 * @param policy Policy containing rules JSON and strategy type.
 */
sso_error_t policy_validate_rules(policy_manager_t *mgr, const policy_t *policy);

/**
 * @brief Enables or disables a policy.
 * 
 * @param mgr Policy manager.
 * @param policy_id Policy ID.
 * @param status Target status value.
 */
sso_error_t policy_set_status(policy_manager_t *mgr, sso_id_t policy_id,
                              policy_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* SSO_POLICY_H */
