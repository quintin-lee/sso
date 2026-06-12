/*
 * sso.h — Core types, error codes, and forward declarations for the SSO system.
 *
 * This is the master header that defines the foundation shared by every module.
 * Strategy pattern via function pointers enables polymorphic permission evaluation.
 *
 * Architecture:
 *   ┌─────────────────────────────────────────────────────┐
 *   │                  Management API (HTTP)               │
 *   ├──────────┬──────────┬──────────┬─────────────────────┤
 *   │   User   │   Role   │  Group   │   Policy Engine     │
 *   │  Manager │  Manager │ Manager  │  (Strategy Router)  │
 *   ├──────────┴──────────┴──────────┴─────────────────────┤
 *   │             Permission Strategy Layer                 │
 *   │  [Functional] [API Endpoint] [Data Scope]             │
 *   │  [RBAC]       [LBAC]        [ABAC]                    │
 *   ├───────────────────────────────────────────────────────┤
 *   │               Token / Session Manager                 │
 *   ├───────────────────────────────────────────────────────┤
 *   │              Storage Backend (SQLite/File)            │
 *   └───────────────────────────────────────────────────────┘
 */

#ifndef SSO_CORE_H
#define SSO_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Version
 * ======================================================================== */
#define SSO_VERSION_MAJOR 1
#define SSO_VERSION_MINOR 0
#define SSO_VERSION_PATCH 0

/* ========================================================================
 * Constants
 * ======================================================================== */
#define SSO_MAX_USERNAME      64
#define SSO_MAX_EMAIL         128
#define SSO_MAX_DISPLAY_NAME  128
#define SSO_MAX_PASSWORD_HASH 256
#define SSO_MAX_ROLE_NAME     64
#define SSO_MAX_GROUP_NAME    64
#define SSO_MAX_POLICY_NAME   64
#define SSO_MAX_STRATEGY_NAME 64
#define SSO_MAX_DESCRIPTION   512
#define SSO_MAX_RULES_JSON    8192
#define SSO_MAX_TOKEN_STR     512
#define SSO_MAX_CLAIMS_JSON   2048
#define SSO_MAX_ATTRIBUTES    2048
#define SSO_MAX_PATH          256

/* ========================================================================
 * ID type — 64-bit unsigned, 0 is reserved meaning "none"
 * ======================================================================== */
typedef uint64_t sso_id_t;
#define SSO_ID_NONE  ((sso_id_t)0)

/* ========================================================================
 * Error codes
 * ======================================================================== */
typedef enum {
    SSO_OK                   =  0,
    SSO_ERR_GENERAL          = -1,
    SSO_ERR_NOT_FOUND        = -2,
    SSO_ERR_ALREADY_EXISTS   = -3,
    SSO_ERR_INVALID_PARAM    = -4,
    SSO_ERR_NO_PERMISSION    = -5,
    SSO_ERR_AUTH_FAILED      = -6,
    SSO_ERR_TOKEN_EXPIRED    = -7,
    SSO_ERR_TOKEN_INVALID    = -8,
    SSO_ERR_STORAGE          = -9,
    SSO_ERR_STRATEGY_CONFLICT= -10,
    SSO_ERR_STRATEGY_NOT_FOUND=-11,
    SSO_ERR_RULE_INVALID     = -12,
    SSO_ERR_OUT_OF_MEMORY    = -13,
    SSO_ERR_NOT_IMPLEMENTED  = -14,
} sso_error_t;

/* Return a human-readable string for an error code. */
const char *sso_strerror(sso_error_t err);

/* ========================================================================
 * Timestamp (epoch milliseconds)
 * ======================================================================== */
typedef int64_t sso_timestamp_t;
sso_timestamp_t sso_timestamp_now(void);

/* ========================================================================
 * Enums shared across modules
 * ======================================================================== */

/* --- User --- */
typedef enum {
    USER_STATUS_INACTIVE  = 0,
    USER_STATUS_ACTIVE    = 1,
    USER_STATUS_LOCKED    = 2,
} user_status_t;

/* --- Resource owner --- */
typedef enum {
    POLICY_TARGET_USER  = 0,   /* policy assigned directly to a user  */
    POLICY_TARGET_ROLE  = 1,   /* policy assigned to a role          */
    POLICY_TARGET_GROUP = 2,   /* policy assigned to a group         */
} policy_target_type_t;

/* --- Policy effect --- */
typedef enum {
    POLICY_EFFECT_DENY  = 0,
    POLICY_EFFECT_ALLOW = 1,
} policy_effect_t;

/* --- Policy status --- */
typedef enum {
    POLICY_STATUS_DISABLED = 0,
    POLICY_STATUS_ENABLED  = 1,
} policy_status_t;

/* ========================================================================
 * Permission strategy types — each maps to one evaluation algorithm.
 * ======================================================================== */
typedef enum {
    PERM_STRATEGY_FUNCTIONAL = 1,   /* 功能权限: menu / button / feature flags */
    PERM_STRATEGY_API        = 2,   /* 接口权限: HTTP method + path matching   */
    PERM_STRATEGY_DATA       = 3,   /* 数据权限: row / column level filtering   */
    PERM_STRATEGY_RBAC       = 4,   /* 角色权限: role membership check          */
    PERM_STRATEGY_LBAC       = 5,   /* 位置权限: IP/location-based control      */
    PERM_STRATEGY_ABAC       = 6,   /* 属性权限: attribute-based control         */
} perm_strategy_type_t;

/* Return string name for a strategy type. */
const char *perm_strategy_name(perm_strategy_type_t t);

/* ========================================================================
 * Forward declarations — every major module is an opaque struct.
 * Concrete definitions live in their respective headers.
 * ======================================================================== */
typedef struct sso_context       sso_context_t;
typedef struct user              user_t;
typedef struct role              role_t;
typedef struct group             group_t;
typedef struct policy            policy_t;
typedef struct permission_strategy permission_strategy_t;
typedef struct storage_backend   storage_backend_t;
typedef struct token_manager     token_manager_t;
typedef struct token             token_t;
typedef struct eval_context      eval_context_t;
typedef struct sso_server        sso_server_t;

/* ========================================================================
 * SSO Context — root object that wires all subsystems together.
 * Every public API receives a pointer to this context.
 * ======================================================================== */
struct sso_context {
    /* Subsystem pointers (opaque; only the implementation sees internals) */
    void                *storage_backend;
    void                *token_mgr;
    void                *perm_engine;
    void                *user_mgr;
    void                *role_mgr;
    void                *group_mgr;
    void                *policy_mgr;

    /* Configuration (set during sso_init) */
    void                *config;

    /* Extension hook — reserved for future use */
    void                *userdata;
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/* Initialise a new SSO context with the given storage backend and config.
 * Returns SSO_OK on success, or an error code on failure. */
sso_error_t sso_init(sso_context_t *ctx, storage_backend_t *storage, const char *config_json);

/* Tear down the context and free all owned resources. */
void sso_destroy(sso_context_t *ctx);

/* ========================================================================
 * Permission strategy — interface for pluggable evaluation algorithms.
 *
 * This IS the "strategy pattern" in C: each strategy fills a vtable-like
 * struct of function pointers.  The permission engine dispatches to the
 * correct strategy based on the policy's strategy_type field.
 * ======================================================================== */
typedef sso_error_t (*strategy_init_fn)(permission_strategy_t *self, sso_context_t *ctx);
typedef void        (*strategy_destroy_fn)(permission_strategy_t *self);
typedef sso_error_t (*strategy_evaluate_fn)(permission_strategy_t *self,
                                            eval_context_t *ctx,
                                            const policy_t *policy,
                                            bool *result);
typedef sso_error_t (*strategy_validate_fn)(permission_strategy_t *self,
                                            const char *rules_json);

struct permission_strategy {
    perm_strategy_type_t type;          /* discriminator                   */
    char                 name[SSO_MAX_STRATEGY_NAME]; /* human-readable   */

    /* Lifecycle */
    strategy_init_fn     init;
    strategy_destroy_fn  destroy;

    /* Core: evaluate one policy against the provided context.
     * Sets *result = true if the policy ALLOWS, false if DENIES. */
    strategy_evaluate_fn evaluate;

    /* Validate that rules_json is well-formed for this strategy. */
    strategy_validate_fn validate_rules;

    /* Strategy-private data (e.g. compiled rule trie, precomputed maps). */
    void                *userdata;
};

/* ========================================================================
 * Evaluation context — carries everything needed to evaluate a permission.
 *
 * The exact content depends on the strategy type:
 *   - FUNCTIONAL: subject has "function_code" in their allowed set
 *   - API:        subject + HTTP method + request path
 *   - DATA:       subject + resource type + optional field-level filter
 * ======================================================================== */
struct eval_context {
    const user_t        *user;           /* the requesting user         */
    sso_id_t             user_id;        /* user id (convenience)       */
    sso_id_t            *role_ids;       /* roles the user holds        */
    size_t               role_count;
    sso_id_t            *group_ids;      /* groups the user belongs to  */
    size_t               group_count;

    /* Strategy-specific payload (union-like; cast based on strategy type) */
    union {
        /* PERM_STRATEGY_FUNCTIONAL */
        struct {
            char function_code[128];     /* e.g. "user:create" */
        } functional;

        /* PERM_STRATEGY_API */
        struct {
            char http_method[8];         /* GET, POST, PUT, DELETE …    */
            char request_path[SSO_MAX_PATH];
        } api;

        /* PERM_STRATEGY_DATA */
        struct {
            char resource_type[64];      /* e.g. "order", "customer"    */
            char *record;                /* JSON representation of the record */
            size_t record_len;
            char **field_filter;         /* output: allowed fields       */
            size_t field_filter_count;
        } data;

        /* PERM_STRATEGY_RBAC */
        struct {
            char role_name[64];          /* role name to check membership */
        } rbac;

        /* PERM_STRATEGY_LBAC */
        struct {
            char source_ip[64];          /* client IP address             */
            char geo_country[8];         /* ISO country code              */
        } lbac;

        /* PERM_STRATEGY_ABAC */
        struct {
            char subject_attrs[SSO_MAX_ATTRIBUTES];  /* user JSON attributes */
            char resource_attrs[SSO_MAX_ATTRIBUTES]; /* resource JSON attr   */
            char action[64];                          /* action being performed */
        } abac;
    } params;

    /* Custom attributes from the environment (key=value pairs, JSON). */
    char                 environment[SSO_MAX_ATTRIBUTES];
    void                *userdata;
};

/* ========================================================================
 * Helper: create/free an eval_context
 * ======================================================================== */
sso_error_t eval_context_init(eval_context_t *ctx, const user_t *user);
void        eval_context_destroy(eval_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SSO_CORE_H */
