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
#include <pthread.h>
#include <stdatomic.h>

/* ========================================================================
 * Built-in strategy declarations (defined in strategies/ dir)
 * ======================================================================== */
extern permission_strategy_t func_perm_strategy;
extern permission_strategy_t api_perm_strategy;
extern permission_strategy_t data_perm_strategy;
extern permission_strategy_t rbac_perm_strategy;
extern permission_strategy_t location_perm_strategy;
extern permission_strategy_t abac_perm_strategy;
extern permission_strategy_t lbac_perm_strategy;

/* ========================================================================
 * Engine structure (private)
 * ======================================================================== */
#define MAX_STRATEGIES 16
#define MAX_POLICY_CACHE 256
#define RESULT_CACHE_SIZE 1024
#define POLICY_RES_CACHE_SIZE 128

typedef struct {
    sso_id_t policy_id;
    void    *compiled;
    perm_strategy_type_t strategy_type;
} policy_cache_entry_t;

typedef struct {
    sso_id_t user_id;
    policy_t policies[64];
    size_t   count;
    uint64_t timestamp;
    bool     valid;
} policy_res_cache_entry_t;

typedef struct {
    sso_id_t user_id;
    uint32_t params_hash;
    bool     allowed;
    uint64_t timestamp;
    bool     valid;
} result_cache_entry_t;

typedef struct {
    atomic_ullong total_evals;
    atomic_ullong cache_hits_l1;
    atomic_ullong cache_hits_l2;
    atomic_ullong allows;
    atomic_ullong denys;
    atomic_ullong total_duration_us;
} engine_metrics_t;

struct permission_engine {
    sso_context_t          *ctx;
    permission_strategy_t  *strategies[MAX_STRATEGIES];
    size_t                  strategy_count;

    /* Concurrency control */
    pthread_rwlock_t        lock;

    /* Policy compilation cache */
    policy_cache_entry_t    cache[MAX_POLICY_CACHE];
    size_t                  cache_count;

    /* Policy resolution cache (L1) */
    policy_res_cache_entry_t res_cache[POLICY_RES_CACHE_SIZE];

    /* Result cache (L2) */
    result_cache_entry_t    result_cache[RESULT_CACHE_SIZE];

    /* Metrics */
    engine_metrics_t        metrics;
};

/* -----------------------------------------------------------------------
 * Hashing for result cache
 * ----------------------------------------------------------------------- */
static uint32_t hash_params(eval_context_t *ctx) {
    uint32_t hash = 5381;
    unsigned char *p = (unsigned char *)&ctx->params;
    size_t len = sizeof(ctx->params);
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + p[i];
    }
    return hash;
}

static uint64_t get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

sso_error_t perm_engine_create(permission_engine_t **engine, sso_context_t *ctx) {
    if (!engine || !ctx) return SSO_ERR_INVALID_PARAM;

    *engine = (permission_engine_t *)calloc(1, sizeof(permission_engine_t));
    if (!*engine) return SSO_ERR_OUT_OF_MEMORY;

    (*engine)->ctx = ctx;
    (*engine)->strategy_count = 0;
    (*engine)->cache_count = 0;

    if (pthread_rwlock_init(&(*engine)->lock, NULL) != 0) {
        free(*engine);
        return SSO_ERR_GENERAL;
    }

    sso_error_t err;

    /* Register built-in strategies */
    if ((err = perm_engine_register_strategy(*engine, &func_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &api_perm_strategy))  != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &data_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &rbac_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &location_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &abac_perm_strategy)) != SSO_OK ||
        (err = perm_engine_register_strategy(*engine, &lbac_perm_strategy)) != SSO_OK) {
        perm_engine_destroy(*engine);
        return err;
    }

    return SSO_OK;
}

void perm_engine_destroy(permission_engine_t *engine) {
    if (!engine) return;

    pthread_rwlock_wrlock(&engine->lock);

    /* Free cached compiled rules */
    for (size_t i = 0; i < engine->cache_count; i++) {
        permission_strategy_t *strat = perm_engine_get_strategy(engine, engine->cache[i].strategy_type);
        if (strat && strat->free_compiled_rules) {
            strat->free_compiled_rules(strat, engine->cache[i].compiled);
        }
    }

    for (size_t i = 0; i < engine->strategy_count; i++) {
        if (engine->strategies[i] && engine->strategies[i]->destroy) {
            engine->strategies[i]->destroy(engine->strategies[i]);
        }
    }

    pthread_rwlock_unlock(&engine->lock);
    pthread_rwlock_destroy(&engine->lock);
    free(engine);
}

/* ========================================================================
 * Cache management
 * ======================================================================== */

static void *perm_engine_get_cached_rule(permission_engine_t *engine, sso_id_t policy_id) {
    for (size_t i = 0; i < engine->cache_count; i++) {
        if (engine->cache[i].policy_id == policy_id) {
            return engine->cache[i].compiled;
        }
    }
    return NULL;
}

static void perm_engine_cache_rule(permission_engine_t *engine, sso_id_t policy_id, 
                                    perm_strategy_type_t type, void *compiled) {
    if (engine->cache_count >= MAX_POLICY_CACHE) return;
    engine->cache[engine->cache_count].policy_id = policy_id;
    engine->cache[engine->cache_count].strategy_type = type;
    engine->cache[engine->cache_count].compiled = compiled;
    engine->cache_count++;
}

void perm_engine_cache_invalidate_user(permission_engine_t *engine, sso_id_t user_id) {
    if (!engine) return;
    pthread_rwlock_wrlock(&engine->lock);
    
    /* Clear Result Cache (L2) */
    for (size_t i = 0; i < RESULT_CACHE_SIZE; i++) {
        if (engine->result_cache[i].valid && engine->result_cache[i].user_id == user_id) {
            engine->result_cache[i].valid = false;
        }
    }

    /* Clear Resolution Cache (L1) */
    for (size_t i = 0; i < POLICY_RES_CACHE_SIZE; i++) {
        if (engine->res_cache[i].valid && engine->res_cache[i].user_id == user_id) {
            engine->res_cache[i].valid = false;
        }
    }

    pthread_rwlock_unlock(&engine->lock);
}

void perm_engine_cache_invalidate_policy(permission_engine_t *engine, sso_id_t policy_id) {
    if (!engine) return;
    pthread_rwlock_wrlock(&engine->lock);
    
    /* 1. Invalidate compiled rule */
    for (size_t i = 0; i < engine->cache_count; i++) {
        if (engine->cache[i].policy_id == policy_id) {
            permission_strategy_t *strat = perm_engine_get_strategy(engine, engine->cache[i].strategy_type);
            if (strat && strat->free_compiled_rules) {
                strat->free_compiled_rules(strat, engine->cache[i].compiled);
            }
            /* Shift others down */
            for (size_t j = i; j < engine->cache_count - 1; j++) {
                engine->cache[j] = engine->cache[j + 1];
            }
            engine->cache_count--;
            break; 
        }
    }

    /* 2. Clear all result and resolution caches as this policy might affect anyone */
    for (size_t i = 0; i < RESULT_CACHE_SIZE; i++) {
        engine->result_cache[i].valid = false;
    }
    for (size_t i = 0; i < POLICY_RES_CACHE_SIZE; i++) {
        engine->res_cache[i].valid = false;
    }

    pthread_rwlock_unlock(&engine->lock);
}

void perm_engine_cache_invalidate_all(permission_engine_t *engine) {
    if (!engine) return;
    pthread_rwlock_wrlock(&engine->lock);

    for (size_t i = 0; i < engine->cache_count; i++) {
        permission_strategy_t *strat = perm_engine_get_strategy(engine, engine->cache[i].strategy_type);
        if (strat && strat->free_compiled_rules) {
            strat->free_compiled_rules(strat, engine->cache[i].compiled);
        }
    }
    engine->cache_count = 0;

    for (size_t i = 0; i < RESULT_CACHE_SIZE; i++) {
        engine->result_cache[i].valid = false;
    }
    for (size_t i = 0; i < POLICY_RES_CACHE_SIZE; i++) {
        engine->res_cache[i].valid = false;
    }

    pthread_rwlock_unlock(&engine->lock);
}

/* ========================================================================
 * Strategy registry
 * ======================================================================== */

sso_error_t perm_engine_register_strategy(permission_engine_t *engine,
                                          permission_strategy_t *strategy) {
    if (!engine || !strategy) return SSO_ERR_INVALID_PARAM;

    pthread_rwlock_wrlock(&engine->lock);

    /* Check for duplicates */
    for (size_t i = 0; i < engine->strategy_count; i++) {
        if (engine->strategies[i]->type == strategy->type) {
            pthread_rwlock_unlock(&engine->lock);
            return SSO_ERR_STRATEGY_CONFLICT;
        }
    }

    if (engine->strategy_count >= MAX_STRATEGIES) {
        pthread_rwlock_unlock(&engine->lock);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    engine->strategies[engine->strategy_count++] = strategy;

    sso_error_t err = SSO_OK;
    /* Call init if provided */
    if (strategy->init) {
        err = strategy->init(strategy, engine->ctx);
    }

    pthread_rwlock_unlock(&engine->lock);
    return err;
}

sso_error_t perm_engine_unregister_strategy(permission_engine_t *engine,
                                            perm_strategy_type_t type) {
    if (!engine) return SSO_ERR_INVALID_PARAM;

    pthread_rwlock_wrlock(&engine->lock);

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
            pthread_rwlock_unlock(&engine->lock);
            return SSO_OK;
        }
    }

    pthread_rwlock_unlock(&engine->lock);
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
 * Metrics implementation
 * ======================================================================== */
sso_error_t perm_engine_get_metrics(permission_engine_t *engine, char *buf, size_t max) {
    if (!engine || !buf) return SSO_ERR_INVALID_PARAM;

    unsigned long long evals = atomic_load(&engine->metrics.total_evals);
    unsigned long long l1_hits = atomic_load(&engine->metrics.cache_hits_l1);
    unsigned long long l2_hits = atomic_load(&engine->metrics.cache_hits_l2);
    unsigned long long allows = atomic_load(&engine->metrics.allows);
    unsigned long long denys = atomic_load(&engine->metrics.denys);
    unsigned long long duration = atomic_load(&engine->metrics.total_duration_us);

    snprintf(buf, max,
        "# HELP sso_perm_evals_total Total number of permission evaluations\n"
        "# TYPE sso_perm_evals_total counter\n"
        "sso_perm_evals_total %llu\n"
        "# HELP sso_perm_cache_hits_total Total number of cache hits\n"
        "# TYPE sso_perm_cache_hits_total counter\n"
        "sso_perm_cache_hits_total{level=\"l1\"} %llu\n"
        "sso_perm_cache_hits_total{level=\"l2\"} %llu\n"
        "# HELP sso_perm_decisions_total Total number of allows/denys\n"
        "# TYPE sso_perm_decisions_total counter\n"
        "sso_perm_decisions_total{effect=\"allow\"} %llu\n"
        "sso_perm_decisions_total{effect=\"deny\"} %llu\n"
        "# HELP sso_perm_eval_duration_us_total Cumulative evaluation duration in microseconds\n"
        "# TYPE sso_perm_eval_duration_us_total counter\n"
        "sso_perm_eval_duration_us_total %llu\n",
        evals, l1_hits, l2_hits, allows, denys, duration);

    return SSO_OK;
}

/* ========================================================================
 * Evaluation — core decision logic
 * ======================================================================== */

sso_error_t perm_engine_evaluate_policy(permission_engine_t *engine,
                                        const policy_t *policy,
                                        eval_context_t *ctx,
                                        bool *result,
                                        char **decision_trace) {
    if (!engine || !policy || !ctx || !result) return SSO_ERR_INVALID_PARAM;

    /* Skip disabled policies */
    if (policy->status == POLICY_STATUS_DISABLED) {
        if (decision_trace) *decision_trace = strdup("Policy disabled");
        *result = true; 
        return SSO_OK;
    }

    /* Find the strategy for this policy */
    permission_strategy_t *strategy =
        perm_engine_get_strategy(engine, policy->strategy_type);
    if (!strategy) {
        if (decision_trace) *decision_trace = strdup("Strategy not found");
        return SSO_ERR_STRATEGY_NOT_FOUND;
    }

    if (!strategy->evaluate) {
        return SSO_ERR_NOT_IMPLEMENTED;
    }

    /* Handle pre-compilation */
    void *compiled = NULL;
    if (strategy->compile_rules) {
        compiled = perm_engine_get_cached_rule(engine, policy->id);
        if (!compiled) {
            sso_error_t cerr = strategy->compile_rules(strategy, policy->rules, &compiled);
            if (cerr == SSO_OK) {
                perm_engine_cache_rule(engine, policy->id, strategy->type, compiled);
            }
        }
    }

    bool strategy_result = false;
    sso_error_t err = strategy->evaluate(strategy, ctx, policy, compiled, &strategy_result);
    
    if (decision_trace) {
        char buf[256];
        snprintf(buf, sizeof(buf), "Strategy %s: %s (matched: %s)", 
                 strategy->name, strategy_result ? "ALLOW" : "DENY", 
                 err == SSO_OK ? "YES" : "NO");
        *decision_trace = strdup(buf);
    }

    if (err == SSO_ERR_NOT_FOUND) {
        return SSO_ERR_NOT_FOUND; 
    }
    if (err != SSO_OK) return err;

    *result = strategy_result;
    return SSO_OK;
}

static void audit_log_decision(eval_context_t *ctx, bool allowed, const char *trace, uint64_t duration_ms, bool cache_hit) {
    FILE *f = fopen("audit.log", "a");
    if (!f) return;

    /* Simple escaping for trace string */
    char escaped_trace[8192] = {0};
    if (trace) {
        size_t j = 0;
        for (size_t i = 0; trace[i] && j < sizeof(escaped_trace) - 3; i++) {
            if (trace[i] == '"') { escaped_trace[j++] = '\\'; escaped_trace[j++] = '"'; }
            else if (trace[i] == '\n') { escaped_trace[j++] = '\\'; escaped_trace[j++] = 'n'; }
            else if (trace[i] == '\t') { escaped_trace[j++] = '\\'; escaped_trace[j++] = 't'; }
            else escaped_trace[j++] = trace[i];
        }
    }

    fprintf(f, "{\"timestamp_ms\": %llu, \"user_id\": %llu, \"decision\": \"%s\", \"duration_ms\": %llu, \"cache_hit\": %s, \"trace\": \"%s\"}\n",
            (unsigned long long)get_time_ms(),
            (unsigned long long)ctx->user_id,
            allowed ? "ALLOW" : "DENY",
            (unsigned long long)duration_ms,
            cache_hit ? "true" : "false",
            escaped_trace);
    fclose(f);
}

sso_error_t perm_engine_evaluate(permission_engine_t *engine,
                                 eval_context_t *ctx,
                                 bool *result,
                                 char **decision_trace) {
    if (!engine || !ctx || !result) return SSO_ERR_INVALID_PARAM;
    if (!ctx->user && ctx->user_id == 0) return SSO_ERR_INVALID_PARAM;

    uint32_t phash = hash_params(ctx);
    size_t cache_idx = phash % RESULT_CACHE_SIZE;
    size_t l1_idx = ctx->user_id % POLICY_RES_CACHE_SIZE;
    uint64_t now = get_time_ms();

    pthread_rwlock_rdlock(&engine->lock);

    /* 0. Check Result Cache (L2) */
    if (engine->result_cache[cache_idx].valid &&
        engine->result_cache[cache_idx].user_id == ctx->user_id &&
        engine->result_cache[cache_idx].params_hash == phash &&
        (now - engine->result_cache[cache_idx].timestamp) < 30000) { /* 30s TTL */
        *result = engine->result_cache[cache_idx].allowed;
        if (decision_trace) *decision_trace = strdup("Decision from Result Cache (L2)");
        
        atomic_fetch_add(&engine->metrics.cache_hits_l2, 1);
        atomic_fetch_add(&engine->metrics.total_evals, 1);
        if (*result) atomic_fetch_add(&engine->metrics.allows, 1);
        else atomic_fetch_add(&engine->metrics.denys, 1);

        pthread_rwlock_unlock(&engine->lock);

        /* Telemetry: Cache Hit */
        uint64_t duration = get_time_ms() - now;
        if (duration > 5) {
             fprintf(stderr, "[perm] CACHE HIT (SLOW): user=%ld duration=%lums\n", 
                     (long)ctx->user_id, (long)duration);
        }
        audit_log_decision(ctx, *result, "Decision from Result Cache (L2)", duration, true);
        return SSO_OK;
    }

    *result = false; /* default: deny */
    sso_error_t err;

    /* Trace buffer */
    char full_trace[4096] = "";
    if (decision_trace) *decision_trace = NULL;

    /* 1. Resolve all policies applicable to this user */
    policy_t policies_buf[64];
    policy_t *policies = policies_buf;
    size_t policy_count = 0;
    size_t max_policies = 64;

    /* Check Resolution Cache (L1) */
    if (engine->res_cache[l1_idx].valid &&
        engine->res_cache[l1_idx].user_id == ctx->user_id &&
        (now - engine->res_cache[l1_idx].timestamp) < 60000) { /* 60s TTL */
        policies = engine->res_cache[l1_idx].policies;
        policy_count = engine->res_cache[l1_idx].count;
        atomic_fetch_add(&engine->metrics.cache_hits_l1, 1);
    } else {
        policy_manager_t *pmgr = (policy_manager_t *)engine->ctx->policy_mgr;
        if (!pmgr) {
            pthread_rwlock_unlock(&engine->lock);
            audit_log_decision(ctx, false, "Error: policy manager not found", get_time_ms() - now, false);
            return SSO_ERR_GENERAL;
        }

        err = policy_resolve_for_user(pmgr, ctx->user_id, policies_buf, &policy_count, max_policies);
        if (err != SSO_OK && err != SSO_ERR_NOT_FOUND) {
            pthread_rwlock_unlock(&engine->lock);
            audit_log_decision(ctx, false, "Error: policy resolution failed", get_time_ms() - now, false);
            return err;
        }

        /* Update L1 Cache */
        engine->res_cache[l1_idx].user_id = ctx->user_id;
        memcpy(engine->res_cache[l1_idx].policies, policies_buf, sizeof(policy_t) * policy_count);
        engine->res_cache[l1_idx].count = policy_count;
        engine->res_cache[l1_idx].timestamp = now;
        engine->res_cache[l1_idx].valid = true;
    }

    if (policy_count == 0) {
        if (decision_trace) *decision_trace = strdup("Default DENY: No policies found");
        pthread_rwlock_unlock(&engine->lock);
        audit_log_decision(ctx, false, "Default DENY: No policies found", get_time_ms() - now, false);
        return SSO_OK;
    }

    /* 2. Evaluate each policy.  DENY-overrides: one DENY → result is DENY. */
    bool any_allowed = false;

    for (size_t i = 0; i < policy_count; i++) {
        bool policy_result = false;
        char *policy_trace = NULL;
        err = perm_engine_evaluate_policy(engine, &policies[i], ctx, &policy_result, &policy_trace);
        
        if (decision_trace && policy_trace) {
            strncat(full_trace, "[Policy ", sizeof(full_trace) - strlen(full_trace) - 1);
            strncat(full_trace, policies[i].name, sizeof(full_trace) - strlen(full_trace) - 1);
            strncat(full_trace, "] ", sizeof(full_trace) - strlen(full_trace) - 1);
            strncat(full_trace, policy_trace, sizeof(full_trace) - strlen(full_trace) - 1);
            strncat(full_trace, "\n", sizeof(full_trace) - strlen(full_trace) - 1);
        }
        if (policy_trace) free(policy_trace);

        if (err == SSO_ERR_NOT_FOUND) {
            continue; 
        }
        if (err != SSO_OK) continue; 

        if (!policy_result) {
            *result = false;
            if (decision_trace) {
                strncat(full_trace, "Result: DENIED (Override by policy)\n", sizeof(full_trace) - strlen(full_trace) - 1);
                *decision_trace = strdup(full_trace);
            }

            /* Update cache for DENY */
            engine->result_cache[cache_idx].user_id = ctx->user_id;
            engine->result_cache[cache_idx].params_hash = phash;
            engine->result_cache[cache_idx].allowed = false;
            engine->result_cache[cache_idx].timestamp = now;
            engine->result_cache[cache_idx].valid = true;

            pthread_rwlock_unlock(&engine->lock);
            audit_log_decision(ctx, false, full_trace, get_time_ms() - now, false);
            return SSO_OK;
        }

        any_allowed = true;
    }

    *result = any_allowed;
    if (decision_trace) {
        strncat(full_trace, any_allowed ? "Result: ALLOWED\n" : "Result: DENIED (No matching allow rule)\n", sizeof(full_trace) - strlen(full_trace) - 1);
        *decision_trace = strdup(full_trace);
    }

    /* Update cache for final result */
    engine->result_cache[cache_idx].user_id = ctx->user_id;
    engine->result_cache[cache_idx].params_hash = phash;
    engine->result_cache[cache_idx].allowed = any_allowed;
    engine->result_cache[cache_idx].timestamp = now;
    engine->result_cache[cache_idx].valid = true;

    atomic_fetch_add(&engine->metrics.total_evals, 1);
    if (any_allowed) atomic_fetch_add(&engine->metrics.allows, 1);
    else atomic_fetch_add(&engine->metrics.denys, 1);

    pthread_rwlock_unlock(&engine->lock);

    /* Telemetry: Log evaluation time */
    uint64_t duration = get_time_ms() - now;
    atomic_fetch_add(&engine->metrics.total_duration_us, (unsigned long long)duration * 1000);
    if (duration > 10) { /* Log only slow evaluations (>10ms) */
        fprintf(stderr, "[perm] SLOW EVAL: user=%ld duration=%lums cache=MISS\n", 
                (long)ctx->user_id, (long)duration);
    }

    audit_log_decision(ctx, any_allowed, full_trace, duration, false);
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
    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed, NULL);
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

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed, NULL);
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

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed, NULL);

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

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed, NULL);
    eval_context_destroy(&ectx);
    return err;
}

sso_error_t perm_check_location(sso_context_t *ctx, sso_id_t user_id,
                                const char *source_ip, const char *geo_country,
                                bool *allowed) {
    if (!ctx || !source_ip || !allowed) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    strncpy(ectx.params.location.source_ip, source_ip,
            sizeof(ectx.params.location.source_ip) - 1);
    if (geo_country) {
        strncpy(ectx.params.location.geo_country, geo_country,
                sizeof(ectx.params.location.geo_country) - 1);
    }

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed, NULL);
    eval_context_destroy(&ectx);
    return err;
}

sso_error_t perm_check_lbac(sso_context_t *ctx, sso_id_t user_id,
                            const char *user_labels, const char *resource_label,
                            bool *allowed) {
    if (!ctx || !user_labels || !resource_label || !allowed) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id((user_manager_t *)ctx->user_mgr, user_id, &user);
    if (err != SSO_OK) return err;

    eval_context_t ectx;
    eval_context_init(&ectx, &user);
    strncpy(ectx.params.lbac.user_labels, user_labels,
            sizeof(ectx.params.lbac.user_labels) - 1);
    strncpy(ectx.params.lbac.resource_label, resource_label,
            sizeof(ectx.params.lbac.resource_label) - 1);

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed, NULL);
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

    err = perm_engine_evaluate((permission_engine_t *)ctx->perm_engine, &ectx, allowed, NULL);
    eval_context_destroy(&ectx);
    return err;
}
