/*
 * sso.c — Core SSO lifecycle, utilities, and context wiring.
 *
 * The sso_init() function wires together all subsystems:
 *   storage → user_mgr → role_mgr → group_mgr → policy_mgr → perm_engine
 *
 * All subsystems are optional at init (NULL is valid) but most operations
 * will fail if their required subsystem is missing.
 */

#define _POSIX_C_SOURCE 199309L

#include "sso.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "permission.h"
#include "token.h"
#include "storage.h"
#include "ratelimit.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sodium.h>

/* ========================================================================
 * Error strings
 * ======================================================================== */
const char *sso_strerror(sso_error_t err) {
    switch (err) {
        case SSO_OK:                    return "Success";
        case SSO_ERR_GENERAL:           return "General error";
        case SSO_ERR_NOT_FOUND:         return "Resource not found";
        case SSO_ERR_ALREADY_EXISTS:    return "Resource already exists";
        case SSO_ERR_INVALID_PARAM:     return "Invalid parameter";
        case SSO_ERR_NO_PERMISSION:     return "Permission denied";
        case SSO_ERR_AUTH_FAILED:       return "Authentication failed";
        case SSO_ERR_TOKEN_EXPIRED:     return "Token expired";
        case SSO_ERR_TOKEN_INVALID:     return "Token invalid";
        case SSO_ERR_STORAGE:           return "Storage error";
        case SSO_ERR_STRATEGY_CONFLICT: return "Strategy already registered";
        case SSO_ERR_STRATEGY_NOT_FOUND:return "Strategy not found";
        case SSO_ERR_RULE_INVALID:      return "Invalid policy rule";
        case SSO_ERR_OUT_OF_MEMORY:    return "Out of memory";
        case SSO_ERR_NOT_IMPLEMENTED:  return "Not implemented";
        case SSO_ERR_RATE_LIMIT:       return "Rate limit exceeded";
        default:                       return "Unknown error";
    }
}

/* ========================================================================
 * Timestamp
 * ======================================================================== */
sso_timestamp_t sso_timestamp_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (sso_timestamp_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ========================================================================
 * Strategy names
 * ======================================================================== */
const char *perm_strategy_name(perm_strategy_type_t t) {
    switch (t) {
        case PERM_STRATEGY_FUNCTIONAL: return "functional";
        case PERM_STRATEGY_API:        return "api";
        case PERM_STRATEGY_DATA:       return "data";
        case PERM_STRATEGY_RBAC:       return "rbac";
        case PERM_STRATEGY_LOCATION:   return "location";
        case PERM_STRATEGY_ABAC:       return "abac";
        case PERM_STRATEGY_LBAC:       return "lbac";
        default:                       return "unknown";
    }
}

/* ========================================================================
 * Evaluation context
 * ======================================================================== */
sso_error_t eval_context_init(eval_context_t *ctx, const user_t *user) {
    if (!ctx || !user) return SSO_ERR_INVALID_PARAM;
    memset(ctx, 0, sizeof(*ctx));
    ctx->user    = user;
    ctx->user_id = user->id;
    ctx->environment[0] = '\0';
    return SSO_OK;
}

void eval_context_destroy(eval_context_t *ctx) {
    if (!ctx) return;
    /* Free field_filter if allocated by data strategy */
    if (ctx->params.data.field_filter) {
        for (size_t i = 0; i < ctx->params.data.field_filter_count; i++) {
            free(ctx->params.data.field_filter[i]);
        }
        free(ctx->params.data.field_filter);
        ctx->params.data.field_filter = NULL;
    }
    ctx->userdata = NULL;
}

/* ========================================================================
 * SSO lifecycle
 * ======================================================================== */

/*
 * Load the token HMAC secret from the environment or generate a random one.
 *
 * Security hierarchy (highest priority first):
 *   1. SSO_TOKEN_SECRET environment variable  (recommended for production)
 *   2. Auto-generated random secret           (development / demo only)
 *
 * A persistent secret is REQUIRED in production so that previously issued
 * tokens remain valid across server restarts.  Set the SSO_TOKEN_SECRET
 * environment variable to a long (~32 character) random string.
 */
#define SSO_ENV_TOKEN_SECRET "SSO_TOKEN_SECRET"
#define SSO_SECRET_BYTES     32   /* 256-bit HMAC key */

static sso_error_t load_token_secret(unsigned char *out, size_t out_len) {
    const char *env_secret = getenv(SSO_ENV_TOKEN_SECRET);

    if (env_secret && strlen(env_secret) > 0) {
        /* Use the secret provided by the environment variable. */
        size_t len = strlen(env_secret);
        if (len > out_len) len = out_len;
        memcpy(out, env_secret, len);
        if (len < out_len) {
            /* Pad with zeros to fill the key buffer. */
            memset(out + len, 0, out_len - len);
        }
        /* Lock secret in memory to prevent swapping to disk. */
        if (sodium_mlock(out, out_len) != 0) {
            /* Non-fatal: best-effort protection. */
        }
        printf("[sso] Token secret loaded from %s environment variable.\n",
               SSO_ENV_TOKEN_SECRET);
        return SSO_OK;
    }

    /* No environment secret — generate a random key from /dev/urandom. */
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        size_t n = fread(out, 1, out_len, f);
        fclose(f);
        if (n == out_len) {
            /* Lock the random secret in memory as well. */
            if (sodium_mlock(out, out_len) != 0) {
                /* Non-fatal: best-effort protection. */
            }
            fprintf(stderr,
                    "[sso] WARNING: No %s set. Generated a random token secret.\n"
                    "       This secret will change on every restart, invalidating\n"
                    "       all previously issued tokens. Set %s for production use.\n",
                    SSO_ENV_TOKEN_SECRET, SSO_ENV_TOKEN_SECRET);
            return SSO_OK;
        }
    }

    /* Fallback (should never happen on a normal system). */
    fprintf(stderr,
            "[sso] CRITICAL: Cannot read /dev/urandom and no %s set.\n"
            "       Using a time-based fallback — TOKENS ARE NOT SECURE.\n",
            SSO_ENV_TOKEN_SECRET);
    sso_timestamp_t now = sso_timestamp_now();
    memcpy(out, &now, sizeof(now) < out_len ? sizeof(now) : out_len);
    return SSO_OK;
}

sso_error_t sso_init(sso_context_t *ctx, storage_backend_t *storage,
                     const char *config_json) {
    if (!ctx) return SSO_ERR_INVALID_PARAM;
    memset(ctx, 0, sizeof(*ctx));

    sso_error_t err;
    if (sodium_init() < 0) { fprintf(stderr, "[sso] Failed to init libsodium\n"); return SSO_ERR_GENERAL; }

    /* 1. Storage backend */
    if (storage) {
        if (storage->open) {
            err = storage->open(storage, config_json ? config_json : ":memory:");
            if (err != SSO_OK) return err;
        }
        ctx->storage_backend = storage;
    }

    /* 2. Rate Limiter (e.g. 10000 IPs) */
    rate_limiter_t *rl = NULL;
    err = rate_limiter_create(&rl, 10000);
    if (err != SSO_OK) goto fail;
    ctx->rate_limiter = rl;

    /* 3. Token manager — load secret or RSA keys */
    token_manager_t *tmgr = (token_manager_t *)calloc(1, sizeof(token_manager_t));
    if (!tmgr) return SSO_ERR_OUT_OF_MEMORY;

    const char *env_priv = getenv("SSO_PRIVATE_KEY");
    const char *env_pub  = getenv("SSO_PUBLIC_KEY");

    if (env_priv) {
        /* RS256 mode */
        err = token_manager_init_rs256(tmgr, env_priv, env_pub, 3600000LL);
        if (err == SSO_OK) {
            printf("[sso] Asymmetric signing (RS256) enabled.\n");
        } else {
            fprintf(stderr, "[sso] Failed to init RS256: %s. Falling back to HS256.\n", sso_strerror(err));
            env_priv = NULL; /* trigger fallback */
        }
    }

    if (!env_priv) {
        /* HS256 mode */
        unsigned char secret[SSO_SECRET_BYTES];
        err = load_token_secret(secret, SSO_SECRET_BYTES);
        if (err != SSO_OK) {
            free(tmgr);
            return err;
        }
        token_manager_init(tmgr, secret, SSO_SECRET_BYTES, 3600000LL);
        /* Securely wipe the stack copy of the key after use. */
        sodium_memzero(secret, SSO_SECRET_BYTES);
    }
    ctx->token_mgr = tmgr;

    /* 3. Managers */
    user_manager_t   *umgr = NULL;
    role_manager_t   *rmgr = NULL;
    group_manager_t  *gmgr = NULL;
    policy_manager_t *pmgr = NULL;
    permission_engine_t *pengine = NULL;

    if ((err = user_manager_create(&umgr, ctx))   != SSO_OK) goto fail;
    ctx->user_mgr = umgr;

    if ((err = role_manager_create(&rmgr, ctx))   != SSO_OK) goto fail;
    ctx->role_mgr = rmgr;

    if ((err = group_manager_create(&gmgr, ctx))  != SSO_OK) goto fail;
    ctx->group_mgr = gmgr;

    if ((err = policy_manager_create(&pmgr, ctx)) != SSO_OK) goto fail;
    ctx->policy_mgr = pmgr;

    if ((err = perm_engine_create(&pengine, ctx)) != SSO_OK) goto fail;
    ctx->perm_engine = pengine;

    return SSO_OK;

fail:
    sso_destroy(ctx);
    return err;
}

void sso_destroy(sso_context_t *ctx) {
    if (!ctx) return;

    if (ctx->rate_limiter)  rate_limiter_destroy((rate_limiter_t *)ctx->rate_limiter);
    if (ctx->perm_engine)   perm_engine_destroy((permission_engine_t *)ctx->perm_engine);
    if (ctx->policy_mgr)    policy_manager_destroy((policy_manager_t *)ctx->policy_mgr);
    if (ctx->group_mgr)     group_manager_destroy((group_manager_t *)ctx->group_mgr);
    if (ctx->role_mgr)      role_manager_destroy((role_manager_t *)ctx->role_mgr);
    if (ctx->user_mgr)      user_manager_destroy((user_manager_t *)ctx->user_mgr);

    if (ctx->token_mgr) {
        /* Use the destroy function that securely wipes the secret. */
        token_manager_destroy((token_manager_t *)ctx->token_mgr);
    }

    if (ctx->storage_backend) {
        storage_backend_t *sb = (storage_backend_t *)ctx->storage_backend;
        if (sb->close) sb->close(sb);
        free(sb);
    }

    memset(ctx, 0, sizeof(*ctx));
}
