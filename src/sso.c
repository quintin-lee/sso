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
#include "logger.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "permission.h"
#include "token.h"
#include "storage.h"
#include "ratelimit.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sodium.h>

/* ========================================================================
 * Error strings
 * ======================================================================== */
const char* sso_strerror(sso_error_t err) {
	switch (err) {
		case SSO_OK:
			return "Success";
		case SSO_ERR_GENERAL:
			return "General error";
		case SSO_ERR_NOT_FOUND:
			return "Resource not found";
		case SSO_ERR_ALREADY_EXISTS:
			return "Resource already exists";
		case SSO_ERR_INVALID_PARAM:
			return "Invalid parameter";
		case SSO_ERR_NO_PERMISSION:
			return "Permission denied";
		case SSO_ERR_AUTH_FAILED:
			return "Authentication failed";
		case SSO_ERR_TOKEN_EXPIRED:
			return "Token expired";
		case SSO_ERR_TOKEN_INVALID:
			return "Token invalid";
		case SSO_ERR_STORAGE:
			return "Storage error";
		case SSO_ERR_STRATEGY_CONFLICT:
			return "Strategy already registered";
		case SSO_ERR_STRATEGY_NOT_FOUND:
			return "Strategy not found";
		case SSO_ERR_RULE_INVALID:
			return "Invalid policy rule";
		case SSO_ERR_OUT_OF_MEMORY:
			return "Out of memory";
		case SSO_ERR_NOT_IMPLEMENTED:
			return "Not implemented";
		case SSO_ERR_RATE_LIMIT:
			return "Rate limit exceeded";
		case SSO_ERR_SOCKET:
			return "Socket creation failed";
		case SSO_ERR_BIND:
			return "Socket bind failed";
		case SSO_ERR_LISTEN:
			return "Socket listen failed";
		case SSO_ERR_INIT:
			return "Initialisation failed";
		case SSO_ERR_CURL:
			return "CURL operation failed";
		case SSO_ERR_PASSWORD_EXPIRED:
			return "Password expired";
		default:
			return "Unknown error";
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
const char* perm_strategy_name(perm_strategy_type_t t) {
	switch (t) {
		case PERM_STRATEGY_FUNCTIONAL:
			return "functional";
		case PERM_STRATEGY_API:
			return "api";
		case PERM_STRATEGY_DATA:
			return "data";
		case PERM_STRATEGY_RBAC:
			return "rbac";
		case PERM_STRATEGY_LOCATION:
			return "location";
		case PERM_STRATEGY_ABAC:
			return "abac";
		case PERM_STRATEGY_LBAC:
			return "lbac";
		default:
			return "unknown";
	}
}

/* ========================================================================
 * Evaluation context
 * ======================================================================== */
sso_error_t eval_context_init(eval_context_t* ctx, const user_t* user) {
	if (!ctx || !user)
		return SSO_ERR_INVALID_PARAM;
	memset(ctx, 0, sizeof(*ctx));
	ctx->user			= user;
	ctx->user_id		= user->id;
	ctx->environment[0] = '\0';
	return SSO_OK;
}

void eval_context_destroy(eval_context_t* ctx) {
	if (!ctx)
		return;
	/* Free data.record if it was strdup'd by perm_check_data */
	free(ctx->params.data.record);
	ctx->params.data.record = NULL;
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
#define SSO_SECRET_BYTES 32 /* 256-bit HMAC key */

static sso_error_t load_token_secret(unsigned char* out, size_t out_len) {
	const char* env_secret = getenv(SSO_ENV_TOKEN_SECRET);

	if (env_secret && strlen(env_secret) > 0) {
		/* Use the secret provided by the environment variable. */
		size_t len = strlen(env_secret);
		if (len > out_len)
			len = out_len;
		memcpy(out, env_secret, len);
		if (len < out_len) {
			/* Pad with zeros to fill the key buffer. */
			memset(out + len, 0, out_len - len);
		}
		/* Lock secret in memory to prevent swapping to disk. */
		if (sodium_mlock(out, out_len) != 0) {
			/* Non-fatal: best-effort protection. */
		}
		LOG_INFO("[sso] Token secret loaded from %s environment variable.", SSO_ENV_TOKEN_SECRET);
		return SSO_OK;
	}

	/* No environment secret — generate a random key from /dev/urandom. */
	FILE* f = fopen("/dev/urandom", "r");
	if (f) {
		size_t n = fread(out, 1, out_len, f);
		fclose(f);
		if (n == out_len) {
			/* Lock the random secret in memory as well. */
			if (sodium_mlock(out, out_len) != 0) {
				/* Non-fatal: best-effort protection. */
			}
			LOG_WARN("[sso] No %s set. Generated a random token secret. "
					 "This secret will change on every restart, invalidating "
					 "all previously issued tokens. Set %s for production use.",
					 SSO_ENV_TOKEN_SECRET, SSO_ENV_TOKEN_SECRET);
			return SSO_OK;
		}
	}

	/* Fallback (should never happen on a normal system). */
	LOG_ERROR("[sso] Cannot read /dev/urandom and no %s set. "
			  "Using a time-based fallback — TOKENS ARE NOT SECURE.",
			  SSO_ENV_TOKEN_SECRET);
	sso_timestamp_t now = sso_timestamp_now();
	memcpy(out, &now, sizeof(now) < out_len ? sizeof(now) : out_len);
	return SSO_OK;
}

sso_error_t sso_init(sso_context_t* ctx, storage_backend_t* storage, void* config_ptr) {
	if (!ctx)
		return SSO_ERR_INVALID_PARAM;
	memset(ctx, 0, sizeof(*ctx));
	sso_config_t* config = NULL;
	if (config_ptr) {
		config = (sso_config_t*)malloc(sizeof(sso_config_t));
		if (!config)
			return SSO_ERR_OUT_OF_MEMORY;
		memcpy(config, config_ptr, sizeof(sso_config_t));
	}
	ctx->config = config;

	sso_error_t err;
	if (sodium_init() < 0) {
		LOG_ERROR("[sso] Failed to init libsodium");
		return SSO_ERR_INIT;
	}

	/* 1. Storage backend */
	if (storage) {
		const char* db_url = config ? config->database_url : "sso_server.db";
		if (config && config->use_memory)
			db_url = ":memory:";

		if (storage->open) {
			err = storage->open(storage, db_url);
			if (err != SSO_OK)
				return err;
		}
		ctx->storage_backend = storage;
	}

	/* 2. Rate Limiter */
	rate_limiter_t* rl		= NULL;
	int				max_ips = (config && config->max_ips > 0) ? config->max_ips : 10000;
	err						= rate_limiter_create(&rl, max_ips);
	if (err != SSO_OK)
		goto fail;
	ctx->rate_limiter = rl;

	/* 3. Token manager — load secret or RSA keys */
	token_manager_t* tmgr = (token_manager_t*)calloc(1, sizeof(token_manager_t));
	if (!tmgr)
		return SSO_ERR_OUT_OF_MEMORY;

	long ttl = (config && config->token_ttl_ms > 0) ? config->token_ttl_ms : 3600000LL;

	if (config && config->private_key_pem[0] != '\0') {
		/* RS256 mode */
		err = token_manager_init_rs256(tmgr, config->private_key_pem,
									   config->public_key_pem[0] ? config->public_key_pem : NULL, ttl);
		if (err == SSO_OK) {
			LOG_INFO("[sso] Asymmetric signing (RS256) enabled.");
		} else {
			LOG_WARN("[sso] Failed to init RS256: %s. Falling back to HS256.", sso_strerror(err));
			config->private_key_pem[0] = '\0'; /* trigger fallback */
		}
	}

	if (!config || config->private_key_pem[0] == '\0') {
		/* HS256 mode */
		unsigned char secret[SSO_SECRET_BYTES];
		if (config && config->token_secret[0] != '\0') {
			size_t slen		= strlen(config->token_secret);
			size_t copy_len = slen < SSO_SECRET_BYTES ? slen : SSO_SECRET_BYTES;
			memcpy(secret, config->token_secret, copy_len);
			if (copy_len < SSO_SECRET_BYTES)
				memset(secret + copy_len, 0, SSO_SECRET_BYTES - copy_len);
			err = SSO_OK;
		} else {
			err = load_token_secret(secret, SSO_SECRET_BYTES);
		}

		if (err != SSO_OK) {
			free(tmgr);
			return err;
		}
		token_manager_init(tmgr, secret, SSO_SECRET_BYTES, ttl);
		/* Securely wipe the stack copy of the key after use. */
		sodium_memzero(secret, SSO_SECRET_BYTES);
	}

	/* P0: wipe token_secret in config now that token_manager has a copy */
	if (config) {
		sodium_memzero(config->token_secret, sizeof(config->token_secret));
		/* Also wipe private_key_pem after token_manager consumed it */
		sodium_memzero(config->private_key_pem, sizeof(config->private_key_pem));
	}

	tmgr->storage  = ctx->storage_backend;
	ctx->token_mgr = tmgr;

	/* 3. Managers */
	user_manager_t*		 umgr	 = NULL;
	role_manager_t*		 rmgr	 = NULL;
	group_manager_t*	 gmgr	 = NULL;
	policy_manager_t*	 pmgr	 = NULL;
	permission_engine_t* pengine = NULL;

	if ((err = user_manager_create(&umgr, ctx)) != SSO_OK)
		goto fail;
	ctx->user_mgr = umgr;

	if ((err = role_manager_create(&rmgr, ctx)) != SSO_OK)
		goto fail;
	ctx->role_mgr = rmgr;

	if ((err = group_manager_create(&gmgr, ctx)) != SSO_OK)
		goto fail;
	ctx->group_mgr = gmgr;

	if ((err = policy_manager_create(&pmgr, ctx)) != SSO_OK)
		goto fail;
	ctx->policy_mgr = pmgr;

	if ((err = perm_engine_create(&pengine, ctx)) != SSO_OK)
		goto fail;
	ctx->perm_engine = pengine;

	return SSO_OK;

fail:
	sso_destroy(ctx);
	return err;
}

void sso_destroy(sso_context_t* ctx) {
	if (!ctx)
		return;

	if (ctx->rate_limiter)
		rate_limiter_destroy((rate_limiter_t*)ctx->rate_limiter);
	if (ctx->perm_engine)
		perm_engine_destroy((permission_engine_t*)ctx->perm_engine);
	if (ctx->policy_mgr)
		policy_manager_destroy((policy_manager_t*)ctx->policy_mgr);
	if (ctx->group_mgr)
		group_manager_destroy((group_manager_t*)ctx->group_mgr);
	if (ctx->role_mgr)
		role_manager_destroy((role_manager_t*)ctx->role_mgr);
	if (ctx->user_mgr)
		user_manager_destroy((user_manager_t*)ctx->user_mgr);

	if (ctx->token_mgr) {
		/* Use the destroy function that securely wipes the secret. */
		token_manager_destroy((token_manager_t*)ctx->token_mgr);
	}

	if (ctx->storage_backend) {
		storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
		if (sb->close)
			sb->close(sb);
		free(sb);
	}

	if (ctx->config) {
		free(ctx->config);
	}

	memset(ctx, 0, sizeof(*ctx));
}

/* Global metrics definitions */
atomic_int	  g_metric_active_connections	= 0;
atomic_ullong g_metric_mfa_success			= 0;
atomic_ullong g_metric_mfa_failure			= 0;
atomic_ullong g_metric_jwt_issue			= 0;
atomic_ullong g_metric_jwt_revoke			= 0;
atomic_ullong g_metric_db_read_count		= 0;
atomic_ullong g_metric_db_read_duration_us	= 0;
atomic_ullong g_metric_db_write_count		= 0;
atomic_ullong g_metric_db_write_duration_us = 0;
atomic_ullong g_metric_arena_blocks			= 0;
