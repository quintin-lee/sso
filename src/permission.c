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
#include "config.h"
#include "logger.h"
#include "otlp.h"
#include "permission.h"
#include "policy.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "storage.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>

/* Audit log path — set from sso_config_t during engine creation. */
static char			 s_audit_log_path[256]	  = "audit.log";
static int			 s_audit_log_max_size_mb  = 10;
static int			 s_audit_log_max_backups  = 5;
static bool			 s_audit_log_rotate_daily = false;
static int			 s_audit_log_last_yday	  = -1;
static char			 s_audit_log_secret[128]  = {0};
static unsigned char s_audit_hmac_prev[32]	  = {0};

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
	sso_id_t			 policy_id;
	void*				 compiled;
	perm_strategy_type_t strategy_type;
} policy_cache_entry_t;

typedef struct {
	sso_id_t user_id;
	policy_t policies[64];
	size_t	 count;
	uint64_t timestamp;
	bool	 valid;
} policy_res_cache_entry_t;

typedef struct {
	sso_id_t user_id;
	uint32_t params_hash;
	bool	 allowed;
	uint64_t timestamp;
	bool	 valid;
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
	sso_context_t*		   ctx;
	permission_strategy_t* strategies[MAX_STRATEGIES];
	size_t				   strategy_count;

	/* Concurrency control */
	pthread_rwlock_t lock;

	/* Policy compilation cache */
	policy_cache_entry_t cache[MAX_POLICY_CACHE];
	size_t				 cache_count;

	/* Policy resolution cache (L1) */
	policy_res_cache_entry_t res_cache[POLICY_RES_CACHE_SIZE];

	/* Result cache (L2) */
	result_cache_entry_t result_cache[RESULT_CACHE_SIZE];

	/* Metrics */
	engine_metrics_t metrics;
};

/* -----------------------------------------------------------------------
 * Hashing for result cache
 * ----------------------------------------------------------------------- */
static uint32_t hash_params(const eval_context_t* ctx) {
	uint32_t			 hash = 5381;
	const unsigned char* p	  = (const unsigned char*)&ctx->params;
	size_t				 len  = sizeof(ctx->params);
	for (size_t i = 0; i < len; i++) {
		hash = ((hash << 5) + hash) + p[i];
	}
	return hash;
}

/* Wall-clock time for audit log timestamps. */
static uint64_t get_time_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

/* Monotonic time for cache TTL / duration measurements — immune to system clock jumps. */
static uint64_t get_time_monotonic_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

sso_error_t perm_engine_create(permission_engine_t** engine, sso_context_t* ctx) {
	if (!engine || !ctx)
		return SSO_ERR_INVALID_PARAM;

	*engine = (permission_engine_t*)calloc(1, sizeof(permission_engine_t));
	if (!*engine)
		return SSO_ERR_OUT_OF_MEMORY;

	(*engine)->ctx			  = ctx;
	(*engine)->strategy_count = 0;
	(*engine)->cache_count	  = 0;

	if (pthread_rwlock_init(&(*engine)->lock, NULL) != 0) {
		free(*engine);
		LOG_ERROR("pthread_rwlock_init failed");
		return SSO_ERR_INIT;
	}

	sso_error_t err;

	/* Register built-in strategies */
	if ((err = perm_engine_register_strategy(*engine, &func_perm_strategy)) != SSO_OK ||
		(err = perm_engine_register_strategy(*engine, &api_perm_strategy)) != SSO_OK ||
		(err = perm_engine_register_strategy(*engine, &data_perm_strategy)) != SSO_OK ||
		(err = perm_engine_register_strategy(*engine, &rbac_perm_strategy)) != SSO_OK ||
		(err = perm_engine_register_strategy(*engine, &location_perm_strategy)) != SSO_OK ||
		(err = perm_engine_register_strategy(*engine, &abac_perm_strategy)) != SSO_OK ||
		(err = perm_engine_register_strategy(*engine, &lbac_perm_strategy)) != SSO_OK) {
		perm_engine_destroy(*engine);
		return err;
	}

	/* Copy audit log path from config */
	sso_config_t* cfg = (sso_config_t*)sso_get_config(ctx);
	if (cfg) {
		if (cfg->audit_log_path[0]) {
			snprintf(s_audit_log_path, sizeof(s_audit_log_path), "%s", cfg->audit_log_path);
		}
		s_audit_log_max_size_mb	 = cfg->audit_log_max_size_mb;
		s_audit_log_max_backups	 = cfg->audit_log_max_backups;
		s_audit_log_rotate_daily = cfg->audit_log_rotate_daily;
		snprintf(s_audit_log_secret, sizeof(s_audit_log_secret), "%s", cfg->audit_log_secret);

		time_t	   now	   = time(NULL);
		struct tm* tm_info = localtime(&now);
		if (tm_info)
			s_audit_log_last_yday = tm_info->tm_yday;
	}

	return SSO_OK;
}

void perm_engine_destroy(permission_engine_t* engine) {
	if (!engine)
		return;

	pthread_rwlock_wrlock(&engine->lock);

	/* Free cached compiled rules */
	for (size_t i = 0; i < MAX_POLICY_CACHE; i++) {
		if (engine->cache[i].policy_id == 0)
			continue;
		permission_strategy_t* strat = perm_engine_get_strategy(engine, engine->cache[i].strategy_type);
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

static void* perm_engine_get_cached_rule(permission_engine_t* engine, sso_id_t policy_id) {
	if (engine->cache_count == 0)
		return NULL;
	/* Direct-index hash: policy IDs are dense sequential integers, so
	   ID % MAX_POLICY_CACHE gives a well-distributed slot, with linear
	   probe for the rare collision (cache_count <= 256). */
	size_t start = (size_t)policy_id % MAX_POLICY_CACHE;
	size_t idx	 = start;
	do {
		if (engine->cache[idx].policy_id == policy_id)
			return engine->cache[idx].compiled;
		if (engine->cache[idx].policy_id == 0)
			break; /* empty slot — not found */
		idx = (idx + 1) % MAX_POLICY_CACHE;
	} while (idx != start);
	return NULL;
}

static void perm_engine_cache_rule(permission_engine_t* engine, sso_id_t policy_id, perm_strategy_type_t type,
								   void* compiled) {
	if (engine->cache_count >= MAX_POLICY_CACHE)
		return;
	size_t start = (size_t)policy_id % MAX_POLICY_CACHE;
	size_t idx	 = start;
	do {
		if (engine->cache[idx].policy_id == 0 || engine->cache[idx].policy_id == policy_id) {
			bool is_new						 = (engine->cache[idx].policy_id == 0);
			engine->cache[idx].policy_id	 = policy_id;
			engine->cache[idx].strategy_type = type;
			engine->cache[idx].compiled		 = compiled;
			if (is_new)
				engine->cache_count++;
			return;
		}
		idx = (idx + 1) % MAX_POLICY_CACHE;
	} while (idx != start);
}

void perm_engine_cache_invalidate_user(permission_engine_t* engine, sso_id_t user_id) {
	if (!engine)
		return;
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

void perm_engine_cache_invalidate_policy(permission_engine_t* engine, sso_id_t policy_id) {
	if (!engine)
		return;
	pthread_rwlock_wrlock(&engine->lock);

	/* 1. Invalidate compiled rule */
	size_t start = (size_t)policy_id % MAX_POLICY_CACHE;
	size_t idx	 = start;
	do {
		if (engine->cache[idx].policy_id == policy_id) {
			permission_strategy_t* strat = perm_engine_get_strategy(engine, engine->cache[idx].strategy_type);
			if (strat && strat->free_compiled_rules) {
				strat->free_compiled_rules(strat, engine->cache[idx].compiled);
			}
			engine->cache[idx].policy_id = 0;
			engine->cache_count--;
			break;
		}
		if (engine->cache[idx].policy_id == 0)
			break; /* empty slot — policy not cached */
		idx = (idx + 1) % MAX_POLICY_CACHE;
	} while (idx != start);

	/* 2. Clear all result and resolution caches as this policy might affect anyone */
	for (size_t i = 0; i < RESULT_CACHE_SIZE; i++) {
		engine->result_cache[i].valid = false;
	}
	for (size_t i = 0; i < POLICY_RES_CACHE_SIZE; i++) {
		engine->res_cache[i].valid = false;
	}

	pthread_rwlock_unlock(&engine->lock);
}

void perm_engine_cache_invalidate_all(permission_engine_t* engine) {
	if (!engine)
		return;
	pthread_rwlock_wrlock(&engine->lock);

	for (size_t i = 0; i < MAX_POLICY_CACHE; i++) {
		if (engine->cache[i].policy_id == 0)
			continue;
		permission_strategy_t* strat = perm_engine_get_strategy(engine, engine->cache[i].strategy_type);
		if (strat && strat->free_compiled_rules) {
			strat->free_compiled_rules(strat, engine->cache[i].compiled);
		}
		engine->cache[i].policy_id = 0;
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

sso_error_t perm_engine_register_strategy(permission_engine_t* engine, permission_strategy_t* strategy) {
	if (!engine || !strategy)
		return SSO_ERR_INVALID_PARAM;

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

sso_error_t perm_engine_unregister_strategy(permission_engine_t* engine, perm_strategy_type_t type) {
	if (!engine)
		return SSO_ERR_INVALID_PARAM;

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

permission_strategy_t* perm_engine_get_strategy(permission_engine_t* engine, perm_strategy_type_t type) {
	if (!engine)
		return NULL;
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
sso_error_t perm_engine_get_metrics(permission_engine_t* engine, char* buf, size_t max) {
	if (!engine || !buf)
		return SSO_ERR_INVALID_PARAM;

	unsigned long long evals	= atomic_load(&engine->metrics.total_evals);
	unsigned long long l1_hits	= atomic_load(&engine->metrics.cache_hits_l1);
	unsigned long long l2_hits	= atomic_load(&engine->metrics.cache_hits_l2);
	unsigned long long allows	= atomic_load(&engine->metrics.allows);
	unsigned long long denys	= atomic_load(&engine->metrics.denys);
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

sso_error_t perm_engine_evaluate_policy(permission_engine_t* engine, const policy_t* policy, eval_context_t* ctx,
										bool* result, char** decision_trace) {
	if (!engine || !policy || !ctx || !result)
		return SSO_ERR_INVALID_PARAM;

	/* Skip disabled policies — return NOT_FOUND so callers skip them */
	if (policy->status == POLICY_STATUS_DISABLED) {
		if (decision_trace)
			*decision_trace = strdup("Policy disabled (skipped)");
		return SSO_ERR_NOT_FOUND;
	}

	/* Find the strategy for this policy */
	permission_strategy_t* strategy = perm_engine_get_strategy(engine, policy->strategy_type);
	if (!strategy) {
		if (decision_trace)
			*decision_trace = strdup("Strategy not found");
		return SSO_ERR_STRATEGY_NOT_FOUND;
	}

	if (!strategy->evaluate) {
		return SSO_ERR_NOT_IMPLEMENTED;
	}

	/* Handle pre-compilation */
	void* compiled = NULL;
	if (strategy->compile_rules) {
		compiled = perm_engine_get_cached_rule(engine, policy->id);
		if (!compiled) {
			sso_error_t cerr = strategy->compile_rules(strategy, policy->rules, &compiled);
			if (cerr == SSO_OK) {
				perm_engine_cache_rule(engine, policy->id, strategy->type, compiled);
			}
		}
	}

	bool		strategy_result = false;
	sso_error_t err				= strategy->evaluate(strategy, ctx, policy, compiled, &strategy_result);

	if (decision_trace) {
		char buf[256];
		snprintf(buf, sizeof(buf), "Strategy %s: %s (matched: %s)", strategy->name, strategy_result ? "ALLOW" : "DENY",
				 err == SSO_OK ? "YES" : "NO");
		*decision_trace = strdup(buf);
	}

	if (err == SSO_ERR_NOT_FOUND) {
		return SSO_ERR_NOT_FOUND;
	}
	if (err != SSO_OK)
		return err;

	*result = strategy_result;
	return SSO_OK;
}

#define AUDIT_LOG_MAX_SIZE (10 * 1024 * 1024)
#define AUDIT_LOG_MAX_BACKUPS 5
#define AUDIT_LOG_STAT_INTERVAL 100

static pthread_mutex_t audit_log_lock = PTHREAD_MUTEX_INITIALIZER;

/* Persistent audit log file pointer — avoids fopen/fclose per-call overhead. */
static FILE* s_audit_log_file = NULL;

static void audit_log_close(void) {
	if (s_audit_log_file) {
		fclose(s_audit_log_file);
		s_audit_log_file = NULL;
	}
}

/* Open (or re-open after rotation) the audit log file with large buffer. */
static FILE* audit_log_open(void) {
	if (s_audit_log_file)
		return s_audit_log_file;
	s_audit_log_file = fopen(s_audit_log_path, "a");
	if (s_audit_log_file) {
		setvbuf(s_audit_log_file, NULL, _IOFBF, 65536); /* 64 KB buffer */
	}
	return s_audit_log_file;
}

static void rotate_audit_log(void) {
	/* Throttle: only stat() every N calls to avoid filesystem overhead. */
	static unsigned int stat_count = 0;
	if ((++stat_count) % AUDIT_LOG_STAT_INTERVAL != 0)
		return;

	bool needs_rotation	 = false;
	char date_suffix[32] = "";

	time_t	   now	   = time(NULL);
	struct tm* tm_info = localtime(&now);

	if (s_audit_log_rotate_daily && tm_info) {
		if (s_audit_log_last_yday != -1 && tm_info->tm_yday != s_audit_log_last_yday) {
			needs_rotation = true;
			/* Use yesterday's date for the rotated file */
			time_t	   yesterday = now - 86400;
			struct tm* y_info	 = localtime(&yesterday);
			if (y_info) {
				strftime(date_suffix, sizeof(date_suffix), "-%Y-%m-%d", y_info);
			}
		}
		s_audit_log_last_yday = tm_info->tm_yday;
	}

	if (!needs_rotation && s_audit_log_max_size_mb > 0) {
		if (s_audit_log_file) {
			fflush(s_audit_log_file); /* Ensure stat sees the correct size */
		}
		struct stat st;
		if (stat(s_audit_log_path, &st) == 0) {
			if (st.st_size >= (off_t)s_audit_log_max_size_mb * 1024 * 1024) {
				needs_rotation = true;
			}
		}
	}

	if (!needs_rotation)
		return;

	/* Close before rotation so the old file is fully written,
	 * then reopen after renaming to follow the new file. */
	audit_log_close();

	if (date_suffix[0] != '\0') {
		/* Date-based rotation: rename to audit.log-YYYY-MM-DD */
		char rotated[512];
		snprintf(rotated, sizeof(rotated), "%s%s", s_audit_log_path, date_suffix);
		rename(s_audit_log_path, rotated);
	} else {
		/* Size-based rotation: rename to audit.log.1, audit.log.2, etc. */
		char oldpath[512], newpath[512];
		for (int i = s_audit_log_max_backups - 1; i > 0; i--) {
			snprintf(oldpath, sizeof(oldpath), "%s.%d", s_audit_log_path, i);
			snprintf(newpath, sizeof(newpath), "%s.%d", s_audit_log_path, i + 1);
			rename(oldpath, newpath);
		}
		char rotated[512];
		snprintf(rotated, sizeof(rotated), "%s.1", s_audit_log_path);
		rename(s_audit_log_path, rotated);
	}

	/* Reopen will happen lazily on next write via audit_log_open(). */
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
static void write_audit_entry_with_hmac(FILE* f, const char* json_payload) {
	if (s_audit_log_secret[0] != '\0') {
		/* Compute HMAC = HMAC-SHA256(secret, prev_hmac + json_payload) */
		HMAC_CTX* hctx = HMAC_CTX_new();
		HMAC_Init_ex(hctx, s_audit_log_secret, strlen(s_audit_log_secret), EVP_sha256(), NULL);
		HMAC_Update(hctx, s_audit_hmac_prev, sizeof(s_audit_hmac_prev));
		HMAC_Update(hctx, (const unsigned char*)json_payload, strlen(json_payload));
		unsigned int len = 0;
		HMAC_Final(hctx, s_audit_hmac_prev, &len);
		HMAC_CTX_free(hctx);

		char hex_sig[65];
		for (int i = 0; i < 32; i++) {
			sprintf(hex_sig + (i * 2), "%02x", s_audit_hmac_prev[i]);
		}
		fprintf(f, "%s,\"signature\":\"%s\"}\n", json_payload, hex_sig);
	} else {
		fprintf(f, "%s}\n", json_payload);
	}
}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

static void audit_log_decision(sso_context_t* sso_ctx, const eval_context_t* ctx, bool allowed, const char* trace,
							   uint64_t duration_ms, bool cache_hit) {
	if (sso_ctx && sso_ctx->storage_backend) {
		storage_backend_t* sb = (storage_backend_t*)sso_ctx->storage_backend;
		if (sb->audit_log_write) {
			audit_log_entry_t entry;
			memset(&entry, 0, sizeof(entry));
			entry.action	   = "eval";
			entry.timestamp_ms = get_time_ms();
			entry.user_id	   = ctx->user_id;
			entry.status	   = allowed ? "ALLOW" : "DENY";
			entry.duration_ms  = duration_ms;
			entry.cache_hit	   = cache_hit;
			entry.trace		   = trace;
			sb->audit_log_write(sb, &entry);
		}
	}

	pthread_mutex_lock(&audit_log_lock);
	rotate_audit_log();

	FILE* f = audit_log_open();
	if (!f) {
		pthread_mutex_unlock(&audit_log_lock);
		return;
	}

	char* escaped_trace = (char*)calloc(1, 8192);
	if (!escaped_trace) {
		pthread_mutex_unlock(&audit_log_lock);
		return;
	}
	if (trace) {
		size_t j = 0;
		for (size_t i = 0; trace[i] && j < 8192 - 3; i++) {
			if (trace[i] == '"') {
				escaped_trace[j++] = '\\';
				escaped_trace[j++] = '"';
			} else if (trace[i] == '\n') {
				escaped_trace[j++] = '\\';
				escaped_trace[j++] = 'n';
			} else if (trace[i] == '\t') {
				escaped_trace[j++] = '\\';
				escaped_trace[j++] = 't';
			} else
				escaped_trace[j++] = trace[i];
		}
	}

	char* entry_buf = (char*)malloc(8192 + 1024);
	if (entry_buf) {
		snprintf(entry_buf, 8192 + 1024,
				 "{"
				 "\"timestamp_ms\":%llu,"
				 "\"user_id\":%llu,"
				 "\"decision\":\"%s\","
				 "\"duration_ms\":%llu,"
				 "\"cache_hit\":%s,"
				 "\"trace\":\"%s\"",
				 (unsigned long long)get_time_ms(), (unsigned long long)ctx->user_id, allowed ? "ALLOW" : "DENY",
				 (unsigned long long)duration_ms, cache_hit ? "true" : "false", escaped_trace);
		write_audit_entry_with_hmac(f, entry_buf);
		free(entry_buf);
	}

	pthread_mutex_unlock(&audit_log_lock);
	free(escaped_trace);
}

void admin_audit_log(sso_context_t* ctx, sso_id_t actor_user_id, const char* actor_username, const char* client_ip,
					 const char* operation, const char* resource, sso_id_t resource_id, const char* status,
					 const char* details) {
	if (ctx && ctx->storage_backend) {
		storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
		if (sb->audit_log_write) {
			audit_log_entry_t entry;
			memset(&entry, 0, sizeof(entry));
			entry.action	   = "admin";
			entry.timestamp_ms = get_time_ms();
			entry.user_id	   = actor_user_id;
			entry.username	   = actor_username;
			entry.ip_address   = client_ip;
			entry.operation	   = operation;
			entry.resource	   = resource;
			entry.resource_id  = resource_id;
			entry.status	   = status;
			entry.details	   = details;
			sb->audit_log_write(sb, &entry);
		}
	}

	sso_config_t* cfg	   = ctx ? sso_get_config(ctx) : NULL;
	const char*	  log_path = s_audit_log_path;
	if (cfg && cfg->audit_log_path[0]) {
		log_path = cfg->audit_log_path;
	}

	pthread_mutex_lock(&audit_log_lock);
	rotate_audit_log();

	/* If the log path differs from the default, fall back to fopen/fclose.
	 * Otherwise use the persistent FILE* for efficiency. */
	FILE* f;
	bool  use_persistent = (log_path == s_audit_log_path || strcmp(log_path, s_audit_log_path) == 0);
	if (use_persistent) {
		f = audit_log_open();
	} else {
		f = fopen(log_path, "a");
	}
	if (!f) {
		pthread_mutex_unlock(&audit_log_lock);
		return;
	}

	char esc_user[256] = "", esc_ip[64] = "", esc_op[64] = "";
	char esc_res[64] = "", esc_st[16] = "", esc_det[1024] = "";
	if (actor_username) {
		size_t j = 0;
		for (size_t i = 0; actor_username[i] && j < sizeof(esc_user) - 3; i++) {
			if (actor_username[i] == '"') {
				esc_user[j++] = '\\';
				esc_user[j++] = '"';
			} else if (actor_username[i] == '\\') {
				esc_user[j++] = '\\';
				esc_user[j++] = '\\';
			} else
				esc_user[j++] = actor_username[i];
		}
	}
	if (client_ip) {
		size_t j = 0;
		for (size_t i = 0; client_ip[i] && j < sizeof(esc_ip) - 3; i++) {
			if (client_ip[i] == '"') {
				esc_ip[j++] = '\\';
				esc_ip[j++] = '"';
			} else
				esc_ip[j++] = client_ip[i];
		}
	}
	if (operation) {
		size_t j = 0;
		for (size_t i = 0; operation[i] && j < sizeof(esc_op) - 3; i++) {
			if (operation[i] == '"') {
				esc_op[j++] = '\\';
				esc_op[j++] = '"';
			} else
				esc_op[j++] = operation[i];
		}
	}
	if (resource) {
		size_t j = 0;
		for (size_t i = 0; resource[i] && j < sizeof(esc_res) - 3; i++) {
			if (resource[i] == '"') {
				esc_res[j++] = '\\';
				esc_res[j++] = '"';
			} else
				esc_res[j++] = resource[i];
		}
	}
	if (status) {
		size_t j = 0;
		for (size_t i = 0; status[i] && j < sizeof(esc_st) - 3; i++) {
			if (status[i] == '"') {
				esc_st[j++] = '\\';
				esc_st[j++] = '"';
			} else
				esc_st[j++] = status[i];
		}
	}
	if (details) {
		size_t j = 0;
		for (size_t i = 0; details[i] && j < sizeof(esc_det) - 3; i++) {
			if (details[i] == '"') {
				esc_det[j++] = '\\';
				esc_det[j++] = '"';
			} else if (details[i] == '\n') {
				esc_det[j++] = '\\';
				esc_det[j++] = 'n';
			} else
				esc_det[j++] = details[i];
		}
	}

	char* entry_buf = (char*)malloc(4096 + 1024);
	if (entry_buf) {
		snprintf(entry_buf, 4096 + 1024,
				 "{"
				 "\"action\":\"admin\","
				 "\"timestamp_ms\":%llu,"
				 "\"user_id\":%llu,"
				 "\"username\":\"%s\","
				 "\"ip_address\":\"%s\","
				 "\"operation\":\"%s\","
				 "\"resource\":\"%s\","
				 "\"resource_id\":%llu,"
				 "\"status\":\"%s\","
				 "\"details\":\"%s\"",
				 (unsigned long long)get_time_ms(), (unsigned long long)actor_user_id, esc_user, esc_ip, esc_op,
				 esc_res, (unsigned long long)resource_id, esc_st, esc_det);
		write_audit_entry_with_hmac(f, entry_buf);
		free(entry_buf);
	}

	if (!use_persistent)
		fclose(f);
	pthread_mutex_unlock(&audit_log_lock);
}

static sso_error_t perm_engine_evaluate_internal(permission_engine_t* engine, eval_context_t* ctx, bool* result,
												 char** decision_trace) {
	if (!engine || !ctx || !result)
		return SSO_ERR_INVALID_PARAM;
	if (!ctx->user && ctx->user_id == 0)
		return SSO_ERR_INVALID_PARAM;

	uint32_t phash	   = hash_params(ctx);
	size_t	 cache_idx = phash % RESULT_CACHE_SIZE;
	size_t	 l1_idx	   = ctx->user_id % POLICY_RES_CACHE_SIZE;
	uint64_t now	   = get_time_monotonic_ms();

	sso_error_t err;
	char*		full_trace = (char*)calloc(1, 4096);
	if (!full_trace)
		return SSO_ERR_OUT_OF_MEMORY;
	bool any_allowed = false;

	/* ---- Phase 1: L2 (result) cache check under rdlock ---- */
	pthread_rwlock_rdlock(&engine->lock);

	if (engine->result_cache[cache_idx].valid && engine->result_cache[cache_idx].user_id == ctx->user_id &&
		engine->result_cache[cache_idx].params_hash == phash &&
		(now - engine->result_cache[cache_idx].timestamp) < 30000) {
		*result = engine->result_cache[cache_idx].allowed;
		if (decision_trace)
			*decision_trace = strdup("Decision from Result Cache (L2)");

		atomic_fetch_add(&engine->metrics.cache_hits_l2, 1);
		atomic_fetch_add(&engine->metrics.total_evals, 1);
		if (*result)
			atomic_fetch_add(&engine->metrics.allows, 1);
		else
			atomic_fetch_add(&engine->metrics.denys, 1);

		pthread_rwlock_unlock(&engine->lock);

		uint64_t duration = get_time_monotonic_ms() - now;
		if (duration > 5) {
			LOG_WARN("[perm] CACHE HIT (SLOW): user=%ld duration=%lums", (long)ctx->user_id, (long)duration);
		}
		audit_log_decision(engine->ctx, ctx, *result, "Decision from Result Cache (L2)", duration, true);
		free(full_trace);
		return SSO_OK;
	}

	*result = false;
	if (decision_trace)
		*decision_trace = NULL;

	/* ---- Phase 2: L1 (resolution) cache check under rdlock ---- */
	bool	  l1_hit	   = (engine->res_cache[l1_idx].valid && engine->res_cache[l1_idx].user_id == ctx->user_id &&
							  (now - engine->res_cache[l1_idx].timestamp) < 60000);
	policy_t* policies_buf = NULL;
	policy_t* policies	   = NULL;
	size_t	  policy_count = 0;

	if (l1_hit) {
		policies	 = engine->res_cache[l1_idx].policies;
		policy_count = engine->res_cache[l1_idx].count;
		atomic_fetch_add(&engine->metrics.cache_hits_l1, 1);
	} else {
		policies_buf = (policy_t*)malloc(sizeof(policy_t) * 64);
		if (!policies_buf) {
			pthread_rwlock_unlock(&engine->lock);
			free(full_trace);
			return SSO_ERR_OUT_OF_MEMORY;
		}
		policies = policies_buf;
	}

	pthread_rwlock_unlock(&engine->lock);
	/* ---- No lock held beyond this point until Phase 3 re-acquire ---- */

	/* ---- Phase 2b: Policy resolution (DB query) without holding the lock ---- */
	if (!l1_hit) {
		size_t			  max_policies = 64;
		policy_manager_t* pmgr		   = (policy_manager_t*)engine->ctx->policy_mgr;
		if (!pmgr) {
			audit_log_decision(engine->ctx, ctx, false, "Error: policy manager not found",
							   get_time_monotonic_ms() - now, false);
			LOG_ERROR("policy manager not found in engine context");
			free(policies_buf);
			free(full_trace);
			return SSO_ERR_INIT;
		}

		err = policy_resolve_for_user(pmgr, ctx->user_id, policies_buf, &policy_count, max_policies);
		if (err != SSO_OK && err != SSO_ERR_NOT_FOUND) {
			audit_log_decision(engine->ctx, ctx, false, "Error: policy resolution failed",
							   get_time_monotonic_ms() - now, false);
			free(policies_buf);
			free(full_trace);
			return err;
		}
	}

	if (policy_count == 0) {
		if (decision_trace)
			*decision_trace = strdup("Default DENY: No policies found");
		audit_log_decision(engine->ctx, ctx, false, "Default DENY: No policies found", get_time_monotonic_ms() - now,
						   false);
		free(policies_buf);
		free(full_trace);
		return SSO_OK;
	}

	/* ---- Phase 3: Evaluation (with proper lock escalation for writing to caches) ---- */

	/* Update the L1 resolution cache under wrlock if it was an L1 miss. */
	if (!l1_hit) {
		pthread_rwlock_wrlock(&engine->lock);
		/* Re-check: another thread may have populated it first while we didn't hold any lock */
		if (!(engine->res_cache[l1_idx].valid && engine->res_cache[l1_idx].user_id == ctx->user_id &&
			  (now - engine->res_cache[l1_idx].timestamp) < 60000)) {
			engine->res_cache[l1_idx].user_id = ctx->user_id;
			memcpy(engine->res_cache[l1_idx].policies, policies_buf, sizeof(policy_t) * policy_count);
			engine->res_cache[l1_idx].count		= policy_count;
			engine->res_cache[l1_idx].timestamp = now;
			engine->res_cache[l1_idx].valid		= true;
		}
		pthread_rwlock_unlock(&engine->lock);
	}

	/* Acquire rdlock for policy evaluation loop to ensure strategies/compiled rules aren't modified */
	pthread_rwlock_rdlock(&engine->lock);

	size_t trace_off = 0;

	for (size_t i = 0; i < policy_count; i++) {
		bool  policy_result = false;
		char* policy_trace	= NULL;
		err					= perm_engine_evaluate_policy(engine, &policies[i], ctx, &policy_result, &policy_trace);

		if (decision_trace && policy_trace) {
			trace_off += snprintf(full_trace + trace_off, 4096 - trace_off, "[Policy %s] %s\n", policies[i].name,
								  policy_trace);
			if (trace_off >= 4096)
				trace_off = 4096 - 1;
		}
		if (policy_trace)
			free(policy_trace);

		if (err == SSO_ERR_NOT_FOUND)
			continue;
		if (err != SSO_OK)
			continue;

		if (!policy_result) {
			*result = false;
			if (decision_trace) {
				trace_off +=
						snprintf(full_trace + trace_off, 4096 - trace_off, "Result: DENIED (Override by policy)\n");
				if (trace_off >= 4096)
					trace_off = 4096 - 1;
				*decision_trace = strdup(full_trace);
			}

			/* Release read lock before acquiring write lock to populate result cache */
			pthread_rwlock_unlock(&engine->lock);

			pthread_rwlock_wrlock(&engine->lock);
			engine->result_cache[cache_idx].user_id		= ctx->user_id;
			engine->result_cache[cache_idx].params_hash = phash;
			engine->result_cache[cache_idx].allowed		= false;
			engine->result_cache[cache_idx].timestamp	= now;
			engine->result_cache[cache_idx].valid		= true;
			pthread_rwlock_unlock(&engine->lock);

			audit_log_decision(engine->ctx, ctx, false, full_trace, get_time_monotonic_ms() - now, false);
			free(policies_buf);
			free(full_trace);
			return SSO_OK;
		}

		any_allowed = true;
	}

	*result = any_allowed;
	if (decision_trace) {
		trace_off += snprintf(full_trace + trace_off, 4096 - trace_off, "%s\n",
							  any_allowed ? "Result: ALLOWED" : "Result: DENIED (No matching allow rule)");
		if (trace_off >= 4096)
			trace_off = 4096 - 1;
		*decision_trace = strdup(full_trace);
	}

	/* Release read lock before acquiring write lock to populate result cache */
	pthread_rwlock_unlock(&engine->lock);

	pthread_rwlock_wrlock(&engine->lock);
	engine->result_cache[cache_idx].user_id		= ctx->user_id;
	engine->result_cache[cache_idx].params_hash = phash;
	engine->result_cache[cache_idx].allowed		= any_allowed;
	engine->result_cache[cache_idx].timestamp	= now;
	engine->result_cache[cache_idx].valid		= true;
	pthread_rwlock_unlock(&engine->lock);

	atomic_fetch_add(&engine->metrics.total_evals, 1);
	if (any_allowed)
		atomic_fetch_add(&engine->metrics.allows, 1);
	else
		atomic_fetch_add(&engine->metrics.denys, 1);

	uint64_t duration = get_time_monotonic_ms() - now;
	atomic_fetch_add(&engine->metrics.total_duration_us, (unsigned long long)duration * 1000);
	if (duration > 10) {
		LOG_WARN("[perm] SLOW EVAL: user=%ld duration=%lums cache=MISS", (long)ctx->user_id, (long)duration);
	}

	audit_log_decision(engine->ctx, ctx, any_allowed, full_trace, duration, false);
	free(policies_buf);
	free(full_trace);
	return SSO_OK;
}

/* ========================================================================
 * Convenience one-shot checkers
 * ======================================================================== */

sso_error_t perm_check_function(sso_context_t* ctx, sso_id_t user_id, const char* function_code, bool* allowed) {
	if (!ctx || !function_code || !allowed)
		return SSO_ERR_INVALID_PARAM;

	/* Fetch user */
	user_t		user;
	sso_error_t err = user_get_by_id((user_manager_t*)ctx->user_mgr, user_id, &user);
	if (err != SSO_OK)
		return err;

	/* Set up eval context */
	eval_context_t ectx;
	eval_context_init(&ectx, &user);
	sso_strlcpy(ectx.params.functional.function_code, function_code, sizeof(ectx.params.functional.function_code));

	/* Evaluate */
	err = perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, allowed, NULL);
	eval_context_destroy(&ectx);
	return err;
}

sso_error_t perm_check_api(sso_context_t* ctx, sso_id_t user_id, const char* method, const char* path, bool* allowed) {
	if (!ctx || !method || !path || !allowed)
		return SSO_ERR_INVALID_PARAM;

	user_t		user;
	sso_error_t err = user_get_by_id((user_manager_t*)ctx->user_mgr, user_id, &user);
	if (err != SSO_OK)
		return err;

	eval_context_t ectx;
	eval_context_init(&ectx, &user);
	sso_strlcpy(ectx.params.api.http_method, method, sizeof(ectx.params.api.http_method));
	sso_strlcpy(ectx.params.api.request_path, path, sizeof(ectx.params.api.request_path));

	err = perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, allowed, NULL);
	eval_context_destroy(&ectx);
	return err;
}

sso_error_t perm_check_data(sso_context_t* ctx, sso_id_t user_id, const char* resource_type, const char* record_json,
							bool* allowed, char*** field_filter, size_t* field_count) {
	if (!ctx || !resource_type || !allowed)
		return SSO_ERR_INVALID_PARAM;

	user_t		user;
	sso_error_t err = user_get_by_id((user_manager_t*)ctx->user_mgr, user_id, &user);
	if (err != SSO_OK)
		return err;

	eval_context_t ectx;
	eval_context_init(&ectx, &user);
	sso_strlcpy(ectx.params.data.resource_type, resource_type, sizeof(ectx.params.data.resource_type));
	if (record_json) {
		ectx.params.data.record		= strdup(record_json);
		ectx.params.data.record_len = strlen(record_json);
	}
	ectx.params.data.field_filter		= NULL;
	ectx.params.data.field_filter_count = 0;

	err = perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, allowed, NULL);

	/* Pass back field filter if the data strategy populated it */
	if (err == SSO_OK && field_filter && field_count) {
		*field_filter = ectx.params.data.field_filter;
		*field_count  = ectx.params.data.field_filter_count;
		/* Zero the context copy so eval_context_destroy doesn't free it */
		ectx.params.data.field_filter		= NULL;
		ectx.params.data.field_filter_count = 0;
		eval_context_destroy(&ectx);
	} else {
		eval_context_destroy(&ectx);
	}

	return err;
}

sso_error_t perm_check_rbac(sso_context_t* ctx, sso_id_t user_id, const char* role_name, bool* allowed) {
	if (!ctx || !role_name || !allowed)
		return SSO_ERR_INVALID_PARAM;

	user_t		user;
	sso_error_t err = user_get_by_id((user_manager_t*)ctx->user_mgr, user_id, &user);
	if (err != SSO_OK)
		return err;

	eval_context_t ectx;
	eval_context_init(&ectx, &user);
	sso_strlcpy(ectx.params.rbac.role_name, role_name, sizeof(ectx.params.rbac.role_name));

	err = perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, allowed, NULL);
	eval_context_destroy(&ectx);
	return err;
}

sso_error_t perm_check_location(sso_context_t* ctx, sso_id_t user_id, const char* source_ip, const char* geo_country,
								bool* allowed) {
	if (!ctx || !source_ip || !allowed)
		return SSO_ERR_INVALID_PARAM;

	user_t		user;
	sso_error_t err = user_get_by_id((user_manager_t*)ctx->user_mgr, user_id, &user);
	if (err != SSO_OK)
		return err;

	eval_context_t ectx;
	eval_context_init(&ectx, &user);
	sso_strlcpy(ectx.params.location.source_ip, source_ip, sizeof(ectx.params.location.source_ip));
	if (geo_country) {
		sso_strlcpy(ectx.params.location.geo_country, geo_country, sizeof(ectx.params.location.geo_country));
	}

	err = perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, allowed, NULL);
	eval_context_destroy(&ectx);
	return err;
}

sso_error_t perm_check_lbac(sso_context_t* ctx, sso_id_t user_id, const char* user_labels, const char* resource_label,
							bool* allowed) {
	if (!ctx || !user_labels || !resource_label || !allowed)
		return SSO_ERR_INVALID_PARAM;

	user_t		user;
	sso_error_t err = user_get_by_id((user_manager_t*)ctx->user_mgr, user_id, &user);
	if (err != SSO_OK)
		return err;

	eval_context_t ectx;
	eval_context_init(&ectx, &user);
	sso_strlcpy(ectx.params.lbac.user_labels, user_labels, sizeof(ectx.params.lbac.user_labels));
	sso_strlcpy(ectx.params.lbac.resource_label, resource_label, sizeof(ectx.params.lbac.resource_label));

	err = perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, allowed, NULL);
	eval_context_destroy(&ectx);
	return err;
}

sso_error_t perm_check_abac(sso_context_t* ctx, sso_id_t user_id, const char* subject_attrs, const char* resource_attrs,
							const char* action, bool* allowed) {
	if (!ctx || !allowed)
		return SSO_ERR_INVALID_PARAM;

	user_t		user;
	sso_error_t err = user_get_by_id((user_manager_t*)ctx->user_mgr, user_id, &user);
	if (err != SSO_OK)
		return err;

	eval_context_t ectx;
	eval_context_init(&ectx, &user);
	if (subject_attrs) {
		sso_strlcpy(ectx.params.abac.subject_attrs, subject_attrs, sizeof(ectx.params.abac.subject_attrs));
	}
	if (resource_attrs) {
		sso_strlcpy(ectx.params.abac.resource_attrs, resource_attrs, sizeof(ectx.params.abac.resource_attrs));
	}
	if (action) {
		sso_strlcpy(ectx.params.abac.action, action, sizeof(ectx.params.abac.action));
	}

	err = perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, allowed, NULL);
	eval_context_destroy(&ectx);
	return err;
}

sso_error_t perm_engine_evaluate(permission_engine_t* engine, eval_context_t* ctx, bool* result,
								 char** decision_trace) {
	otlp_span_t span;
	otlp_span_start_tls(&span, "perm.evaluate");
	sso_error_t err = perm_engine_evaluate_internal(engine, ctx, result, decision_trace);
	otlp_span_end_tls(&span, err != SSO_OK);
	return err;
}
