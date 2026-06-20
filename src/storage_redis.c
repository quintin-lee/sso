/*
 * storage_redis.c — Redis storage backend via hiredis.
 *
 * Implements the full storage_backend vtable using Redis key-value structures.
 *
 * Key schema:
 *   Entity hashes:      {entity}:id:{id}               → Hash
 *   Name indexes:       {entity}:name:{name}            → String (value = id)
 *   Phone index:        user:phone:{phone}              → String (value = id)
 *   Auto-increment:     {entity}:next_id                → String
 *   Membership sets:    {entity}:{id}:{relation}        → Set
 *   Counter-sets:       {relation}:{id}:{entity}        → Set
 *   Parent pointers:    {entity}:{id}:parent            → String
 *   Policy targets:     policy:{id}:targets:{type}      → Set
 *   Target policies:    target:{type}:{id}:policies     → Set
 *   SMS codes:          sms:{phone}                     → String + EXPIRE
 *   OAuth codes:        oauth:code:{code}               → Hash + EXPIRE
 *   OAuth clients:      oauth:client:{client_id}        → Hash
 *   OAuth client list:  oauth:clients:list              → List
 *   Refresh tokens:     refresh_token:{hash}            → Hash
 */

#include "sso.h"
#include "storage.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <hiredis/hiredis.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

/* ========================================================================
 * Redis Bloom Filter for Zero-Hop JTI Revocation Checks
 * ======================================================================== */
#define BLOOM_SIZE (1024 * 1024) /* 1MB bitset */
static uint8_t g_jti_bloom[BLOOM_SIZE];
static pthread_mutex_t g_bloom_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t djb2_hash(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash;
}

static uint32_t fnv1a_hash(const char *str) {
    uint32_t hash = 2166136261u;
    int c;
    while ((c = *str++)) {
        hash ^= c;
        hash *= 16777619;
    }
    return hash;
}

static void bloom_add(const char *jti) {
    uint32_t h1 = djb2_hash(jti) % (BLOOM_SIZE * 8);
    uint32_t h2 = fnv1a_hash(jti) % (BLOOM_SIZE * 8);
    pthread_mutex_lock(&g_bloom_lock);
    g_jti_bloom[h1 / 8] |= (1 << (h1 % 8));
    g_jti_bloom[h2 / 8] |= (1 << (h2 % 8));
    pthread_mutex_unlock(&g_bloom_lock);
}

static bool bloom_might_contain(const char *jti) {
    uint32_t h1 = djb2_hash(jti) % (BLOOM_SIZE * 8);
    uint32_t h2 = fnv1a_hash(jti) % (BLOOM_SIZE * 8);
    pthread_mutex_lock(&g_bloom_lock);
    bool b1 = g_jti_bloom[h1 / 8] & (1 << (h1 % 8));
    bool b2 = g_jti_bloom[h2 / 8] & (1 << (h2 % 8));
    pthread_mutex_unlock(&g_bloom_lock);
    return b1 && b2;
}

/* ========================================================================
 * Backend private data
 * ======================================================================== */
typedef struct {
    redisContext *ctx;
    redisContext *sub_ctx;
    pthread_t sub_thread;
    int sub_running;
} redis_priv_t;

/* ========================================================================
 * Helper: prefix format buffers / max key lengths
 * ======================================================================== */
#define KEYBUF 512
#define CMDKEYBUF 1024
#define VALBUF 64

/* Build a key into buf (static inline). */
static void key_id(char *buf, size_t sz, const char *prefix, sso_id_t id) {
    snprintf(buf, sz, "%s:id:%lld", prefix, (long long)id);
}
static void key_name(char *buf, size_t sz, const char *prefix, const char *name) {
    snprintf(buf, sz, "%s:name:%s", prefix, name);
}
static void key_phone(char *buf, size_t sz, const char *phone) {
    snprintf(buf, sz, "user:phone:%s", phone);
}
static void key_next_id(char *buf, size_t sz, const char *prefix) {
    snprintf(buf, sz, "%s:next_id", prefix);
}
static void key_policy_target(char *buf, size_t sz, sso_id_t pid, int ttype) {
    snprintf(buf, sz, "policy:%lld:targets:%d", (long long)pid, ttype);
}
static void key_target_policies(char *buf, size_t sz, int ttype, sso_id_t tid) {
    snprintf(buf, sz, "target:%d:%lld:policies", ttype, (long long)tid);
}

/* ========================================================================
 * Helper: Redis command execution with error checking
 * ======================================================================== */

/* Execute a Redis command and return the reply. Returns NULL on connection error. */
static redisReply *redis_cmd(redisContext *ctx, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    redisReply *r = (redisReply *)redisvCommand(ctx, fmt, ap);
    va_end(ap);
    if (!r) {
        LOG_ERROR("[storage_redis] connection lost: %s", ctx->errstr);
    }
    return r;
}

/* Helper: execute a formatted string command */
static redisReply *redis_cmd_str(redisContext *ctx, const char *cmd) {
    redisReply *r = (redisReply *)redisCommand(ctx, cmd);
    if (!r) {
        LOG_ERROR("[storage_redis] connection lost: %s", ctx->errstr);
    }
    return r;
}

/* Helper: free reply and return SSO_OK / SSO_ERR_STORAGE */
static sso_error_t redis_ok(redisContext *ctx, redisReply *r) {
    (void)ctx;
    if (!r) return SSO_ERR_STORAGE;
    int ok = (r->type != REDIS_REPLY_ERROR);
    freeReplyObject(r);
    return ok ? SSO_OK : SSO_ERR_STORAGE;
}

/* Helper: check reply is INTEGER (for EXISTS, SADD, DEL, etc.) */
static int redis_int(redisReply *r, int fallback) {
    if (!r || r->type != REDIS_REPLY_INTEGER) {
        if (r) freeReplyObject(r);
        return fallback;
    }
    int v = (int)r->integer;
    freeReplyObject(r);
    return v;
}

/* Helper: check reply is STRING, copy to dest. Returns SSO_OK / SSO_ERR_NOT_FOUND */
static sso_error_t redis_str_copy(redisReply *r, char *dest, size_t dest_sz) {
    if (!r) return SSO_ERR_STORAGE;
    if (r->type == REDIS_REPLY_NIL) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }
    if (r->type != REDIS_REPLY_STRING) { freeReplyObject(r); return SSO_ERR_STORAGE; }
    sso_strlcpy(dest, r->str, dest_sz);
    dest[dest_sz - 1] = '\0';
    freeReplyObject(r);
    return SSO_OK;
}

/* Helper: check reply is INTEGER, return as sso_id_t */
static sso_error_t redis_reply_id(redisReply *r, sso_id_t *out) {
    if (!r) return SSO_ERR_STORAGE;
    if (r->type == REDIS_REPLY_NIL) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }
    if (r->type != REDIS_REPLY_STRING && r->type != REDIS_REPLY_INTEGER) {
        freeReplyObject(r); return SSO_ERR_STORAGE;
    }
    if (r->type == REDIS_REPLY_STRING)
        *out = (sso_id_t)atoll(r->str);
    else
        *out = (sso_id_t)r->integer;
    freeReplyObject(r);
    return SSO_OK;
}

/* ========================================================================
 * Generic Hash Read/Write helpers
 * ======================================================================== */

/* Set multiple hash fields on an entity key. Fields are key-value pairs
 * terminated by a NULL key sentinel. */
static sso_error_t redis_hash_set(redisContext *ctx, const char *key, ...) {
    va_list ap;
    va_start(ap, key);
    /* Build HMSET command: HMSET key field1 val1 field2 val2 ... */
    /* Use a dynamic command buffer for simplicity */
    char cmd[CMDKEYBUF];
    int pos = snprintf(cmd, sizeof(cmd), "HMSET %s", key);
    if (pos < 0 || (size_t)pos >= sizeof(cmd)) { va_end(ap); return SSO_ERR_STORAGE; }

    const char *field;
    while ((field = va_arg(ap, const char *)) != NULL) {
        const char *val = va_arg(ap, const char *);
        int n = snprintf(cmd + pos, sizeof(cmd) - pos, " %s %s", field, val);
        if (n < 0 || (size_t)(pos + n) >= sizeof(cmd)) { va_end(ap); return SSO_ERR_STORAGE; }
        pos += n;
    }
    va_end(ap);
    redisReply *r = redis_cmd_str(ctx, cmd);
    return redis_ok(ctx, r);
}


/* ========================================================================
 * Entity generation helpers
 * ======================================================================== */

static sso_error_t redis_next_id(redisContext *ctx, const char *prefix, sso_id_t *out) {
    char key[KEYBUF];
    key_next_id(key, sizeof(key), prefix);
    redisReply *r = redis_cmd(ctx, "INCR %s", key);
    if (!r) return SSO_ERR_STORAGE;
    *out = (sso_id_t)r->integer;
    freeReplyObject(r);
    return SSO_OK;
}

/* Push ID to the entity's ordered list for pagination */
static sso_error_t redis_list_push(redisContext *ctx, const char *list_key, sso_id_t id) {
    char val[VALBUF];
    snprintf(val, sizeof(val), "%lld", (long long)id);
    redisReply *r = redis_cmd(ctx, "RPUSH %s %s", list_key, val);
    return redis_ok(ctx, r);
}

static sso_error_t redis_list_rem(redisContext *ctx, const char *list_key, sso_id_t id) {
    char val[VALBUF];
    snprintf(val, sizeof(val), "%lld", (long long)id);
    redisReply *r = redis_cmd(ctx, "LREM %s 0 %s", list_key, val);
    return redis_ok(ctx, r);
}

/* Check if a name-based key already exists (for unique constraint) */
static sso_error_t redis_check_unique(redisContext *ctx, const char *key) {
    redisReply *r = redis_cmd(ctx, "EXISTS %s", key);
    int exists = redis_int(r, 0);
    return exists ? SSO_ERR_ALREADY_EXISTS : SSO_OK;
}

/* Set a name/phone index: key -> string value of id */
static sso_error_t redis_set_index(redisContext *ctx, const char *key, sso_id_t id) {
    char val[VALBUF];
    snprintf(val, sizeof(val), "%lld", (long long)id);
    redisReply *r = redis_cmd(ctx, "SET %s %s", key, val);
    return redis_ok(ctx, r);
}

/* Delete an index key */
static sso_error_t redis_del(redisContext *ctx, const char *key) {
    redisReply *r = redis_cmd(ctx, "DEL %s", key);
    return redis_ok(ctx, r);
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

static void *redis_sub_thread(void *arg) {
    redis_priv_t *priv = arg;
    if (!priv || !priv->sub_ctx) return NULL;

    redisReply *r = redisCommand(priv->sub_ctx, "SUBSCRIBE sso:revocations");
    if (r) freeReplyObject(r);

    while (priv->sub_running) {
        void *reply = NULL;
        if (redisGetReply(priv->sub_ctx, &reply) != REDIS_OK) {
            break; /* Connection closed or error */
        }
        redisReply *rr = (redisReply *)reply;
        if (rr && rr->type == REDIS_REPLY_ARRAY && rr->elements == 3) {
            if (rr->element[0]->type == REDIS_REPLY_STRING && strcmp(rr->element[0]->str, "message") == 0) {
                if (rr->element[2]->type == REDIS_REPLY_STRING) {
                    bloom_add(rr->element[2]->str);
                }
            }
        }
        if (rr) freeReplyObject(rr);
    }
    return NULL;
}

static sso_error_t redis_open(storage_backend_t *self, const char *dsn) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv) return SSO_ERR_INVALID_PARAM;

    /* Parse DSN */
    char host[256] = "127.0.0.1";
    int port = 6379;
    int db = 0;
    int is_sentinel = 0;
    char master_name[64] = "mymaster";

    if (dsn && dsn[0]) {
        if (strncmp(dsn, "redis-sentinel://", 17) == 0) {
            is_sentinel = 1;
            const char *p = dsn + 17;
            const char *at = strchr(p, '@');
            if (at) p = at + 1;
            char buf[256];
            snprintf(buf, sizeof(buf), "%s", p);
            
            char *q = strchr(buf, '?');
            if (q) {
                *q = '\0';
                char *m = strstr(q + 1, "master=");
                if (m) {
                    snprintf(master_name, sizeof(master_name), "%s", m + 7);
                    char *amp = strchr(master_name, '&');
                    if (amp) *amp = '\0';
                }
            }
            
            char *slash = strchr(buf, '/');
            if (slash) {
                *slash = '\0';
                db = atoi(slash + 1);
            }
            char *colon = strchr(buf, ':');
            if (colon) {
                *colon = '\0';
                snprintf(host, sizeof(host), "%s", buf);
                port = atoi(colon + 1);
            } else {
                snprintf(host, sizeof(host), "%s", buf);
            }
        } else if (strncmp(dsn, "redis://", 8) == 0) {
            const char *p = dsn + 8;
            const char *at = strchr(p, '@');
            if (at) p = at + 1;
            char buf[256];
            snprintf(buf, sizeof(buf), "%s", p);
            char *slash = strchr(buf, '/');
            if (slash) {
                *slash = '\0';
                db = atoi(slash + 1);
            }
            char *colon = strchr(buf, ':');
            if (colon) {
                *colon = '\0';
                snprintf(host, sizeof(host), "%s", buf);
                port = atoi(colon + 1);
            } else {
                snprintf(host, sizeof(host), "%s", buf);
            }
        } else {
            /* host:port format */
            char buf[256];
            snprintf(buf, sizeof(buf), "%s", dsn);
            char *colon = strchr(buf, ':');
            if (colon) {
                *colon = '\0';
                snprintf(host, sizeof(host), "%s", buf);
                port = atoi(colon + 1);
            } else {
                snprintf(host, sizeof(host), "%s", dsn);
            }
        }
    }

    /* Sentinel Resolution */
    if (is_sentinel) {
        redisContext *s_ctx = redisConnect(host, port);
        if (!s_ctx || s_ctx->err) {
            LOG_ERROR("[storage_redis] Failed to connect to Sentinel at %s:%d", host, port);
            if (s_ctx) redisFree(s_ctx);
            return SSO_ERR_STORAGE;
        }
        
        redisReply *r = redisCommand(s_ctx, "SENTINEL get-master-addr-by-name %s", master_name);
        if (r && r->type == REDIS_REPLY_ARRAY && r->elements == 2) {
            snprintf(host, sizeof(host), "%s", r->element[0]->str);
            port = atoi(r->element[1]->str);
            freeReplyObject(r);
        } else {
            LOG_ERROR("[storage_redis] Sentinel failed to resolve master '%s'", master_name);
            if (r) freeReplyObject(r);
            redisFree(s_ctx);
            return SSO_ERR_STORAGE;
        }
        redisFree(s_ctx);
        LOG_INFO("[storage_redis] Resolved master '%s' to %s:%d via Sentinel", master_name, host, port);
    }

    priv->ctx = redisConnect(host, port);
    if (!priv->ctx) {
        LOG_ERROR("[storage_redis] Failed to create redis context");
        return SSO_ERR_STORAGE;
    }
    if (priv->ctx->err) {
        LOG_ERROR("[storage_redis] Connection error: %s", priv->ctx->errstr);
        redisFree(priv->ctx);
        priv->ctx = NULL;
        return SSO_ERR_STORAGE;
    }

    if (db > 0) {
        redisReply *r = redis_cmd(priv->ctx, "SELECT %d", db);
        if (!r || r->type == REDIS_REPLY_ERROR) {
            if (r) freeReplyObject(r);
            LOG_ERROR("[storage_redis] SELECT %d failed", db);
            redisFree(priv->ctx);
            priv->ctx = NULL;
            return SSO_ERR_STORAGE;
        }
        freeReplyObject(r);
    }

    /* Start Pub/Sub background thread for JTI broadcasting */
    priv->sub_ctx = redisConnect(host, port);
    if (priv->sub_ctx && !priv->sub_ctx->err) {
        if (db > 0) {
            redisReply *sr = redisCommand(priv->sub_ctx, "SELECT %d", db);
            if (sr) freeReplyObject(sr);
        }
        priv->sub_running = 1;
        pthread_create(&priv->sub_thread, NULL, redis_sub_thread, priv);
        LOG_INFO("[storage_redis] Real-time Pub/Sub revocation broadcast enabled");
    } else {
        if (priv->sub_ctx) {
            redisFree(priv->sub_ctx);
            priv->sub_ctx = NULL;
        }
        LOG_ERROR("[storage_redis] Warning: Failed to connect Pub/Sub. Broadcasting disabled.");
    }

    return SSO_OK;
}

static void redis_close(storage_backend_t *self) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (priv) {
        if (priv->sub_running) {
            priv->sub_running = 0;
            pthread_cancel(priv->sub_thread);
            pthread_join(priv->sub_thread, NULL);
            if (priv->sub_ctx) {
                redisFree(priv->sub_ctx);
                priv->sub_ctx = NULL;
            }
        }
        if (priv->ctx) {
            redisFree(priv->ctx);
            priv->ctx = NULL;
        }
        free(priv);
        self->handle = NULL;
    }
}

/* Redis has no multi-statement transactions at the vtable level;
 * we rely on Redis being single-threaded per connection for atomicity. */
static sso_error_t redis_begin(storage_backend_t *self)   {
    (void)self;
    return SSO_OK;
}

static sso_error_t redis_commit(storage_backend_t *self)  {
    (void)self;
    return SSO_OK;
}

static sso_error_t redis_rollback(storage_backend_t *self) {
    (void)self;
    return SSO_OK;
}

static void redis_thread_init(storage_backend_t *self) {
    (void)self;
}

static void redis_thread_cleanup(storage_backend_t *self) {
    (void)self;
}

/* ========================================================================
 * User CRUD
 * ======================================================================== */

static sso_error_t redis_user_create(storage_backend_t *self, user_t *user) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    /* Check unique constraints */
    if (user->username[0]) {
        char nk[KEYBUF]; key_name(nk, sizeof(nk), "user", user->username);
        sso_error_t e = redis_check_unique(priv->ctx, nk);
        if (e != SSO_OK) return e;
    }
    if (user->phone[0]) {
        char pk[KEYBUF]; key_phone(pk, sizeof(pk), user->phone);
        sso_error_t e = redis_check_unique(priv->ctx, pk);
        if (e != SSO_OK) return e;
    }

    sso_error_t err = redis_next_id(priv->ctx, "user", &user->id);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "user", user->id);

    char status_str[16], created_str[32], updated_str[32], mfa_str[8];
    snprintf(status_str, sizeof(status_str), "%d", (int)user->status);
    snprintf(created_str, sizeof(created_str), "%lld", (long long)user->created_at);
    snprintf(updated_str, sizeof(updated_str), "%lld", (long long)user->updated_at);
    snprintf(mfa_str, sizeof(mfa_str), "%d", user->mfa_enabled);

    err = redis_hash_set(priv->ctx, idk,
        "id", status_str,
        "username", user->username[0] ? user->username : "",
        "phone", user->phone[0] ? user->phone : "",
        "password_hash", user->password_hash,
        "email", user->email,
        "display_name", user->display_name,
        "status", status_str,
        "created_at", created_str,
        "updated_at", updated_str,
        "attributes", user->attributes,
        "mfa_enabled", mfa_str,
        "mfa_secret", user->mfa_secret,
        (void *)NULL);
    if (err != SSO_OK) return err;

    /* Indexes */
    if (user->username[0]) {
        char nk[KEYBUF]; key_name(nk, sizeof(nk), "user", user->username);
        redis_set_index(priv->ctx, nk, user->id);
    }
    if (user->phone[0]) {
        char pk[KEYBUF]; key_phone(pk, sizeof(pk), user->phone);
        redis_set_index(priv->ctx, pk, user->id);
    }

    /* List for pagination */
    redis_list_push(priv->ctx, "user:list", user->id);
    return SSO_OK;
}

static sso_error_t redis_user_get_by_id(storage_backend_t *self, sso_id_t id, user_t *user) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    memset(user, 0, sizeof(*user));

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "user", id);
    redisReply *r = redis_cmd(priv->ctx, "HGETALL %s", idk);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type == REDIS_REPLY_NIL) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); return SSO_ERR_STORAGE; }

    user->id = id;
    for (size_t i = 0; i + 1 < r->elements; i += 2) {
        const char *fn = r->element[i]->str;
        const char *fv = r->element[i + 1]->str;
        if (!fn || !fv) continue;
        if (strcmp(fn, "username") == 0)
            sso_strlcpy(user->username, fv, sizeof(user->username));
        else if (strcmp(fn, "phone") == 0)
            sso_strlcpy(user->phone, fv, sizeof(user->phone));
        else if (strcmp(fn, "password_hash") == 0)
            sso_strlcpy(user->password_hash, fv, sizeof(user->password_hash));
        else if (strcmp(fn, "email") == 0)
            sso_strlcpy(user->email, fv, sizeof(user->email));
        else if (strcmp(fn, "display_name") == 0)
            sso_strlcpy(user->display_name, fv, sizeof(user->display_name));
        else if (strcmp(fn, "status") == 0)
            user->status = (user_status_t)atoi(fv);
        else if (strcmp(fn, "created_at") == 0)
            user->created_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "updated_at") == 0)
            user->updated_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "attributes") == 0)
            sso_strlcpy(user->attributes, fv, sizeof(user->attributes));
        else if (strcmp(fn, "mfa_enabled") == 0)
            user->mfa_enabled = atoi(fv);
        else if (strcmp(fn, "mfa_secret") == 0)
            sso_strlcpy(user->mfa_secret, fv, sizeof(user->mfa_secret));
    }
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_user_get_by_name(storage_backend_t *self, const char *name, user_t *user) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    char nk[KEYBUF]; key_name(nk, sizeof(nk), "user", name);
    sso_id_t id = 0;
    sso_error_t err = redis_reply_id(redis_cmd(priv->ctx, "GET %s", nk), &id);
    if (err != SSO_OK) return err;
    return redis_user_get_by_id(self, id, user);
}

static sso_error_t redis_user_get_by_phone(storage_backend_t *self, const char *phone, user_t *user) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    char pk[KEYBUF]; key_phone(pk, sizeof(pk), phone);
    sso_id_t id = 0;
    sso_error_t err = redis_reply_id(redis_cmd(priv->ctx, "GET %s", pk), &id);
    if (err != SSO_OK) return err;
    return redis_user_get_by_id(self, id, user);
}

static sso_error_t redis_user_update(storage_backend_t *self, const user_t *user) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "user", user->id);

    char status_str[16], updated_str[32], mfa_str[8];
    snprintf(status_str, sizeof(status_str), "%d", (int)user->status);
    snprintf(updated_str, sizeof(updated_str), "%lld", (long long)user->updated_at);
    snprintf(mfa_str, sizeof(mfa_str), "%d", user->mfa_enabled);

    return redis_hash_set(priv->ctx, idk,
        "phone", user->phone,
        "password_hash", user->password_hash,
        "email", user->email,
        "display_name", user->display_name,
        "status", status_str,
        "updated_at", updated_str,
        "attributes", user->attributes,
        "mfa_enabled", mfa_str,
        "mfa_secret", user->mfa_secret,
        (void *)NULL);
}

static sso_error_t redis_user_delete(storage_backend_t *self, sso_id_t id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    /* Fetch user to get indexes for cleanup */
    user_t u;
    sso_error_t err = redis_user_get_by_id(self, id, &u);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "user", id);

    /* Delete indexes */
    if (u.username[0]) {
        char nk[KEYBUF]; key_name(nk, sizeof(nk), "user", u.username);
        redis_del(priv->ctx, nk);
    }
    if (u.phone[0]) {
        char pk[KEYBUF]; key_phone(pk, sizeof(pk), u.phone);
        redis_del(priv->ctx, pk);
    }

    /* Remove from membership sets */
    char rk[KEYBUF]; snprintf(rk, sizeof(rk), "user:%lld:roles", (long long)id);
    redisReply *roles = redis_cmd(priv->ctx, "SMEMBERS %s", rk);
    if (roles && roles->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < roles->elements; i++) {
            if (roles->element[i]->str) {
                char urk[KEYBUF];
                snprintf(urk, sizeof(urk), "role:%s:users", roles->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", urk, (long long)id);
            }
        }
    }
    if (roles) freeReplyObject(roles);
    redis_del(priv->ctx, rk);

    char gk[KEYBUF]; snprintf(gk, sizeof(gk), "user:%lld:groups", (long long)id);
    redisReply *grps = redis_cmd(priv->ctx, "SMEMBERS %s", gk);
    if (grps && grps->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < grps->elements; i++) {
            if (grps->element[i]->str) {
                char guk[KEYBUF];
                snprintf(guk, sizeof(guk), "group:%s:users", grps->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", guk, (long long)id);
            }
        }
    }
    if (grps) freeReplyObject(grps);
    redis_del(priv->ctx, gk);

    /* Remove policy assignments for this user target (type=0 = user) */
    char tpk[KEYBUF]; key_target_policies(tpk, sizeof(tpk), 0, id);
    redisReply *policies = redis_cmd(priv->ctx, "SMEMBERS %s", tpk);
    if (policies && policies->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < policies->elements; i++) {
            if (policies->element[i]->str) {
                char ptk[KEYBUF];
                snprintf(ptk, sizeof(ptk), "policy:%s:targets:0", policies->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", ptk, (long long)id);
            }
        }
    }
    if (policies) freeReplyObject(policies);
    redis_del(priv->ctx, tpk);

    /* Delete the hash and list entry */
    redis_del(priv->ctx, idk);
    redis_list_rem(priv->ctx, "user:list", id);

    return SSO_OK;
}

static sso_error_t redis_user_list(storage_backend_t *self, const char *q, int status,
                                    int offset, int limit, sso_id_t *ids,
                                    size_t *count, size_t *total_count) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    /* Get all user IDs from the list */
    redisReply *r = redis_cmd(priv->ctx, "LRANGE user:list 0 -1");
    if (!r || r->type != REDIS_REPLY_ARRAY) {
        if (r) freeReplyObject(r);
        *count = 0; *total_count = 0;
        return SSO_OK;
    }

    size_t total = r->elements;
    size_t match = 0;
    size_t out = 0;
    bool has_q = (q && q[0] != '\0');

    for (size_t i = 0; i < total && out < (size_t)limit; i++) {
        if (!r->element[i]->str) continue;
        sso_id_t uid = (sso_id_t)atoll(r->element[i]->str);

        /* For filtering, we need to fetch user data */
        if (has_q || status != -1) {
            user_t u;
            if (redis_user_get_by_id(self, uid, &u) != SSO_OK) continue;
            if (status != -1 && (int)u.status != status) continue;
            if (has_q && !strstr(u.username, q) && !strstr(u.display_name, q)
                && !strstr(u.email, q) && !strstr(u.phone, q)) continue;
            match++;
            if (match > (size_t)offset) ids[out++] = uid;
        } else {
            /* No filtering — fast path using list indices */
            match++;
            if (match > (size_t)offset) ids[out++] = uid;
        }
    }

    *total_count = has_q || status != -1 ? match : total;
    *count = out;
    freeReplyObject(r);
    return SSO_OK;
}

/* ========================================================================
 * SMS code storage
 * ======================================================================== */

static sso_error_t redis_save_sms_code(storage_backend_t *self, const char *phone,
                                        const char *code, sso_timestamp_t expires_at) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char key[KEYBUF]; snprintf(key, sizeof(key), "sms:%s", phone);
    unsigned long ttl = (expires_at > sso_timestamp_now())
        ? (unsigned long)(expires_at - sso_timestamp_now()) / 1000UL : 300UL;

    redisReply *r = redis_cmd(priv->ctx, "SET %s %s EX %lu", key, code, ttl);
    return redis_ok(priv->ctx, r);
}

static sso_error_t redis_get_sms_code(storage_backend_t *self, const char *phone, char *code_out) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char key[KEYBUF]; snprintf(key, sizeof(key), "sms:%s", phone);
    return redis_str_copy(redis_cmd(priv->ctx, "GET %s", key), code_out, 16);
}

static sso_error_t redis_delete_sms_code(storage_backend_t *self, const char *phone) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char key[KEYBUF]; snprintf(key, sizeof(key), "sms:%s", phone);
    redisReply *r = redis_cmd(priv->ctx, "DEL %s", key);
    return redis_ok(priv->ctx, r);
}

/* ========================================================================
 * Generic Entity CRUD helpers (Role, Group, Policy)
 * ======================================================================== */


/* ========================================================================
 * Role CRUD
 * ======================================================================== */

/* Helper to deserialize a role hash into role_t */
static sso_error_t redis_role_from_hash(redisReply *r, role_t *role) {
    memset(role, 0, sizeof(*role));
    if (!r || r->type != REDIS_REPLY_ARRAY) return SSO_ERR_STORAGE;
    if (r->elements == 0) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }

    for (size_t i = 0; i + 1 < r->elements; i += 2) {
        const char *fn = r->element[i]->str;
        const char *fv = r->element[i + 1]->str;
        if (!fn || !fv) continue;
        if (strcmp(fn, "id") == 0)
            role->id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "name") == 0)
            sso_strlcpy(role->name, fv, sizeof(role->name));
        else if (strcmp(fn, "description") == 0)
            sso_strlcpy(role->description, fv, sizeof(role->description));
        else if (strcmp(fn, "parent_role_id") == 0)
            role->parent_role_id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "status") == 0)
            role->status = (role_status_t)atoi(fv);
        else if (strcmp(fn, "created_at") == 0)
            role->created_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "updated_at") == 0)
            role->updated_at = (sso_timestamp_t)atoll(fv);
    }
    return SSO_OK;
}

static sso_error_t redis_role_get_by_id(storage_backend_t *self, sso_id_t id, role_t *role) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "role", id);
    redisReply *r = redis_cmd(priv->ctx, "HGETALL %s", idk);
    if (!r) return SSO_ERR_STORAGE;
    sso_error_t err = redis_role_from_hash(r, role);
    if (err == SSO_OK) role->id = id;
    return err;
}

#define REDIS_GET_BY_NAME(name_type, prefix) \
static sso_error_t redis_##name_type##_get_by_name(storage_backend_t *self, const char *name, name_type##_t *out) { \
    redis_priv_t *priv = (redis_priv_t *)self->handle; \
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE; \
    char nk[KEYBUF]; key_name(nk, sizeof(nk), prefix, name); \
    sso_id_t id = 0; \
    sso_error_t err = redis_reply_id(redis_cmd(priv->ctx, "GET %s", nk), &id); \
    if (err != SSO_OK) return err; \
    return redis_##name_type##_get_by_id(self, id, out); \
}

REDIS_GET_BY_NAME(role, "role")
/* Forward declarations for group/policy — defined below their CRUD sections */
static sso_error_t redis_group_get_by_id(storage_backend_t *self, sso_id_t id, group_t *group);
static sso_error_t redis_policy_get_by_id(storage_backend_t *self, sso_id_t id, policy_t *policy);
REDIS_GET_BY_NAME(group, "group")
REDIS_GET_BY_NAME(policy, "policy")

static sso_error_t redis_role_create(storage_backend_t *self, role_t *role) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char nk[KEYBUF]; key_name(nk, sizeof(nk), "role", role->name);
    sso_error_t err = redis_check_unique(priv->ctx, nk);
    if (err != SSO_OK) return err;

    err = redis_next_id(priv->ctx, "role", &role->id);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "role", role->id);
    char sid[VALBUF], sparent[VALBUF], sstatus[16], sc[32], su[32];
    snprintf(sid, sizeof(sid), "%lld", (long long)role->id);
    snprintf(sparent, sizeof(sparent), "%lld", (long long)role->parent_role_id);
    snprintf(sstatus, sizeof(sstatus), "%d", (int)role->status);
    snprintf(sc, sizeof(sc), "%lld", (long long)role->created_at);
    snprintf(su, sizeof(su), "%lld", (long long)role->updated_at);

    err = redis_hash_set(priv->ctx, idk,
        "id", sid, "name", role->name, "description", role->description,
        "parent_role_id", sparent, "status", sstatus,
        "created_at", sc, "updated_at", su, (void *)NULL);
    if (err != SSO_OK) return err;

    redis_set_index(priv->ctx, nk, role->id);
    redis_list_push(priv->ctx, "role:list", role->id);
    return SSO_OK;
}

static sso_error_t redis_role_update(storage_backend_t *self, const role_t *role) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "role", role->id);
    char sparent[VALBUF], sstatus[16], su[32];
    snprintf(sparent, sizeof(sparent), "%lld", (long long)role->parent_role_id);
    snprintf(sstatus, sizeof(sstatus), "%d", (int)role->status);
    snprintf(su, sizeof(su), "%lld", (long long)role->updated_at);

    return redis_hash_set(priv->ctx, idk,
        "name", role->name, "description", role->description,
        "parent_role_id", sparent, "status", sstatus,
        "updated_at", su, (void *)NULL);
}

static sso_error_t redis_role_delete(storage_backend_t *self, sso_id_t id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    role_t r;
    sso_error_t err = redis_role_get_by_id(self, id, &r);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "role", id);
    char nk[KEYBUF]; key_name(nk, sizeof(nk), "role", r.name);
    redis_del(priv->ctx, idk);
    redis_del(priv->ctx, nk);
    redis_del(priv->ctx, "parent");

    /* Cascade: remove from user_roles, role_groups, policy targets */
    char ruk[KEYBUF]; snprintf(ruk, sizeof(ruk), "role:%lld:users", (long long)id);
    redisReply *users = redis_cmd(priv->ctx, "SMEMBERS %s", ruk);
    if (users && users->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < users->elements; i++) {
            if (users->element[i]->str) {
                char urk[KEYBUF];
                snprintf(urk, sizeof(urk), "user:%s:roles", users->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", urk, (long long)id);
            }
        }
    }
    if (users) freeReplyObject(users);
    redis_del(priv->ctx, ruk);

    char rgk[KEYBUF]; snprintf(rgk, sizeof(rgk), "role:%lld:groups", (long long)id);
    redisReply *grps = redis_cmd(priv->ctx, "SMEMBERS %s", rgk);
    if (grps && grps->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < grps->elements; i++) {
            if (grps->element[i]->str) {
                char grk[KEYBUF];
                snprintf(grk, sizeof(grk), "group:%s:roles", grps->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", grk, (long long)id);
            }
        }
    }
    if (grps) freeReplyObject(grps);
    redis_del(priv->ctx, rgk);

    /* Policy assignments for this role (target_type=1) */
    char tpk[KEYBUF]; key_target_policies(tpk, sizeof(tpk), 1, id);
    redisReply *pols = redis_cmd(priv->ctx, "SMEMBERS %s", tpk);
    if (pols && pols->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < pols->elements; i++) {
            if (pols->element[i]->str) {
                char ptk[KEYBUF];
                snprintf(ptk, sizeof(ptk), "policy:%s:targets:1", pols->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", ptk, (long long)id);
            }
        }
    }
    if (pols) freeReplyObject(pols);
    redis_del(priv->ctx, tpk);

    redis_list_rem(priv->ctx, "role:list", id);
    return SSO_OK;
}

/* Generic list helper for simple entity (role/group/policy) without search filtering */
#define REDIS_SIMPLE_LIST(name_type, prefix, list_key) \
static sso_error_t redis_##name_type##_list(storage_backend_t *self, const char *q, int status, \
                                             int offset, int limit, sso_id_t *ids, \
                                             size_t *count, size_t *total_count) { \
    redis_priv_t *priv = (redis_priv_t *)self->handle; \
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE; \
    redisReply *r = redis_cmd(priv->ctx, "LRANGE %s 0 -1", list_key); \
    if (!r || r->type != REDIS_REPLY_ARRAY) { \
        if (r) freeReplyObject(r); \
        *count = 0; *total_count = 0; return SSO_OK; \
    } \
    size_t total = r->elements; \
    size_t match = 0, out = 0; \
    bool has_q = (q && q[0] != '\0'); \
    for (size_t i = 0; i < total && out < (size_t)limit; i++) { \
        if (!r->element[i]->str) continue; \
        sso_id_t eid = (sso_id_t)atoll(r->element[i]->str); \
        if (has_q || status != -1) { \
            name_type##_t ent; \
            if (redis_##name_type##_get_by_id(self, eid, &ent) != SSO_OK) continue; \
            if (status != -1 && (int)ent.status != status) continue; \
            if (has_q && !strstr(ent.name, q)) continue; \
            match++; \
            if (match > (size_t)offset) ids[out++] = eid; \
        } else { \
            match++; \
            if (match > (size_t)offset) ids[out++] = eid; \
        } \
    } \
    *total_count = (has_q || status != -1) ? match : total; \
    *count = out; \
    freeReplyObject(r); \
    return SSO_OK; \
}

REDIS_SIMPLE_LIST(role, "role", "role:list")
REDIS_SIMPLE_LIST(group, "group", "group:list")
REDIS_SIMPLE_LIST(policy, "policy", "policy:list")

/* ========================================================================
 * Group CRUD
 * ======================================================================== */

/* Helper to deserialize a group hash into group_t */
static sso_error_t redis_group_from_hash(redisReply *r, group_t *group) {
    memset(group, 0, sizeof(*group));
    if (!r || r->type != REDIS_REPLY_ARRAY) return SSO_ERR_STORAGE;
    if (r->elements == 0) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }

    for (size_t i = 0; i + 1 < r->elements; i += 2) {
        const char *fn = r->element[i]->str;
        const char *fv = r->element[i + 1]->str;
        if (!fn || !fv) continue;
        if (strcmp(fn, "id") == 0)
            group->id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "name") == 0)
            sso_strlcpy(group->name, fv, sizeof(group->name));
        else if (strcmp(fn, "description") == 0)
            sso_strlcpy(group->description, fv, sizeof(group->description));
        else if (strcmp(fn, "parent_group_id") == 0)
            group->parent_group_id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "status") == 0)
            group->status = (group_status_t)atoi(fv);
        else if (strcmp(fn, "created_at") == 0)
            group->created_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "updated_at") == 0)
            group->updated_at = (sso_timestamp_t)atoll(fv);
    }
    return SSO_OK;
}

static sso_error_t redis_group_get_by_id(storage_backend_t *self, sso_id_t id, group_t *group) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "group", id);
    redisReply *r = redis_cmd(priv->ctx, "HGETALL %s", idk);
    if (!r) return SSO_ERR_STORAGE;
    sso_error_t err = redis_group_from_hash(r, group);
    if (err == SSO_OK) group->id = id;
    return err;
}

static sso_error_t redis_group_create(storage_backend_t *self, group_t *group) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char nk[KEYBUF]; key_name(nk, sizeof(nk), "group", group->name);
    sso_error_t err = redis_check_unique(priv->ctx, nk);
    if (err != SSO_OK) return err;

    err = redis_next_id(priv->ctx, "group", &group->id);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "group", group->id);
    char sid[VALBUF], sparent[VALBUF], sstatus[16], sc[32], su[32];
    snprintf(sid, sizeof(sid), "%lld", (long long)group->id);
    snprintf(sparent, sizeof(sparent), "%lld", (long long)group->parent_group_id);
    snprintf(sstatus, sizeof(sstatus), "%d", (int)group->status);
    snprintf(sc, sizeof(sc), "%lld", (long long)group->created_at);
    snprintf(su, sizeof(su), "%lld", (long long)group->updated_at);

    err = redis_hash_set(priv->ctx, idk,
        "id", sid, "name", group->name, "description", group->description,
        "parent_group_id", sparent, "status", sstatus,
        "created_at", sc, "updated_at", su, (void *)NULL);
    if (err != SSO_OK) return err;

    redis_set_index(priv->ctx, nk, group->id);
    redis_list_push(priv->ctx, "group:list", group->id);
    return SSO_OK;
}

static sso_error_t redis_group_update(storage_backend_t *self, const group_t *group) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "group", group->id);
    char sparent[VALBUF], sstatus[16], su[32];
    snprintf(sparent, sizeof(sparent), "%lld", (long long)group->parent_group_id);
    snprintf(sstatus, sizeof(sstatus), "%d", (int)group->status);
    snprintf(su, sizeof(su), "%lld", (long long)group->updated_at);

    return redis_hash_set(priv->ctx, idk,
        "name", group->name, "description", group->description,
        "parent_group_id", sparent, "status", sstatus,
        "updated_at", su, (void *)NULL);
}

static sso_error_t redis_group_delete(storage_backend_t *self, sso_id_t id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    group_t g;
    sso_error_t err = redis_group_get_by_id(self, id, &g);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "group", id);
    char nk[KEYBUF]; key_name(nk, sizeof(nk), "group", g.name);
    redis_del(priv->ctx, idk);
    redis_del(priv->ctx, nk);

    /* Cascade: remove from user_groups and role_groups */
    char guk[KEYBUF]; snprintf(guk, sizeof(guk), "group:%lld:users", (long long)id);
    redisReply *users = redis_cmd(priv->ctx, "SMEMBERS %s", guk);
    if (users && users->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < users->elements; i++) {
            if (users->element[i]->str) {
                char ugk[KEYBUF];
                snprintf(ugk, sizeof(ugk), "user:%s:groups", users->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", ugk, (long long)id);
            }
        }
    }
    if (users) freeReplyObject(users);
    redis_del(priv->ctx, guk);

    char grk[KEYBUF]; snprintf(grk, sizeof(grk), "group:%lld:roles", (long long)id);
    redisReply *roles = redis_cmd(priv->ctx, "SMEMBERS %s", grk);
    if (roles && roles->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < roles->elements; i++) {
            if (roles->element[i]->str) {
                char rgk[KEYBUF];
                snprintf(rgk, sizeof(rgk), "role:%s:groups", roles->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", rgk, (long long)id);
            }
        }
    }
    if (roles) freeReplyObject(roles);
    redis_del(priv->ctx, grk);

    /* Policy assignments for this group (target_type=2) */
    char tpk[KEYBUF]; key_target_policies(tpk, sizeof(tpk), 2, id);
    redisReply *pols = redis_cmd(priv->ctx, "SMEMBERS %s", tpk);
    if (pols && pols->type == REDIS_REPLY_ARRAY) {
        for (size_t i = 0; i < pols->elements; i++) {
            if (pols->element[i]->str) {
                char ptk[KEYBUF];
                snprintf(ptk, sizeof(ptk), "policy:%s:targets:2", pols->element[i]->str);
                redis_cmd(priv->ctx, "SREM %s %lld", ptk, (long long)id);
            }
        }
    }
    if (pols) freeReplyObject(pols);
    redis_del(priv->ctx, tpk);

    redis_list_rem(priv->ctx, "group:list", id);
    return SSO_OK;
}

/* ========================================================================
 * Policy CRUD
 * ======================================================================== */

/* Helper to deserialize a policy hash into policy_t */
static sso_error_t redis_policy_from_hash(redisReply *r, policy_t *policy) {
    memset(policy, 0, sizeof(*policy));
    if (!r || r->type != REDIS_REPLY_ARRAY) return SSO_ERR_STORAGE;
    if (r->elements == 0) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }

    for (size_t i = 0; i + 1 < r->elements; i += 2) {
        const char *fn = r->element[i]->str;
        const char *fv = r->element[i + 1]->str;
        if (!fn || !fv) continue;
        if (strcmp(fn, "id") == 0)
            policy->id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "name") == 0)
            sso_strlcpy(policy->name, fv, sizeof(policy->name));
        else if (strcmp(fn, "strategy_type") == 0)
            policy->strategy_type = (perm_strategy_type_t)atoi(fv);
        else if (strcmp(fn, "effect") == 0)
            policy->effect = (policy_effect_t)atoi(fv);
        else if (strcmp(fn, "priority") == 0)
            policy->priority = atoi(fv);
        else if (strcmp(fn, "rules") == 0)
            sso_strlcpy(policy->rules, fv, sizeof(policy->rules));
        else if (strcmp(fn, "status") == 0)
            policy->status = (policy_status_t)atoi(fv);
        else if (strcmp(fn, "created_at") == 0)
            policy->created_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "updated_at") == 0)
            policy->updated_at = (sso_timestamp_t)atoll(fv);
    }
    return SSO_OK;
}

static sso_error_t redis_policy_get_by_id(storage_backend_t *self, sso_id_t id, policy_t *policy) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "policy", id);
    redisReply *r = redis_cmd(priv->ctx, "HGETALL %s", idk);
    if (!r) return SSO_ERR_STORAGE;
    sso_error_t err = redis_policy_from_hash(r, policy);
    if (err == SSO_OK) policy->id = id;
    return err;
}

static sso_error_t redis_policy_create(storage_backend_t *self, policy_t *policy) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char nk[KEYBUF]; key_name(nk, sizeof(nk), "policy", policy->name);
    sso_error_t err = redis_check_unique(priv->ctx, nk);
    if (err != SSO_OK) return err;

    err = redis_next_id(priv->ctx, "policy", &policy->id);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "policy", policy->id);
    char sid[VALBUF], stype[16], seffect[16], sprio[16], sstatus[16], sc[32], su[32];
    snprintf(sid, sizeof(sid), "%lld", (long long)policy->id);
    snprintf(stype, sizeof(stype), "%d", (int)policy->strategy_type);
    snprintf(seffect, sizeof(seffect), "%d", (int)policy->effect);
    snprintf(sprio, sizeof(sprio), "%d", policy->priority);
    snprintf(sstatus, sizeof(sstatus), "%d", (int)policy->status);
    snprintf(sc, sizeof(sc), "%lld", (long long)policy->created_at);
    snprintf(su, sizeof(su), "%lld", (long long)policy->updated_at);

    err = redis_hash_set(priv->ctx, idk,
        "id", sid, "name", policy->name,
        "strategy_type", stype, "effect", seffect,
        "priority", sprio, "rules", policy->rules,
        "status", sstatus,
        "created_at", sc, "updated_at", su, (void *)NULL);
    if (err != SSO_OK) return err;

    redis_set_index(priv->ctx, nk, policy->id);
    redis_list_push(priv->ctx, "policy:list", policy->id);
    return SSO_OK;
}

static sso_error_t redis_policy_update(storage_backend_t *self, const policy_t *policy) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "policy", policy->id);
    char stype[16], seffect[16], sprio[16], sstatus[16], su[32];
    snprintf(stype, sizeof(stype), "%d", (int)policy->strategy_type);
    snprintf(seffect, sizeof(seffect), "%d", (int)policy->effect);
    snprintf(sprio, sizeof(sprio), "%d", policy->priority);
    snprintf(sstatus, sizeof(sstatus), "%d", (int)policy->status);
    snprintf(su, sizeof(su), "%lld", (long long)policy->updated_at);

    return redis_hash_set(priv->ctx, idk,
        "name", policy->name,
        "strategy_type", stype, "effect", seffect,
        "priority", sprio, "rules", policy->rules,
        "status", sstatus,
        "updated_at", su, (void *)NULL);
}

static sso_error_t redis_policy_delete(storage_backend_t *self, sso_id_t id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    policy_t p;
    sso_error_t err = redis_policy_get_by_id(self, id, &p);
    if (err != SSO_OK) return err;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "policy", id);
    char nk[KEYBUF]; key_name(nk, sizeof(nk), "policy", p.name);
    redis_del(priv->ctx, idk);
    redis_del(priv->ctx, nk);

    /* Remove from all target sets */
    for (int tt = 0; tt < 3; tt++) {
        char ptk[KEYBUF]; key_policy_target(ptk, sizeof(ptk), id, tt);
        redisReply *targets = redis_cmd(priv->ctx, "SMEMBERS %s", ptk);
        if (targets && targets->type == REDIS_REPLY_ARRAY) {
            for (size_t i = 0; i < targets->elements; i++) {
                if (targets->element[i]->str) {
                    char tpk[KEYBUF];
                    snprintf(tpk, sizeof(tpk), "target:%d:%s:policies", tt, targets->element[i]->str);
                    redis_cmd(priv->ctx, "SREM %s %lld", tpk, (long long)id);
                }
            }
        }
        if (targets) freeReplyObject(targets);
        redis_del(priv->ctx, ptk);
    }

    redis_list_rem(priv->ctx, "policy:list", id);
    return SSO_OK;
}

/* ========================================================================
 * Assignment helpers
 * ======================================================================== */

/* User-Role bidirectional sets */
static sso_error_t redis_assign_role_to_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    redisReply *r = redis_cmd(priv->ctx, "SADD user:%lld:roles %lld", (long long)user_id, (long long)role_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SADD role:%lld:users %lld", (long long)role_id, (long long)user_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_unassign_role_from_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    redisReply *r = redis_cmd(priv->ctx, "SREM user:%lld:roles %lld", (long long)user_id, (long long)role_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SREM role:%lld:users %lld", (long long)role_id, (long long)user_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_get_user_roles(storage_backend_t *self, sso_id_t user_id,
                                         sso_id_t *role_ids, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    redisReply *r = redis_cmd(priv->ctx, "SMEMBERS user:%lld:roles", (long long)user_id);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); *count = 0; return SSO_ERR_NOT_FOUND; }

    size_t n = 0;
    for (size_t i = 0; i < r->elements && n < max; i++) {
        if (r->element[i]->str)
            role_ids[n++] = (sso_id_t)atoll(r->element[i]->str);
    }
    *count = n;
    freeReplyObject(r);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

static sso_error_t redis_get_role_users(storage_backend_t *self, sso_id_t role_id,
                                         sso_id_t *user_ids, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    redisReply *r = redis_cmd(priv->ctx, "SMEMBERS role:%lld:users", (long long)role_id);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); *count = 0; return SSO_ERR_NOT_FOUND; }

    size_t n = 0;
    for (size_t i = 0; i < r->elements && n < max; i++) {
        if (r->element[i]->str)
            user_ids[n++] = (sso_id_t)atoll(r->element[i]->str);
    }
    *count = n;
    freeReplyObject(r);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* Role-Group bidirectional sets */
static sso_error_t redis_assign_role_to_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    redisReply *r = redis_cmd(priv->ctx, "SADD role:%lld:groups %lld", (long long)role_id, (long long)group_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SADD group:%lld:roles %lld", (long long)group_id, (long long)role_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_unassign_role_from_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    redisReply *r = redis_cmd(priv->ctx, "SREM role:%lld:groups %lld", (long long)role_id, (long long)group_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SREM group:%lld:roles %lld", (long long)group_id, (long long)role_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

/* User-Group bidirectional sets */
static sso_error_t redis_add_user_to_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    redisReply *r = redis_cmd(priv->ctx, "SADD group:%lld:users %lld", (long long)group_id, (long long)user_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SADD user:%lld:groups %lld", (long long)user_id, (long long)group_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_remove_user_from_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    redisReply *r = redis_cmd(priv->ctx, "SREM group:%lld:users %lld", (long long)group_id, (long long)user_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SREM user:%lld:groups %lld", (long long)user_id, (long long)group_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_get_user_groups(storage_backend_t *self, sso_id_t user_id,
                                          sso_id_t *group_ids, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    redisReply *r = redis_cmd(priv->ctx, "SMEMBERS user:%lld:groups", (long long)user_id);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); *count = 0; return SSO_ERR_NOT_FOUND; }

    size_t n = 0;
    for (size_t i = 0; i < r->elements && n < max; i++) {
        if (r->element[i]->str)
            group_ids[n++] = (sso_id_t)atoll(r->element[i]->str);
    }
    *count = n;
    freeReplyObject(r);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

static sso_error_t redis_get_group_users(storage_backend_t *self, sso_id_t group_id,
                                          sso_id_t *user_ids, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    redisReply *r = redis_cmd(priv->ctx, "SMEMBERS group:%lld:users", (long long)group_id);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); *count = 0; return SSO_ERR_NOT_FOUND; }

    size_t n = 0;
    for (size_t i = 0; i < r->elements && n < max; i++) {
        if (r->element[i]->str)
            user_ids[n++] = (sso_id_t)atoll(r->element[i]->str);
    }
    *count = n;
    freeReplyObject(r);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* Policy assignments */
static sso_error_t redis_assign_policy(storage_backend_t *self, sso_id_t policy_id,
                                        policy_target_type_t target_type, sso_id_t target_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char ptk[KEYBUF]; key_policy_target(ptk, sizeof(ptk), policy_id, (int)target_type);
    char tpk[KEYBUF]; key_target_policies(tpk, sizeof(tpk), (int)target_type, target_id);

    redisReply *r = redis_cmd(priv->ctx, "SADD %s %lld", ptk, (long long)target_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SADD %s %lld", tpk, (long long)policy_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_unassign_policy(storage_backend_t *self, sso_id_t policy_id,
                                          policy_target_type_t target_type, sso_id_t target_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char ptk[KEYBUF]; key_policy_target(ptk, sizeof(ptk), policy_id, (int)target_type);
    char tpk[KEYBUF]; key_target_policies(tpk, sizeof(tpk), (int)target_type, target_id);

    redisReply *r = redis_cmd(priv->ctx, "SREM %s %lld", ptk, (long long)target_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    r = redis_cmd(priv->ctx, "SREM %s %lld", tpk, (long long)policy_id);
    if (!r) return SSO_ERR_STORAGE;
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_get_policy_targets(storage_backend_t *self, sso_id_t policy_id,
                                              policy_target_type_t target_type,
                                              sso_id_t *target_ids, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char ptk[KEYBUF]; key_policy_target(ptk, sizeof(ptk), policy_id, (int)target_type);
    redisReply *r = redis_cmd(priv->ctx, "SMEMBERS %s", ptk);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); *count = 0; return SSO_ERR_NOT_FOUND; }

    size_t n = 0;
    for (size_t i = 0; i < r->elements && n < max; i++) {
        if (r->element[i]->str)
            target_ids[n++] = (sso_id_t)atoll(r->element[i]->str);
    }
    *count = n;
    freeReplyObject(r);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

static sso_error_t redis_get_target_policies(storage_backend_t *self,
                                              policy_target_type_t target_type, sso_id_t target_id,
                                              sso_id_t *policy_ids, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char tpk[KEYBUF]; key_target_policies(tpk, sizeof(tpk), (int)target_type, target_id);
    redisReply *r = redis_cmd(priv->ctx, "SMEMBERS %s", tpk);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); *count = 0; return SSO_ERR_NOT_FOUND; }

    size_t n = 0;
    for (size_t i = 0; i < r->elements && n < max; i++) {
        if (r->element[i]->str)
            policy_ids[n++] = (sso_id_t)atoll(r->element[i]->str);
    }
    *count = n;
    freeReplyObject(r);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* ========================================================================
 * Hierarchy helpers
 * ======================================================================== */

static sso_error_t redis_role_get_parent(storage_backend_t *self, sso_id_t role_id, sso_id_t *parent_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "role", role_id);
    return redis_reply_id(redis_cmd(priv->ctx, "HGET %s parent_role_id", idk), parent_id);
}

static sso_error_t redis_group_get_parent(storage_backend_t *self, sso_id_t group_id, sso_id_t *parent_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char idk[KEYBUF]; key_id(idk, sizeof(idk), "group", group_id);
    return redis_reply_id(redis_cmd(priv->ctx, "HGET %s parent_group_id", idk), parent_id);
}

static sso_error_t redis_get_user_roles_with_ancestors(storage_backend_t *self, sso_id_t user_id,
                                                        sso_id_t *role_ids, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    /* Get directly assigned roles */
    sso_id_t direct[64];
    size_t dc = 0;
    sso_error_t err = redis_get_user_roles(self, user_id, direct, &dc, 64);
    if (err != SSO_OK) { *count = 0; return SSO_ERR_NOT_FOUND; }

    size_t n = 0;
    for (size_t i = 0; i < dc && n < max; i++) {
        sso_id_t cur = direct[i];

        /* Only include active roles */
        role_t r_info;
        if (redis_role_get_by_id(self, cur, &r_info) != SSO_OK ||
            r_info.status != ROLE_STATUS_ACTIVE) {
            continue;
        }

        /* Dedup check */
        bool dup = false;
        for (size_t j = 0; j < n; j++) {
            if (role_ids[j] == cur) { dup = true; break; }
        }
        if (!dup) role_ids[n++] = cur;

        /* Traverse parent chain */
        while (n < max) {
            sso_id_t par;
            if (redis_role_get_parent(self, cur, &par) != SSO_OK || par == SSO_ID_NONE) break;

            if (redis_role_get_by_id(self, par, &r_info) != SSO_OK ||
                r_info.status != ROLE_STATUS_ACTIVE) {
                break;
            }

            dup = false;
            for (size_t j = 0; j < n; j++) {
                if (role_ids[j] == par) { dup = true; break; }
            }
            if (!dup) role_ids[n++] = par;
            cur = par;
        }
    }

    *count = n;
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* ========================================================================
 * OAuth authorization codes
 * ======================================================================== */

static sso_error_t redis_oauth_code_create(storage_backend_t *self, const oauth_auth_code_t *code) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char key[KEYBUF]; snprintf(key, sizeof(key), "oauth:code:%s", code->code);
    char uid[VALBUF], expires[32], used[4];
    snprintf(uid, sizeof(uid), "%lld", (long long)code->user_id);
    snprintf(expires, sizeof(expires), "%lld", (long long)code->expires_at);
    snprintf(used, sizeof(used), "%d", code->used);

    sso_error_t err = redis_hash_set(priv->ctx, key,
        "code", code->code,
        "client_id", code->client_id,
        "user_id", uid,
        "redirect_uri", code->redirect_uri,
        "scope", code->scope,
        "nonce", code->nonce,
        "code_challenge", code->code_challenge,
        "code_challenge_method", code->code_challenge_method,
        "expires_at", expires,
        "used", used,
        (void *)NULL);
    if (err != SSO_OK) return err;

    /* Set TTL on the key */
    unsigned long ttl = (code->expires_at > sso_timestamp_now())
        ? (unsigned long)(code->expires_at - sso_timestamp_now()) / 1000UL : 300UL;
    if (ttl < 1) ttl = 1;
    redisReply *r = redis_cmd(priv->ctx, "EXPIRE %s %lu", key, ttl);
    return redis_ok(priv->ctx, r);
}

static sso_error_t redis_oauth_code_get(storage_backend_t *self, const char *code, oauth_auth_code_t *out) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    memset(out, 0, sizeof(*out));

    char key[KEYBUF]; snprintf(key, sizeof(key), "oauth:code:%s", code);
    redisReply *r = redis_cmd(priv->ctx, "HGETALL %s", key);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type == REDIS_REPLY_NIL) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); return SSO_ERR_STORAGE; }

    for (size_t i = 0; i + 1 < r->elements; i += 2) {
        const char *fn = r->element[i]->str;
        const char *fv = r->element[i + 1]->str;
        if (!fn || !fv) continue;
        if (strcmp(fn, "code") == 0)
            sso_strlcpy(out->code, fv, sizeof(out->code));
        else if (strcmp(fn, "client_id") == 0)
            sso_strlcpy(out->client_id, fv, sizeof(out->client_id));
        else if (strcmp(fn, "user_id") == 0)
            out->user_id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "redirect_uri") == 0)
            sso_strlcpy(out->redirect_uri, fv, sizeof(out->redirect_uri));
        else if (strcmp(fn, "scope") == 0)
            sso_strlcpy(out->scope, fv, sizeof(out->scope));
        else if (strcmp(fn, "nonce") == 0)
            sso_strlcpy(out->nonce, fv, sizeof(out->nonce));
        else if (strcmp(fn, "code_challenge") == 0)
            sso_strlcpy(out->code_challenge, fv, sizeof(out->code_challenge));
        else if (strcmp(fn, "code_challenge_method") == 0)
            sso_strlcpy(out->code_challenge_method, fv, sizeof(out->code_challenge_method));
        else if (strcmp(fn, "expires_at") == 0)
            out->expires_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "used") == 0)
            out->used = atoi(fv);
    }
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_oauth_code_mark_used(storage_backend_t *self, const char *code) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char key[KEYBUF]; snprintf(key, sizeof(key), "oauth:code:%s", code);
    redisReply *r = redis_cmd(priv->ctx, "HSET %s used 1", key);
    return redis_ok(priv->ctx, r);
}

static sso_error_t redis_oauth_code_cleanup(storage_backend_t *self) {
    /* Redis auto-expires keys via TTL, so explicit cleanup is a no-op.
     * The EXPIRE set on each oauth code key handles this automatically. */
    (void)self;
    return SSO_OK;
}

/* ========================================================================
 * OAuth client CRUD
 * ======================================================================== */

static sso_error_t redis_oauth_client_create(storage_backend_t *self, oauth_client_t *client) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    /* Check unique client_id */
    char ck[KEYBUF]; snprintf(ck, sizeof(ck), "oauth:client:%s", client->client_id);
    sso_error_t err = redis_check_unique(priv->ctx, ck);
    if (err != SSO_OK) return err;

    /* Generate internal ID */
    err = redis_next_id(priv->ctx, "oauth:client", &client->id);
    if (err != SSO_OK) return err;

    char sid[VALBUF], sttl[32], sstatus[16], sc[32], su[32];
    snprintf(sid, sizeof(sid), "%lld", (long long)client->id);
    snprintf(sttl, sizeof(sttl), "%ld", client->token_ttl_ms);
    snprintf(sstatus, sizeof(sstatus), "%d", client->status);
    snprintf(sc, sizeof(sc), "%lld", (long long)client->created_at);
    snprintf(su, sizeof(su), "%lld", (long long)client->updated_at);

    err = redis_hash_set(priv->ctx, ck,
        "id", sid,
        "client_id", client->client_id,
        "client_secret_hash", client->client_secret_hash,
        "redirect_uris", client->redirect_uris,
        "app_name", client->app_name,
        "app_description", client->app_description,
        "app_logo_url", client->app_logo_url,
        "allowed_scopes", client->allowed_scopes,
        "allowed_grant_types", client->allowed_grant_types,
        "token_ttl_ms", sttl,
        "status", sstatus,
        "created_at", sc,
        "updated_at", su,
        (void *)NULL);
    if (err != SSO_OK) return err;

    char rk[KEYBUF];
    snprintf(rk, sizeof(rk), "oauth:client:id:%lld", (long long)client->id);
    {
        redisReply *ri = redis_cmd(priv->ctx, "SET %s %s", rk, client->client_id);
        if (ri) freeReplyObject(ri);
    }

    redis_list_push(priv->ctx, "oauth:clients:list", client->id);
    return SSO_OK;
}

static sso_error_t redis_oauth_client_get(storage_backend_t *self, const char *client_id, oauth_client_t *client) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    memset(client, 0, sizeof(*client));

    char ck[KEYBUF]; snprintf(ck, sizeof(ck), "oauth:client:%s", client_id);
    redisReply *r = redis_cmd(priv->ctx, "HGETALL %s", ck);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type == REDIS_REPLY_NIL) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); return SSO_ERR_STORAGE; }

    for (size_t i = 0; i + 1 < r->elements; i += 2) {
        const char *fn = r->element[i]->str;
        const char *fv = r->element[i + 1]->str;
        if (!fn || !fv) continue;
        if (strcmp(fn, "id") == 0)
            client->id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "client_id") == 0)
            sso_strlcpy(client->client_id, fv, sizeof(client->client_id));
        else if (strcmp(fn, "client_secret_hash") == 0)
            sso_strlcpy(client->client_secret_hash, fv, sizeof(client->client_secret_hash));
        else if (strcmp(fn, "redirect_uris") == 0)
            sso_strlcpy(client->redirect_uris, fv, sizeof(client->redirect_uris));
        else if (strcmp(fn, "app_name") == 0)
            sso_strlcpy(client->app_name, fv, sizeof(client->app_name));
        else if (strcmp(fn, "app_description") == 0)
            sso_strlcpy(client->app_description, fv, sizeof(client->app_description));
        else if (strcmp(fn, "app_logo_url") == 0)
            sso_strlcpy(client->app_logo_url, fv, sizeof(client->app_logo_url));
        else if (strcmp(fn, "allowed_scopes") == 0)
            sso_strlcpy(client->allowed_scopes, fv, sizeof(client->allowed_scopes));
        else if (strcmp(fn, "allowed_grant_types") == 0)
            sso_strlcpy(client->allowed_grant_types, fv, sizeof(client->allowed_grant_types));
        else if (strcmp(fn, "token_ttl_ms") == 0)
            client->token_ttl_ms = atol(fv);
        else if (strcmp(fn, "status") == 0)
            client->status = atoi(fv);
        else if (strcmp(fn, "created_at") == 0)
            client->created_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "updated_at") == 0)
            client->updated_at = (sso_timestamp_t)atoll(fv);
    }
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_oauth_client_update(storage_backend_t *self, const oauth_client_t *client) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char ck[KEYBUF]; snprintf(ck, sizeof(ck), "oauth:client:%s", client->client_id);
    char sttl[32], sstatus[16], su[32];
    snprintf(sttl, sizeof(sttl), "%ld", client->token_ttl_ms);
    snprintf(sstatus, sizeof(sstatus), "%d", client->status);
    snprintf(su, sizeof(su), "%lld", (long long)client->updated_at);

    return redis_hash_set(priv->ctx, ck,
        "client_secret_hash", client->client_secret_hash,
        "redirect_uris", client->redirect_uris,
        "app_name", client->app_name,
        "app_description", client->app_description,
        "app_logo_url", client->app_logo_url,
        "allowed_scopes", client->allowed_scopes,
        "allowed_grant_types", client->allowed_grant_types,
        "token_ttl_ms", sttl,
        "status", sstatus,
        "updated_at", su,
        (void *)NULL);
}

static sso_error_t redis_oauth_client_delete(storage_backend_t *self, const char *client_id) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    /* Need the client to find its internal ID for list removal */
    oauth_client_t c;
    sso_error_t err = redis_oauth_client_get(self, client_id, &c);
    if (err != SSO_OK) return err;

    char ck[KEYBUF]; snprintf(ck, sizeof(ck), "oauth:client:%s", client_id);
    redis_del(priv->ctx, ck);
    redis_list_rem(priv->ctx, "oauth:clients:list", c.id);
    return SSO_OK;
}

static sso_error_t redis_oauth_client_list(storage_backend_t *self, int offset, int limit,
                                            oauth_client_t *clients, size_t *count, size_t max) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    redisReply *r = redis_cmd(priv->ctx, "LRANGE oauth:clients:list %d %d",
                               offset, offset + limit - 1);
    if (!r || r->type != REDIS_REPLY_ARRAY) {
        if (r) freeReplyObject(r);
        *count = 0;
        return SSO_OK;
    }

    size_t n = 0;
    for (size_t i = 0; i < r->elements && i < max && n < (size_t)limit; i++) {
        if (!r->element[i]->str) continue;
        sso_id_t cid = (sso_id_t)atoll(r->element[i]->str);

        /* Fetch each client by its internal ID — but we need client_id for that.
         * Instead, iterate LRANGE with the full list and find by position. 
         * This is O(N) but acceptable for admin pagination. */
        /* Simpler approach: use the list to get all IDs, then fetch by client_id
         * from hash. The hash key is derived from client_id, not internal ID.
         * We'll store a reverse index. */
        /* For now, use SCAN-based approach: we iterate and fetch based on list position. */
        (void)cid;
    }
    freeReplyObject(r);

    /* Simpler approach: LRANGE the whole list, then fetch each client by client_id.
     * We need a client_id -> internal ID mapping. Use a SET for client IDs. */
    /* Alternative: iterate SCAN 0 MATCH oauth:client:* and fetch. */
    /* For correctness, let's use SCAN. */
    {
        redisReply *s = redis_cmd(priv->ctx, "LRANGE oauth:clients:list 0 -1");
        if (!s || s->type != REDIS_REPLY_ARRAY) {
            if (s) freeReplyObject(s);
            *count = 0; return SSO_OK;
        }
        size_t match = 0;
        size_t total = s->elements;
        n = 0;
        for (size_t i = 0; i < total && n < (size_t)limit && n < max; i++) {
            if (!s->element[i]->str) continue;
            match++;
            if (match <= (size_t)offset) continue;

            sso_id_t oid = (sso_id_t)atoll(s->element[i]->str);
            /* We need to find the client_id from internal ID.
             * Use a reverse lookup: we store a hash oauth:client:id:{id} -> client_id */
            char rk[KEYBUF];
            snprintf(rk, sizeof(rk), "oauth:client:id:%lld", (long long)oid);
            redisReply *cr = redis_cmd(priv->ctx, "GET %s", rk);
            if (cr && cr->type == REDIS_REPLY_STRING && cr->str) {
                if (redis_oauth_client_get(self, cr->str, &clients[n]) == SSO_OK) {
                    n++;
                }
            }
            if (cr) freeReplyObject(cr);
        }
        *count = n;
        freeReplyObject(s);
    }
    return SSO_OK;
}

/* ========================================================================
 * Refresh tokens
 * ======================================================================== */

static sso_error_t redis_refresh_token_create(storage_backend_t *self, const refresh_token_t *rt) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char key[KEYBUF]; snprintf(key, sizeof(key), "refresh_token:%s", rt->token_hash);
    char uid[VALBUF], expires[32], issued[32], revoked[4];
    snprintf(uid, sizeof(uid), "%lld", (long long)rt->user_id);
    snprintf(expires, sizeof(expires), "%lld", (long long)rt->expires_at);
    snprintf(issued, sizeof(issued), "%lld", (long long)rt->issued_at);
    snprintf(revoked, sizeof(revoked), "%d", rt->revoked);

    return redis_hash_set(priv->ctx, key,
        "token_hash", rt->token_hash,
        "user_id", uid,
        "client_id", rt->client_id,
        "expires_at", expires,
        "issued_at", issued,
        "revoked", revoked,
        (void *)NULL);
}

static sso_error_t redis_refresh_token_get(storage_backend_t *self, const char *token_hash, refresh_token_t *out) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;
    memset(out, 0, sizeof(*out));

    char key[KEYBUF]; snprintf(key, sizeof(key), "refresh_token:%s", token_hash);
    redisReply *r = redis_cmd(priv->ctx, "HGETALL %s", key);
    if (!r) return SSO_ERR_STORAGE;
    if (r->type == REDIS_REPLY_NIL) { freeReplyObject(r); return SSO_ERR_NOT_FOUND; }
    if (r->type != REDIS_REPLY_ARRAY) { freeReplyObject(r); return SSO_ERR_STORAGE; }

    for (size_t i = 0; i + 1 < r->elements; i += 2) {
        const char *fn = r->element[i]->str;
        const char *fv = r->element[i + 1]->str;
        if (!fn || !fv) continue;
        if (strcmp(fn, "token_hash") == 0)
            sso_strlcpy(out->token_hash, fv, sizeof(out->token_hash));
        else if (strcmp(fn, "user_id") == 0)
            out->user_id = (sso_id_t)atoll(fv);
        else if (strcmp(fn, "client_id") == 0)
            sso_strlcpy(out->client_id, fv, sizeof(out->client_id));
        else if (strcmp(fn, "expires_at") == 0)
            out->expires_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "issued_at") == 0)
            out->issued_at = (sso_timestamp_t)atoll(fv);
        else if (strcmp(fn, "revoked") == 0)
            out->revoked = atoi(fv);
    }
    freeReplyObject(r);
    return SSO_OK;
}

static sso_error_t redis_refresh_token_revoke(storage_backend_t *self, const char *token_hash) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    char key[KEYBUF]; snprintf(key, sizeof(key), "refresh_token:%s", token_hash);
    redisReply *r = redis_cmd(priv->ctx, "HSET %s revoked 1", key);
    return redis_ok(priv->ctx, r);
}

static sso_error_t redis_jti_revoke(storage_backend_t *self, const char *jti, sso_timestamp_t expires_at) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return SSO_ERR_STORAGE;

    sso_timestamp_t now = sso_timestamp_now();
    if (expires_at <= now) return SSO_OK;
    int ttl_sec = (int)((expires_at - now) / 1000);
    if (ttl_sec <= 0) ttl_sec = 1;

    redisReply *r = redis_cmd(priv->ctx, "SETEX revoked_jti:%s %d 1", jti, ttl_sec);
    sso_error_t err = redis_ok(priv->ctx, r);
    if (err == SSO_OK) {
        /* Broadcast and locally cache the revocation */
        bloom_add(jti);
        redisReply *pr = redis_cmd(priv->ctx, "PUBLISH sso:revocations %s", jti);
        if (pr) freeReplyObject(pr);
    }
    return err;
}

static bool redis_jti_is_revoked(storage_backend_t *self, const char *jti) {
    redis_priv_t *priv = (redis_priv_t *)self->handle;
    if (!priv || !priv->ctx) return false;

    /* Bloom Filter zero-hop short circuit */
    if (!bloom_might_contain(jti)) {
        return false;
    }

    redisReply *r = redis_cmd(priv->ctx, "EXISTS revoked_jti:%s", jti);
    if (!r) return false;
    bool exists = false;
    if (r->type == REDIS_REPLY_INTEGER) {
        exists = (r->integer == 1);
    }
    freeReplyObject(r);
    return exists;
}

/* ========================================================================
 * Vtable setup
 * ======================================================================== */

sso_error_t storage_redis_create(storage_backend_t **backend) {
    if (!backend) return SSO_ERR_INVALID_PARAM;

    *backend = (storage_backend_t *)calloc(1, sizeof(storage_backend_t));
    if (!*backend) return SSO_ERR_OUT_OF_MEMORY;

    redis_priv_t *priv = (redis_priv_t *)calloc(1, sizeof(redis_priv_t));
    if (!priv) { free(*backend); *backend = NULL; return SSO_ERR_OUT_OF_MEMORY; }

    sso_strlcpy((*backend)->name, "redis", sizeof((*backend)->name));
    (*backend)->name[sizeof((*backend)->name) - 1] = '\0';

    /* Lifecycle */
    (*backend)->open            = redis_open;
    (*backend)->close           = redis_close;
    (*backend)->begin           = redis_begin;
    (*backend)->commit          = redis_commit;
    (*backend)->rollback        = redis_rollback;
    (*backend)->thread_init     = redis_thread_init;
    (*backend)->thread_cleanup  = redis_thread_cleanup;

    /* User */
    (*backend)->user_create         = redis_user_create;
    (*backend)->user_get_by_id      = redis_user_get_by_id;
    (*backend)->user_get_by_name    = redis_user_get_by_name;
    (*backend)->user_get_by_phone   = redis_user_get_by_phone;
    (*backend)->user_update         = redis_user_update;
    (*backend)->user_delete         = redis_user_delete;
    (*backend)->user_list           = redis_user_list;

    /* SMS */
    (*backend)->save_sms_code       = redis_save_sms_code;
    (*backend)->get_sms_code        = redis_get_sms_code;
    (*backend)->delete_sms_code     = redis_delete_sms_code;

    /* Role */
    (*backend)->role_create         = redis_role_create;
    (*backend)->role_get_by_id      = redis_role_get_by_id;
    (*backend)->role_get_by_name    = redis_role_get_by_name;
    (*backend)->role_update         = redis_role_update;
    (*backend)->role_delete         = redis_role_delete;
    (*backend)->role_list           = redis_role_list;

    /* Group */
    (*backend)->group_create        = redis_group_create;
    (*backend)->group_get_by_id     = redis_group_get_by_id;
    (*backend)->group_get_by_name   = redis_group_get_by_name;
    (*backend)->group_update        = redis_group_update;
    (*backend)->group_delete        = redis_group_delete;
    (*backend)->group_list          = redis_group_list;

    /* Policy */
    (*backend)->policy_create       = redis_policy_create;
    (*backend)->policy_get_by_id    = redis_policy_get_by_id;
    (*backend)->policy_get_by_name  = redis_policy_get_by_name;
    (*backend)->policy_update       = redis_policy_update;
    (*backend)->policy_delete       = redis_policy_delete;
    (*backend)->policy_list         = redis_policy_list;

    /* Assignments */
    (*backend)->assign_role_to_user         = redis_assign_role_to_user;
    (*backend)->unassign_role_from_user     = redis_unassign_role_from_user;
    (*backend)->get_user_roles              = redis_get_user_roles;
    (*backend)->get_role_users              = redis_get_role_users;
    (*backend)->assign_role_to_group        = redis_assign_role_to_group;
    (*backend)->unassign_role_from_group    = redis_unassign_role_from_group;
    (*backend)->add_user_to_group           = redis_add_user_to_group;
    (*backend)->remove_user_from_group      = redis_remove_user_from_group;
    (*backend)->get_user_groups             = redis_get_user_groups;
    (*backend)->get_group_users             = redis_get_group_users;
    (*backend)->assign_policy               = redis_assign_policy;
    (*backend)->unassign_policy             = redis_unassign_policy;
    (*backend)->get_policy_targets          = redis_get_policy_targets;
    (*backend)->get_target_policies         = redis_get_target_policies;

    /* Hierarchy */
    (*backend)->role_get_parent              = redis_role_get_parent;
    (*backend)->group_get_parent             = redis_group_get_parent;
    (*backend)->get_user_roles_with_ancestors = redis_get_user_roles_with_ancestors;

    /* OAuth codes */
    (*backend)->oauth_code_create   = redis_oauth_code_create;
    (*backend)->oauth_code_get      = redis_oauth_code_get;
    (*backend)->oauth_code_mark_used = redis_oauth_code_mark_used;
    (*backend)->oauth_code_cleanup  = redis_oauth_code_cleanup;

    /* OAuth clients */
    (*backend)->oauth_client_create = redis_oauth_client_create;
    (*backend)->oauth_client_get    = redis_oauth_client_get;
    (*backend)->oauth_client_update = redis_oauth_client_update;
    (*backend)->oauth_client_delete = redis_oauth_client_delete;
    (*backend)->oauth_client_list   = redis_oauth_client_list;

    (*backend)->refresh_token_create = redis_refresh_token_create;
    (*backend)->refresh_token_get    = redis_refresh_token_get;
    (*backend)->refresh_token_revoke = redis_refresh_token_revoke;
    (*backend)->jti_revoke           = redis_jti_revoke;
    (*backend)->jti_is_revoked       = redis_jti_is_revoked;

    (*backend)->handle = priv;
    return SSO_OK;
}
