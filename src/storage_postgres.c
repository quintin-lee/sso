#include "storage.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "logger.h"
#include <libpq-fe.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>

/* ========================================================================
 * Backend private data & connection pool
 * ======================================================================== */
#include <pthread.h>

#define POSTGRES_POOL_MAX 16

typedef struct {
    PGconn *conn; /* default connection (fallback) */
    char dsn[512];
    PGconn *pool[POSTGRES_POOL_MAX];
    int pool_in_use[POSTGRES_POOL_MAX];
    int pool_size;
    pthread_mutex_t pool_mutex;
    pthread_cond_t pool_cond;
} postgres_priv_t;

static _Thread_local PGconn *tls_conn = NULL;

static postgres_priv_t *postgres_get_priv(storage_backend_t *self) {
    postgres_priv_t *global_priv = (postgres_priv_t *)(self->handle);
    if (tls_conn) {
        static _Thread_local postgres_priv_t tls_priv;
        tls_priv = *global_priv;
        tls_priv.conn = tls_conn;
        return &tls_priv;
    }
    return global_priv;
}

static PGconn *postgres_pool_acquire(postgres_priv_t *priv) {
    pthread_mutex_lock(&priv->pool_mutex);
    while (1) {
        // Find idle connection
        for (int i = 0; i < priv->pool_size; i++) {
            if (!priv->pool_in_use[i]) {
                if (PQstatus(priv->pool[i]) != CONNECTION_OK) {
                    PQfinish(priv->pool[i]);
                    priv->pool[i] = PQconnectdb(priv->dsn);
                }
                priv->pool_in_use[i] = 1;
                pthread_mutex_unlock(&priv->pool_mutex);
                return priv->pool[i];
            }
        }
        
        // Open new connection if pool has capacity
        if (priv->pool_size < POSTGRES_POOL_MAX) {
            PGconn *conn = PQconnectdb(priv->dsn);
            if (PQstatus(conn) == CONNECTION_OK) {
                int idx = priv->pool_size++;
                priv->pool[idx] = conn;
                priv->pool_in_use[idx] = 1;
                pthread_mutex_unlock(&priv->pool_mutex);
                return conn;
            } else {
                PQfinish(conn);
                pthread_mutex_unlock(&priv->pool_mutex);
                return NULL;
            }
        }
        
        // Pool is full, wait
        pthread_cond_wait(&priv->pool_cond, &priv->pool_mutex);
    }
}

static void postgres_pool_release(postgres_priv_t *priv, PGconn *conn) {
    if (!conn) return;
    pthread_mutex_lock(&priv->pool_mutex);
    for (int i = 0; i < priv->pool_size; i++) {
        if (priv->pool[i] == conn) {
            priv->pool_in_use[i] = 0;
            pthread_cond_signal(&priv->pool_cond);
            break;
        }
    }
    pthread_mutex_unlock(&priv->pool_mutex);
}

static void postgres_thread_init(storage_backend_t *self) {
    if (!self) return;
    postgres_priv_t *priv = (postgres_priv_t *)(self->handle);
    if (!priv) return;
    if (!tls_conn) {
        tls_conn = postgres_pool_acquire(priv);
    }
}

static void postgres_thread_cleanup(storage_backend_t *self) {
    if (!self) return;
    postgres_priv_t *priv = (postgres_priv_t *)(self->handle);
    if (!priv) return;
    if (tls_conn) {
        postgres_pool_release(priv, tls_conn);
        tls_conn = NULL;
    }
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

static sso_error_t postgres_open(storage_backend_t *self, const char *dsn) {
    if (!self || !dsn) return SSO_ERR_INVALID_PARAM;

    postgres_priv_t *priv = postgres_get_priv(self);
    
    // Copy DSN
    strncpy(priv->dsn, dsn, sizeof(priv->dsn) - 1);
    priv->dsn[sizeof(priv->dsn) - 1] = '\0';
    
    // Init synchronization primitives
    pthread_mutex_init(&priv->pool_mutex, NULL);
    pthread_cond_init(&priv->pool_cond, NULL);
    priv->pool_size = 0;
    
    // Connect default connection
    priv->conn = PQconnectdb(dsn);
    if (PQstatus(priv->conn) != CONNECTION_OK) {
        PQfinish(priv->conn);
        priv->conn = NULL;
        pthread_mutex_destroy(&priv->pool_mutex);
        pthread_cond_destroy(&priv->pool_cond);
        return SSO_ERR_STORAGE;
    }
    
    // Seed pool with default connection
    priv->pool[0] = priv->conn;
    priv->pool_in_use[0] = 0;
    priv->pool_size = 1;

    /* Initialize schema */
    const char *schema = 
        "CREATE TABLE IF NOT EXISTS users ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  username TEXT UNIQUE NOT NULL,"
        "  phone TEXT UNIQUE,"
        "  password_hash TEXT NOT NULL,"
        "  email TEXT DEFAULT '',"
        "  display_name TEXT DEFAULT '',"
        "  status INTEGER DEFAULT 1,"
        "  created_at BIGINT DEFAULT 0,"
        "  updated_at BIGINT DEFAULT 0,"
        "  attributes TEXT DEFAULT '{}',"
        "  mfa_enabled INTEGER DEFAULT 0,"
        "  mfa_secret TEXT DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS sms_codes ("
        "  phone TEXT PRIMARY KEY,"
        "  code TEXT NOT NULL,"
        "  expires_at BIGINT NOT NULL,"
        "  attempts INTEGER DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS roles ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  name TEXT UNIQUE NOT NULL,"
        "  description TEXT DEFAULT '',"
        "  parent_role_id BIGINT DEFAULT 0,"
        "  status INTEGER DEFAULT 1,"
        "  created_at BIGINT DEFAULT 0,"
        "  updated_at BIGINT DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS groups ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  name TEXT UNIQUE NOT NULL,"
        "  description TEXT DEFAULT '',"
        "  parent_group_id BIGINT DEFAULT 0,"
        "  status INTEGER DEFAULT 1,"
        "  created_at BIGINT DEFAULT 0,"
        "  updated_at BIGINT DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS policies ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  name TEXT UNIQUE NOT NULL,"
        "  strategy_type INTEGER NOT NULL,"
        "  effect INTEGER NOT NULL DEFAULT 1,"
        "  priority INTEGER NOT NULL DEFAULT 0,"
        "  rules TEXT NOT NULL DEFAULT '{}',"
        "  status INTEGER NOT NULL DEFAULT 1,"
        "  created_at BIGINT DEFAULT 0,"
        "  updated_at BIGINT DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS user_roles ("
        "  user_id BIGINT NOT NULL,"
        "  role_id BIGINT NOT NULL,"
        "  PRIMARY KEY (user_id, role_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS user_groups ("
        "  user_id BIGINT NOT NULL,"
        "  group_id BIGINT NOT NULL,"
        "  PRIMARY KEY (user_id, group_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS role_groups ("
        "  role_id BIGINT NOT NULL,"
        "  group_id BIGINT NOT NULL,"
        "  PRIMARY KEY (role_id, group_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS policy_assignments ("
        "  policy_id BIGINT,"
        "  target_type INTEGER,"
        "  target_id BIGINT,"
        "  PRIMARY KEY(policy_id, target_type, target_id)"
        ");"
        "CREATE TABLE IF NOT EXISTS oauth_auth_codes ("
        "  code TEXT PRIMARY KEY,"
        "  client_id TEXT NOT NULL,"
        "  user_id BIGINT NOT NULL,"
        "  redirect_uri TEXT NOT NULL,"
        "  scope TEXT DEFAULT '',"
        "  nonce TEXT DEFAULT '',"
        "  code_challenge TEXT DEFAULT '',"
        "  code_challenge_method TEXT DEFAULT '',"
        "  expires_at BIGINT NOT NULL,"
        "  used INTEGER DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS oauth_clients ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  client_id TEXT UNIQUE NOT NULL,"
        "  client_secret_hash TEXT NOT NULL,"
        "  redirect_uris TEXT NOT NULL,"
        "  app_name TEXT DEFAULT '',"
        "  app_description TEXT DEFAULT '',"
        "  app_logo_url TEXT DEFAULT '',"
        "  allowed_scopes TEXT DEFAULT '',"
        "  allowed_grant_types TEXT DEFAULT '',"
        "  token_ttl_ms BIGINT DEFAULT 0,"
        "  status INTEGER DEFAULT 1,"
        "  created_at BIGINT DEFAULT 0,"
        "  updated_at BIGINT DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS refresh_tokens ("
        "  token_hash TEXT PRIMARY KEY,"
        "  user_id BIGINT NOT NULL,"
        "  client_id TEXT,"
        "  expires_at BIGINT NOT NULL,"
        "  issued_at BIGINT NOT NULL,"
        "  revoked INTEGER DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS revoked_jtis ("
        "  jti TEXT PRIMARY KEY,"
        "  expires_at BIGINT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS audit_logs ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  action TEXT,"
        "  timestamp_ms BIGINT,"
        "  user_id BIGINT,"
        "  username TEXT,"
        "  ip_address TEXT,"
        "  operation TEXT,"
        "  resource TEXT,"
        "  resource_id BIGINT,"
        "  status TEXT,"
        "  details TEXT,"
        "  duration_ms BIGINT,"
        "  cache_hit BOOLEAN,"
        "  trace TEXT"
        ");";

    PGresult *res = PQexec(priv->conn, schema);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);

    return SSO_OK;
}

static void postgres_close(storage_backend_t *self) {
    if (!self) return;
    postgres_priv_t *priv = postgres_get_priv(self);
    if (priv) {
        pthread_mutex_lock(&priv->pool_mutex);
        for (int i = 0; i < priv->pool_size; i++) {
            if (priv->pool[i]) {
                PQfinish(priv->pool[i]);
                priv->pool[i] = NULL;
            }
        }
        pthread_mutex_unlock(&priv->pool_mutex);
        pthread_mutex_destroy(&priv->pool_mutex);
        pthread_cond_destroy(&priv->pool_cond);
        free(priv);
        self->handle = NULL;
    }
}

static sso_error_t postgres_begin(storage_backend_t *self) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    PGresult *res = PQexec(priv->conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_commit(storage_backend_t *self) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    PGresult *res = PQexec(priv->conn, "COMMIT");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_rollback(storage_backend_t *self) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    PGresult *res = PQexec(priv->conn, "ROLLBACK");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

/* ========================================================================
 * Helpers
 * ======================================================================== */

static void map_user(PGresult *res, int row, user_t *u) {
    const char *val;
    
    val = PQgetvalue(res, row, 0);
    u->id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    
    strncpy(u->username, PQgetvalue(res, row, 1), sizeof(u->username) - 1);
    u->username[sizeof(u->username) - 1] = '\0';
    
    strncpy(u->phone, PQgetvalue(res, row, 2), sizeof(u->phone) - 1);
    u->phone[sizeof(u->phone) - 1] = '\0';
    
    strncpy(u->password_hash, PQgetvalue(res, row, 3), sizeof(u->password_hash) - 1);
    u->password_hash[sizeof(u->password_hash) - 1] = '\0';
    
    strncpy(u->email, PQgetvalue(res, row, 4), sizeof(u->email) - 1);
    u->email[sizeof(u->email) - 1] = '\0';
    
    strncpy(u->display_name, PQgetvalue(res, row, 5), sizeof(u->display_name) - 1);
    u->display_name[sizeof(u->display_name) - 1] = '\0';
    
    val = PQgetvalue(res, row, 6);
    u->status = (user_status_t)(val ? atoi(val) : 0);
    
    val = PQgetvalue(res, row, 7);
    u->created_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    
    val = PQgetvalue(res, row, 8);
    u->updated_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    
    strncpy(u->attributes, PQgetvalue(res, row, 9), sizeof(u->attributes) - 1);
    u->attributes[sizeof(u->attributes) - 1] = '\0';
    
    val = PQgetvalue(res, row, 10);
    u->mfa_enabled = val ? atoi(val) : 0;
    
    strncpy(u->mfa_secret, PQgetvalue(res, row, 11), sizeof(u->mfa_secret) - 1);
    u->mfa_secret[sizeof(u->mfa_secret) - 1] = '\0';
}

static void read_role(PGresult *res, int row, role_t *r) {
    const char *val;
    val = PQgetvalue(res, row, 0);
    r->id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    strncpy(r->name, PQgetvalue(res, row, 1), sizeof(r->name) - 1);
    r->name[sizeof(r->name) - 1] = '\0';
    strncpy(r->description, PQgetvalue(res, row, 2), sizeof(r->description) - 1);
    r->description[sizeof(r->description) - 1] = '\0';
    val = PQgetvalue(res, row, 3);
    r->parent_role_id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    val = PQgetvalue(res, row, 4);
    r->status = (role_status_t)(val ? atoi(val) : 0);
    val = PQgetvalue(res, row, 5);
    r->created_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    val = PQgetvalue(res, row, 6);
    r->updated_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
}

static void read_group(PGresult *res, int row, group_t *g) {
    const char *val;
    val = PQgetvalue(res, row, 0);
    g->id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    strncpy(g->name, PQgetvalue(res, row, 1), sizeof(g->name) - 1);
    g->name[sizeof(g->name) - 1] = '\0';
    strncpy(g->description, PQgetvalue(res, row, 2), sizeof(g->description) - 1);
    g->description[sizeof(g->description) - 1] = '\0';
    val = PQgetvalue(res, row, 3);
    g->parent_group_id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    val = PQgetvalue(res, row, 4);
    g->status = (group_status_t)(val ? atoi(val) : 0);
    val = PQgetvalue(res, row, 5);
    g->created_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    val = PQgetvalue(res, row, 6);
    g->updated_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
}

static void read_policy(PGresult *res, int row, policy_t *p) {
    const char *val;
    val = PQgetvalue(res, row, 0);
    p->id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    strncpy(p->name, PQgetvalue(res, row, 1), sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';
    val = PQgetvalue(res, row, 2);
    p->strategy_type = (perm_strategy_type_t)(val ? atoi(val) : 0);
    val = PQgetvalue(res, row, 3);
    p->effect = (policy_effect_t)(val ? atoi(val) : 0);
    val = PQgetvalue(res, row, 4);
    p->priority = val ? atoi(val) : 0;
    strncpy(p->rules, PQgetvalue(res, row, 5), sizeof(p->rules) - 1);
    p->rules[sizeof(p->rules) - 1] = '\0';
    val = PQgetvalue(res, row, 6);
    p->status = (policy_status_t)(val ? atoi(val) : 0);
    val = PQgetvalue(res, row, 7);
    p->created_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    val = PQgetvalue(res, row, 8);
    p->updated_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
}

static void read_oauth_client(PGresult *res, int row, oauth_client_t *c) {
    const char *val;
    
    val = PQgetvalue(res, row, 0);
    c->id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    
    val = PQgetvalue(res, row, 1);
    strncpy(c->client_id, val ? val : "", sizeof(c->client_id) - 1);
    c->client_id[sizeof(c->client_id) - 1] = '\0';
    
    val = PQgetvalue(res, row, 2);
    strncpy(c->client_secret_hash, val ? val : "", sizeof(c->client_secret_hash) - 1);
    c->client_secret_hash[sizeof(c->client_secret_hash) - 1] = '\0';
    
    val = PQgetvalue(res, row, 3);
    strncpy(c->redirect_uris, val ? val : "", sizeof(c->redirect_uris) - 1);
    c->redirect_uris[sizeof(c->redirect_uris) - 1] = '\0';
    
    val = PQgetvalue(res, row, 4);
    strncpy(c->app_name, val ? val : "", sizeof(c->app_name) - 1);
    c->app_name[sizeof(c->app_name) - 1] = '\0';
    
    val = PQgetvalue(res, row, 5);
    strncpy(c->app_description, val ? val : "", sizeof(c->app_description) - 1);
    c->app_description[sizeof(c->app_description) - 1] = '\0';
    
    val = PQgetvalue(res, row, 6);
    strncpy(c->app_logo_url, val ? val : "", sizeof(c->app_logo_url) - 1);
    c->app_logo_url[sizeof(c->app_logo_url) - 1] = '\0';
    
    val = PQgetvalue(res, row, 7);
    strncpy(c->allowed_scopes, val ? val : "", sizeof(c->allowed_scopes) - 1);
    c->allowed_scopes[sizeof(c->allowed_scopes) - 1] = '\0';
    
    val = PQgetvalue(res, row, 8);
    strncpy(c->allowed_grant_types, val ? val : "", sizeof(c->allowed_grant_types) - 1);
    c->allowed_grant_types[sizeof(c->allowed_grant_types) - 1] = '\0';
    
    val = PQgetvalue(res, row, 9);
    c->token_ttl_ms = (val ? strtol(val, NULL, 10) : 0);
    
    val = PQgetvalue(res, row, 10);
    c->status = (val ? atoi(val) : 0);
    
    val = PQgetvalue(res, row, 11);
    c->created_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    
    val = PQgetvalue(res, row, 12);
    c->updated_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
}

/* ========================================================================
 * User CRUD
 * ======================================================================== */

static sso_error_t postgres_user_create(storage_backend_t *self, user_t *u) {
    if (!self || !u) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = 
        "INSERT INTO users (username, phone, password_hash, email, display_name, status, created_at, updated_at, attributes, mfa_enabled, mfa_secret) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id";

    char status_str[16], created_at_str[32], updated_at_str[32], mfa_enabled_str[16];
    snprintf(status_str, sizeof(status_str), "%d", (int)u->status);
    snprintf(created_at_str, sizeof(created_at_str), "%" PRId64, u->created_at);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, u->updated_at);
    snprintf(mfa_enabled_str, sizeof(mfa_enabled_str), "%d", u->mfa_enabled);

    const char *params[11] = {
        u->username,
        u->phone[0] ? u->phone : NULL,
        u->password_hash,
        u->email,
        u->display_name,
        status_str,
        created_at_str,
        updated_at_str,
        u->attributes,
        mfa_enabled_str,
        u->mfa_secret
    };

    PGresult *res = PQexecParams(priv->conn, query, 11, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    const char *id_val = PQgetvalue(res, 0, 0);
    u->id = (sso_id_t)(id_val ? strtoull(id_val, NULL, 10) : 0);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_user_get_by_id(storage_backend_t *self, sso_id_t id, user_t *u) {
    if (!self || !u) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, username, phone, password_hash, email, display_name, status, created_at, updated_at, attributes, mfa_enabled, mfa_secret FROM users WHERE id = $1";
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    map_user(res, 0, u);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_user_get_by_name(storage_backend_t *self, const char *name, user_t *u) {
    if (!self || !name || !u) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, username, phone, password_hash, email, display_name, status, created_at, updated_at, attributes, mfa_enabled, mfa_secret FROM users WHERE username = $1";
    const char *params[1] = { name };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    map_user(res, 0, u);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_user_get_by_phone(storage_backend_t *self, const char *phone, user_t *u) {
    if (!self || !phone || !u) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, username, phone, password_hash, email, display_name, status, created_at, updated_at, attributes, mfa_enabled, mfa_secret FROM users WHERE phone = $1";
    const char *params[1] = { phone };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    map_user(res, 0, u);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_user_update(storage_backend_t *self, const user_t *u) {
    if (!self || !u) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = 
        "UPDATE users SET phone = $1, password_hash = $2, email = $3, display_name = $4, status = $5, updated_at = $6, attributes = $7, mfa_enabled = $8, mfa_secret = $9 "
        "WHERE id = $10";

    char status_str[16], updated_at_str[32], mfa_enabled_str[16], id_str[32];
    snprintf(status_str, sizeof(status_str), "%d", (int)u->status);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, u->updated_at);
    snprintf(mfa_enabled_str, sizeof(mfa_enabled_str), "%d", u->mfa_enabled);
    snprintf(id_str, sizeof(id_str), "%" PRIu64, u->id);

    const char *params[10] = {
        u->phone[0] ? u->phone : NULL,
        u->password_hash,
        u->email,
        u->display_name,
        status_str,
        updated_at_str,
        u->attributes,
        mfa_enabled_str,
        u->mfa_secret,
        id_str
    };

    PGresult *res = PQexecParams(priv->conn, query, 10, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_user_delete(storage_backend_t *self, sso_id_t id) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    /* Cascade delete associated data */
    PQexecParams(priv->conn, "DELETE FROM user_roles WHERE user_id = $1", 1, NULL, params, NULL, NULL, 0);
    PQexecParams(priv->conn, "DELETE FROM user_groups WHERE user_id = $1", 1, NULL, params, NULL, NULL, 0);
    PQexecParams(priv->conn, "DELETE FROM policy_assignments WHERE target_type = 0 AND target_id = $1", 1, NULL, params, NULL, NULL, 0);

    const char *query = "DELETE FROM users WHERE id = $1";
    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_user_list(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count) {
    if (!self || !ids || !count || !total_count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char where[512] = "";
    int p_idx = 1;
    const char *params[6];
    char status_str[16], offset_str[16], limit_str[16], q_pattern[SSO_MAX_QUERY + 2];

    if ((q && q[0] != '\0') || status != -1) {
        strcpy(where, " WHERE ");
        if (status != -1) {
            snprintf(status_str, sizeof(status_str), "%d", status);
            params[p_idx-1] = status_str;
            strcat(where, "status = $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx++);
            strcat(where, idx_str);
        }
        if (q && q[0] != '\0') {
            if (status != -1) strcat(where, " AND ");
            snprintf(q_pattern, sizeof(q_pattern), "%%%s%%", q);
            params[p_idx-1] = q_pattern;
            strcat(where, "(username LIKE $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx);
            strcat(where, idx_str);
            strcat(where, " OR display_name LIKE $");
            strcat(where, idx_str);
            strcat(where, " OR email LIKE $");
            strcat(where, idx_str);
            strcat(where, " OR phone LIKE $");
            strcat(where, idx_str);
            strcat(where, ")");
            p_idx++;
        }
    }

    char query[1024];
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM users %s", where);
    PGresult *res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    *total_count = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);

    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    params[p_idx-1] = limit_str;
    int limit_p_idx = p_idx++;

    snprintf(offset_str, sizeof(offset_str), "%d", offset);
    params[p_idx-1] = offset_str;
    int offset_p_idx = p_idx++;

    snprintf(query, sizeof(query), "SELECT id FROM users %s ORDER BY id LIMIT $%d OFFSET $%d", where, limit_p_idx, offset_p_idx);
    res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    int rows = PQntuples(res);
    for (int i = 0; i < rows; i++) {
        ids[i] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    }
    *count = (size_t)rows;
    PQclear(res);
    return SSO_OK;
}

/* ========================================================================
 * SMS storage
 * ======================================================================== */

static sso_error_t postgres_save_sms_code(storage_backend_t *self, const char *phone, const char *code, sso_timestamp_t expires_at) {
    if (!self || !phone || !code) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = 
        "INSERT INTO sms_codes (phone, code, expires_at, attempts) VALUES ($1, $2, $3, 0) "
        "ON CONFLICT (phone) DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at, attempts = 0";
    
    char expires_at_str[32];
    snprintf(expires_at_str, sizeof(expires_at_str), "%" PRId64, expires_at);
    const char *params[3] = { phone, code, expires_at_str };

    PGresult *res = PQexecParams(priv->conn, query, 3, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_get_sms_code(storage_backend_t *self, const char *phone, char *code_out) {
    if (!self || !phone || !code_out) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT code, expires_at FROM sms_codes WHERE phone = $1";
    const char *params[1] = { phone };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    sso_timestamp_t expires_at = strtoll(PQgetvalue(res, 0, 1), NULL, 10);
    if (sso_timestamp_now() > expires_at) {
        PQclear(res);
        return SSO_ERR_TOKEN_EXPIRED;
    }

    strncpy(code_out, PQgetvalue(res, 0, 0), 15);
    code_out[15] = '\0';
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_delete_sms_code(storage_backend_t *self, const char *phone) {
    if (!self || !phone) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "DELETE FROM sms_codes WHERE phone = $1";
    const char *params[1] = { phone };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

/* ========================================================================
 * Role CRUD
 * ======================================================================== */

static sso_error_t postgres_role_create(storage_backend_t *self, role_t *r) {
    if (!self || !r) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "INSERT INTO roles (name, description, parent_role_id, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id";
    char parent_id_str[32], status_str[16], created_at_str[32], updated_at_str[32];
    snprintf(parent_id_str, sizeof(parent_id_str), "%" PRIu64, r->parent_role_id);
    snprintf(status_str, sizeof(status_str), "%d", (int)r->status);
    snprintf(created_at_str, sizeof(created_at_str), "%" PRId64, r->created_at);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, r->updated_at);

    const char *params[6] = { r->name, r->description, parent_id_str, status_str, created_at_str, updated_at_str };

    PGresult *res = PQexecParams(priv->conn, query, 6, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    r->id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_role_get_by_id(storage_backend_t *self, sso_id_t id, role_t *r) {
    if (!self || !r) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, name, description, parent_role_id, status, created_at, updated_at FROM roles WHERE id = $1";
    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    read_role(res, 0, r);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_role_get_by_name(storage_backend_t *self, const char *name, role_t *r) {
    if (!self || !name || !r) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, name, description, parent_role_id, status, created_at, updated_at FROM roles WHERE name = $1";
    const char *params[1] = { name };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    read_role(res, 0, r);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_role_update(storage_backend_t *self, const role_t *r) {
    if (!self || !r) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "UPDATE roles SET name = $1, description = $2, parent_role_id = $3, status = $4, updated_at = $5 WHERE id = $6";
    char parent_id_str[32], status_str[16], updated_at_str[32], id_str[32];
    snprintf(parent_id_str, sizeof(parent_id_str), "%" PRIu64, r->parent_role_id);
    snprintf(status_str, sizeof(status_str), "%d", (int)r->status);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, r->updated_at);
    snprintf(id_str, sizeof(id_str), "%" PRIu64, r->id);

    const char *params[6] = { r->name, r->description, parent_id_str, status_str, updated_at_str, id_str };

    PGresult *res = PQexecParams(priv->conn, query, 6, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_role_delete(storage_backend_t *self, sso_id_t id) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    PQexecParams(priv->conn, "DELETE FROM user_roles WHERE role_id = $1", 1, NULL, params, NULL, NULL, 0);
    PQexecParams(priv->conn, "DELETE FROM role_groups WHERE role_id = $1", 1, NULL, params, NULL, NULL, 0);
    PQexecParams(priv->conn, "DELETE FROM policy_assignments WHERE target_type = 1 AND target_id = $1", 1, NULL, params, NULL, NULL, 0);

    const char *query = "DELETE FROM roles WHERE id = $1";
    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_role_list(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count) {
    if (!self || !ids || !count || !total_count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char where[512] = "";
    int p_idx = 1;
    const char *params[6];
    char status_str[16], offset_str[16], limit_str[16], q_pattern[SSO_MAX_QUERY + 2];

    if ((q && q[0] != '\0') || status != -1) {
        strcpy(where, " WHERE ");
        if (status != -1) {
            snprintf(status_str, sizeof(status_str), "%d", status);
            params[p_idx-1] = status_str;
            strcat(where, "status = $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx++);
            strcat(where, idx_str);
        }
        if (q && q[0] != '\0') {
            if (status != -1) strcat(where, " AND ");
            snprintf(q_pattern, sizeof(q_pattern), "%%%s%%", q);
            params[p_idx-1] = q_pattern;
            strcat(where, "(name LIKE $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx);
            strcat(where, idx_str);
            strcat(where, " OR description LIKE $");
            strcat(where, idx_str);
            strcat(where, ")");
            p_idx++;
        }
    }

    char query[1024];
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM roles %s", where);
    PGresult *res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    *total_count = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);

    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    params[p_idx-1] = limit_str;
    int limit_p_idx = p_idx++;
    snprintf(offset_str, sizeof(offset_str), "%d", offset);
    params[p_idx-1] = offset_str;
    int offset_p_idx = p_idx++;

    snprintf(query, sizeof(query), "SELECT id FROM roles %s ORDER BY id LIMIT $%d OFFSET $%d", where, limit_p_idx, offset_p_idx);
    res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    int rows = PQntuples(res);
    for (int i = 0; i < rows; i++) ids[i] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    *count = (size_t)rows;
    PQclear(res);
    return SSO_OK;
}

/* ========================================================================
 * Group CRUD
 * ======================================================================== */

static sso_error_t postgres_group_create(storage_backend_t *self, group_t *g) {
    if (!self || !g) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "INSERT INTO groups (name, description, parent_group_id, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id";
    char parent_id_str[32], status_str[16], created_at_str[32], updated_at_str[32];
    snprintf(parent_id_str, sizeof(parent_id_str), "%" PRIu64, g->parent_group_id);
    snprintf(status_str, sizeof(status_str), "%d", (int)g->status);
    snprintf(created_at_str, sizeof(created_at_str), "%" PRId64, g->created_at);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, g->updated_at);

    const char *params[6] = { g->name, g->description, parent_id_str, status_str, created_at_str, updated_at_str };

    PGresult *res = PQexecParams(priv->conn, query, 6, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    g->id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_group_get_by_id(storage_backend_t *self, sso_id_t id, group_t *g) {
    if (!self || !g) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, name, description, parent_group_id, status, created_at, updated_at FROM groups WHERE id = $1";
    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    read_group(res, 0, g);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_group_get_by_name(storage_backend_t *self, const char *name, group_t *g) {
    if (!self || !name || !g) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, name, description, parent_group_id, status, created_at, updated_at FROM groups WHERE name = $1";
    const char *params[1] = { name };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    read_group(res, 0, g);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_group_update(storage_backend_t *self, const group_t *g) {
    if (!self || !g) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "UPDATE groups SET name = $1, description = $2, parent_group_id = $3, status = $4, updated_at = $5 WHERE id = $6";
    char parent_id_str[32], status_str[16], updated_at_str[32], id_str[32];
    snprintf(parent_id_str, sizeof(parent_id_str), "%" PRIu64, g->parent_group_id);
    snprintf(status_str, sizeof(status_str), "%d", (int)g->status);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, g->updated_at);
    snprintf(id_str, sizeof(id_str), "%" PRIu64, g->id);

    const char *params[6] = { g->name, g->description, parent_id_str, status_str, updated_at_str, id_str };

    PGresult *res = PQexecParams(priv->conn, query, 6, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_group_delete(storage_backend_t *self, sso_id_t id) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    PQexecParams(priv->conn, "DELETE FROM user_groups WHERE group_id = $1", 1, NULL, params, NULL, NULL, 0);
    PQexecParams(priv->conn, "DELETE FROM role_groups WHERE group_id = $1", 1, NULL, params, NULL, NULL, 0);
    PQexecParams(priv->conn, "DELETE FROM policy_assignments WHERE target_type = 2 AND target_id = $1", 1, NULL, params, NULL, NULL, 0);

    const char *query = "DELETE FROM groups WHERE id = $1";
    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_group_list(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count) {
    if (!self || !ids || !count || !total_count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char where[512] = "";
    int p_idx = 1;
    const char *params[6];
    char status_str[16], offset_str[16], limit_str[16], q_pattern[SSO_MAX_QUERY + 2];

    if ((q && q[0] != '\0') || status != -1) {
        strcpy(where, " WHERE ");
        if (status != -1) {
            snprintf(status_str, sizeof(status_str), "%d", status);
            params[p_idx-1] = status_str;
            strcat(where, "status = $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx++);
            strcat(where, idx_str);
        }
        if (q && q[0] != '\0') {
            if (status != -1) strcat(where, " AND ");
            snprintf(q_pattern, sizeof(q_pattern), "%%%s%%", q);
            params[p_idx-1] = q_pattern;
            strcat(where, "(name LIKE $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx);
            strcat(where, idx_str);
            strcat(where, " OR description LIKE $");
            strcat(where, idx_str);
            strcat(where, ")");
            p_idx++;
        }
    }

    char query[1024];
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM groups %s", where);
    PGresult *res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    *total_count = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);

    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    params[p_idx-1] = limit_str;
    int limit_p_idx = p_idx++;
    snprintf(offset_str, sizeof(offset_str), "%d", offset);
    params[p_idx-1] = offset_str;
    int offset_p_idx = p_idx++;

    snprintf(query, sizeof(query), "SELECT id FROM groups %s ORDER BY id LIMIT $%d OFFSET $%d", where, limit_p_idx, offset_p_idx);
    res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    int rows = PQntuples(res);
    for (int i = 0; i < rows; i++) ids[i] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    *count = (size_t)rows;
    PQclear(res);
    return SSO_OK;
}

/* ========================================================================
 * Policy CRUD
 * ======================================================================== */

static sso_error_t postgres_policy_create(storage_backend_t *self, policy_t *p) {
    if (!self || !p) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "INSERT INTO policies (name, strategy_type, effect, priority, rules, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id";
    char strategy_str[16], effect_str[16], priority_str[16], status_str[16], created_at_str[32], updated_at_str[32];
    snprintf(strategy_str, sizeof(strategy_str), "%d", (int)p->strategy_type);
    snprintf(effect_str, sizeof(effect_str), "%d", (int)p->effect);
    snprintf(priority_str, sizeof(priority_str), "%d", p->priority);
    snprintf(status_str, sizeof(status_str), "%d", (int)p->status);
    snprintf(created_at_str, sizeof(created_at_str), "%" PRId64, p->created_at);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, p->updated_at);

    const char *params[8] = { p->name, strategy_str, effect_str, priority_str, p->rules, status_str, created_at_str, updated_at_str };

    PGresult *res = PQexecParams(priv->conn, query, 8, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    p->id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_policy_get_by_id(storage_backend_t *self, sso_id_t id, policy_t *p) {
    if (!self || !p) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, name, strategy_type, effect, priority, rules, status, created_at, updated_at FROM policies WHERE id = $1";
    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    read_policy(res, 0, p);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_policy_get_by_name(storage_backend_t *self, const char *name, policy_t *p) {
    if (!self || !name || !p) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT id, name, strategy_type, effect, priority, rules, status, created_at, updated_at FROM policies WHERE name = $1";
    const char *params[1] = { name };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    read_policy(res, 0, p);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_policy_update(storage_backend_t *self, const policy_t *p) {
    if (!self || !p) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "UPDATE policies SET name = $1, strategy_type = $2, effect = $3, priority = $4, rules = $5, status = $6, updated_at = $7 WHERE id = $8";
    char strategy_str[16], effect_str[16], priority_str[16], status_str[16], updated_at_str[32], id_str[32];
    snprintf(strategy_str, sizeof(strategy_str), "%d", (int)p->strategy_type);
    snprintf(effect_str, sizeof(effect_str), "%d", (int)p->effect);
    snprintf(priority_str, sizeof(priority_str), "%d", p->priority);
    snprintf(status_str, sizeof(status_str), "%d", (int)p->status);
    snprintf(updated_at_str, sizeof(updated_at_str), "%" PRId64, p->updated_at);
    snprintf(id_str, sizeof(id_str), "%" PRIu64, p->id);

    const char *params[8] = { p->name, strategy_str, effect_str, priority_str, p->rules, status_str, updated_at_str, id_str };

    PGresult *res = PQexecParams(priv->conn, query, 8, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_policy_delete(storage_backend_t *self, sso_id_t id) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };

    PQexecParams(priv->conn, "DELETE FROM policy_assignments WHERE policy_id = $1", 1, NULL, params, NULL, NULL, 0);

    const char *query = "DELETE FROM policies WHERE id = $1";
    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_policy_list(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count) {
    if (!self || !ids || !count || !total_count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    char where[512] = "";
    int p_idx = 1;
    const char *params[6];
    char status_str[16], offset_str[16], limit_str[16], q_pattern[SSO_MAX_QUERY + 2];

    if ((q && q[0] != '\0') || status != -1) {
        strcpy(where, " WHERE ");
        if (status != -1) {
            snprintf(status_str, sizeof(status_str), "%d", status);
            params[p_idx-1] = status_str;
            strcat(where, "status = $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx++);
            strcat(where, idx_str);
        }
        if (q && q[0] != '\0') {
            if (status != -1) strcat(where, " AND ");
            snprintf(q_pattern, sizeof(q_pattern), "%%%s%%", q);
            params[p_idx-1] = q_pattern;
            strcat(where, "name LIKE $");
            char idx_str[4]; snprintf(idx_str, sizeof(idx_str), "%d", p_idx++);
            strcat(where, idx_str);
        }
    }

    char query[1024];
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM policies %s", where);
    PGresult *res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    *total_count = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);

    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    params[p_idx-1] = limit_str;
    int limit_p_idx = p_idx++;
    snprintf(offset_str, sizeof(offset_str), "%d", offset);
    params[p_idx-1] = offset_str;
    int offset_p_idx = p_idx++;

    snprintf(query, sizeof(query), "SELECT id FROM policies %s ORDER BY id LIMIT $%d OFFSET $%d", where, limit_p_idx, offset_p_idx);
    res = PQexecParams(priv->conn, query, p_idx - 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    int rows = PQntuples(res);
    for (int i = 0; i < rows; i++) ids[i] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    *count = (size_t)rows;
    PQclear(res);
    return SSO_OK;
}

/* ========================================================================
 * Assignment helpers
 * ======================================================================== */

static sso_error_t postgres_assign_id_id(storage_backend_t *self, const char *query, sso_id_t id1, sso_id_t id2) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char s1[32], s2[32];
    snprintf(s1, sizeof(s1), "%" PRIu64, id1);
    snprintf(s2, sizeof(s2), "%" PRIu64, id2);
    const char *params[2] = { s1, s2 };
    PGresult *res = PQexecParams(priv->conn, query, 2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_assign_role_to_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    return postgres_assign_id_id(self, "INSERT INTO user_roles (role_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", role_id, user_id);
}
static sso_error_t postgres_unassign_role_from_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    return postgres_assign_id_id(self, "DELETE FROM user_roles WHERE role_id = $1 AND user_id = $2", role_id, user_id);
}
static sso_error_t postgres_assign_role_to_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    return postgres_assign_id_id(self, "INSERT INTO role_groups (role_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", role_id, group_id);
}
static sso_error_t postgres_unassign_role_from_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    return postgres_assign_id_id(self, "DELETE FROM role_groups WHERE role_id = $1 AND group_id = $2", role_id, group_id);
}
static sso_error_t postgres_add_user_to_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    return postgres_assign_id_id(self, "INSERT INTO user_groups (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", group_id, user_id);
}
static sso_error_t postgres_remove_user_from_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    return postgres_assign_id_id(self, "DELETE FROM user_groups WHERE group_id = $1 AND user_id = $2", group_id, user_id);
}

static sso_error_t postgres_get_ids(storage_backend_t *self, const char *query, sso_id_t id, sso_id_t *ids, size_t *count, size_t max) {
    if (!self || !ids || !count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, id);
    const char *params[1] = { id_str };
    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    int rows = PQntuples(res);
    int n = 0;
    for (int i = 0; i < rows && (size_t)n < max; i++) {
        ids[n++] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    }
    *count = (size_t)n;
    PQclear(res);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

static sso_error_t postgres_get_user_roles(storage_backend_t *self, sso_id_t user_id, sso_id_t *role_ids, size_t *count, size_t max) {
    return postgres_get_ids(self, "SELECT role_id FROM user_roles WHERE user_id = $1", user_id, role_ids, count, max);
}
static sso_error_t postgres_get_role_users(storage_backend_t *self, sso_id_t role_id, sso_id_t *user_ids, size_t *count, size_t max) {
    return postgres_get_ids(self, "SELECT user_id FROM user_roles WHERE role_id = $1", role_id, user_ids, count, max);
}
static sso_error_t postgres_get_user_groups(storage_backend_t *self, sso_id_t user_id, sso_id_t *group_ids, size_t *count, size_t max) {
    return postgres_get_ids(self, "SELECT group_id FROM user_groups WHERE user_id = $1", user_id, group_ids, count, max);
}
static sso_error_t postgres_get_group_users(storage_backend_t *self, sso_id_t group_id, sso_id_t *user_ids, size_t *count, size_t max) {
    return postgres_get_ids(self, "SELECT user_id FROM user_groups WHERE group_id = $1", group_id, user_ids, count, max);
}

static sso_error_t postgres_assign_policy(storage_backend_t *self, sso_id_t policy_id, policy_target_type_t target_type, sso_id_t target_id) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char p_id[32], t_type[16], t_id[32];
    snprintf(p_id, sizeof(p_id), "%" PRIu64, policy_id);
    snprintf(t_type, sizeof(t_type), "%d", (int)target_type);
    snprintf(t_id, sizeof(t_id), "%" PRIu64, target_id);
    const char *params[3] = { p_id, t_type, t_id };
    PGresult *res = PQexecParams(priv->conn, "INSERT INTO policy_assignments (policy_id, target_type, target_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", 3, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_unassign_policy(storage_backend_t *self, sso_id_t policy_id, policy_target_type_t target_type, sso_id_t target_id) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char p_id[32], t_type[16], t_id[32];
    snprintf(p_id, sizeof(p_id), "%" PRIu64, policy_id);
    snprintf(t_type, sizeof(t_type), "%d", (int)target_type);
    snprintf(t_id, sizeof(t_id), "%" PRIu64, target_id);
    const char *params[3] = { p_id, t_type, t_id };
    PGresult *res = PQexecParams(priv->conn, "DELETE FROM policy_assignments WHERE policy_id = $1 AND target_type = $2 AND target_id = $3", 3, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_get_policy_targets(storage_backend_t *self, sso_id_t policy_id, policy_target_type_t target_type, sso_id_t *target_ids, size_t *count, size_t max) {
    if (!self || !target_ids || !count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char p_id[32], t_type[16];
    snprintf(p_id, sizeof(p_id), "%" PRIu64, policy_id);
    snprintf(t_type, sizeof(t_type), "%d", (int)target_type);
    const char *params[2] = { p_id, t_type };
    PGresult *res = PQexecParams(priv->conn, "SELECT target_id FROM policy_assignments WHERE policy_id = $1 AND target_type = $2", 2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    int rows = PQntuples(res);
    int n = 0;
    for (int i = 0; i < rows && (size_t)n < max; i++) target_ids[n++] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    *count = (size_t)n;
    PQclear(res);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

static sso_error_t postgres_get_target_policies(storage_backend_t *self, policy_target_type_t target_type, sso_id_t target_id, sso_id_t *policy_ids, size_t *count, size_t max) {
    if (!self || !policy_ids || !count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char t_type[16], t_id[32];
    snprintf(t_type, sizeof(t_type), "%d", (int)target_type);
    snprintf(t_id, sizeof(t_id), "%" PRIu64, target_id);
    const char *params[2] = { t_type, t_id };
    PGresult *res = PQexecParams(priv->conn, "SELECT policy_id FROM policy_assignments WHERE target_type = $1 AND target_id = $2", 2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    int rows = PQntuples(res);
    int n = 0;
    for (int i = 0; i < rows && (size_t)n < max; i++) policy_ids[n++] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    *count = (size_t)n;
    PQclear(res);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* ========================================================================
 * Hierarchy
 * ======================================================================== */

static sso_error_t postgres_role_get_parent(storage_backend_t *self, sso_id_t role_id, sso_id_t *parent_id) {
    if (!self || !parent_id) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, role_id);
    const char *params[1] = { id_str };
    PGresult *res = PQexecParams(priv->conn, "SELECT parent_role_id FROM roles WHERE id = $1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }
    *parent_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_group_get_parent(storage_backend_t *self, sso_id_t group_id, sso_id_t *parent_id) {
    if (!self || !parent_id) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, group_id);
    const char *params[1] = { id_str };
    PGresult *res = PQexecParams(priv->conn, "SELECT parent_group_id FROM groups WHERE id = $1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }
    *parent_id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_get_user_roles_with_ancestors(storage_backend_t *self, sso_id_t user_id, sso_id_t *role_ids, size_t *count, size_t max) {
    if (!self || !role_ids || !count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char id_str[32]; snprintf(id_str, sizeof(id_str), "%" PRIu64, user_id);
    const char *params[1] = { id_str };
    const char *sql =
        "WITH RECURSIVE user_role_tree(role_id) AS ("
        "  SELECT role_id FROM user_roles WHERE user_id = $1"
        "  UNION"
        "  SELECT r.parent_role_id FROM roles r"
        "  INNER JOIN user_role_tree ut ON r.id = ut.role_id"
        "  WHERE r.parent_role_id != 0 AND r.status = 1"
        ")"
        "SELECT DISTINCT t.role_id FROM user_role_tree t "
        "INNER JOIN roles r ON t.role_id = r.id WHERE r.status = 1";

    PGresult *res = PQexecParams(priv->conn, sql, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    int rows = PQntuples(res);
    int n = 0;
    for (int i = 0; i < rows && (size_t)n < max; i++) role_ids[n++] = strtoull(PQgetvalue(res, i, 0), NULL, 10);
    *count = (size_t)n;
    PQclear(res);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* ========================================================================
 * OAuth Storage
 * ======================================================================== */

static sso_error_t postgres_oauth_code_create(storage_backend_t *self, const oauth_auth_code_t *c) {
    if (!self || !c) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char user_id[32], expires[32];
    snprintf(user_id, sizeof(user_id), "%" PRIu64, c->user_id);
    snprintf(expires, sizeof(expires), "%" PRId64, c->expires_at);
    const char *params[9] = { c->code, c->client_id, user_id, c->redirect_uri, c->scope, c->nonce, c->code_challenge, c->code_challenge_method, expires };
    PGresult *res = PQexecParams(priv->conn, "INSERT INTO oauth_auth_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, used) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0)", 9, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_code_get(storage_backend_t *self, const char *code, oauth_auth_code_t *out) {
    if (!self || !code || !out) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    const char *params[1] = { code };
    PGresult *res = PQexecParams(priv->conn, "SELECT code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, expires_at, used FROM oauth_auth_codes WHERE code = $1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }
    memset(out, 0, sizeof(*out));
    strncpy(out->code, PQgetvalue(res, 0, 0), sizeof(out->code)-1);
    strncpy(out->client_id, PQgetvalue(res, 0, 1), sizeof(out->client_id)-1);
    out->user_id = strtoull(PQgetvalue(res, 0, 2), NULL, 10);
    strncpy(out->redirect_uri, PQgetvalue(res, 0, 3), sizeof(out->redirect_uri)-1);
    strncpy(out->scope, PQgetvalue(res, 0, 4), sizeof(out->scope)-1);
    strncpy(out->nonce, PQgetvalue(res, 0, 5), sizeof(out->nonce)-1);
    strncpy(out->code_challenge, PQgetvalue(res, 0, 6), sizeof(out->code_challenge)-1);
    strncpy(out->code_challenge_method, PQgetvalue(res, 0, 7), sizeof(out->code_challenge_method)-1);
    out->expires_at = strtoll(PQgetvalue(res, 0, 8), NULL, 10);
    out->used = atoi(PQgetvalue(res, 0, 9));
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_code_mark_used(storage_backend_t *self, const char *code) {
    if (!self || !code) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    const char *params[1] = { code };
    PGresult *res = PQexecParams(priv->conn, "UPDATE oauth_auth_codes SET used = 1 WHERE code = $1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_code_cleanup(storage_backend_t *self) {
    if (!self) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char now[32]; snprintf(now, sizeof(now), "%" PRId64, sso_timestamp_now());
    const char *params[1] = { now };
    PGresult *res = PQexecParams(priv->conn, "DELETE FROM oauth_auth_codes WHERE expires_at < $1 OR used = 1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_client_create(storage_backend_t *self, oauth_client_t *c) {
    if (!self || !c) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char ttl[32], status[16], created[32], updated[32];
    snprintf(ttl, sizeof(ttl), "%ld", c->token_ttl_ms);
    snprintf(status, sizeof(status), "%d", c->status);
    snprintf(created, sizeof(created), "%" PRId64, c->created_at);
    snprintf(updated, sizeof(updated), "%" PRId64, c->updated_at);
    const char *params[12] = { c->client_id, c->client_secret_hash, c->redirect_uris, c->app_name, c->app_description, c->app_logo_url, c->allowed_scopes, c->allowed_grant_types, ttl, status, created, updated };
    PGresult *res = PQexecParams(priv->conn, "INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris, app_name, app_description, app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id", 12, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        const char *sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
        sso_error_t ret = SSO_ERR_STORAGE;
        if (sqlstate && strcmp(sqlstate, "23505") == 0) {
            ret = SSO_ERR_ALREADY_EXISTS;
        }
        PQclear(res);
        return ret;
    }
    c->id = strtoull(PQgetvalue(res, 0, 0), NULL, 10);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_client_get(storage_backend_t *self, const char *client_id, oauth_client_t *c) {
    if (!self || !client_id || !c) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    const char *params[1] = { client_id };
    PGresult *res = PQexecParams(priv->conn, "SELECT id, client_id, client_secret_hash, redirect_uris, app_name, app_description, app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, updated_at FROM oauth_clients WHERE client_id = $1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }
    read_oauth_client(res, 0, c);
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_client_update(storage_backend_t *self, const oauth_client_t *c) {
    if (!self || !c) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char ttl[32], status[16], updated[32], id_str[32];
    snprintf(ttl, sizeof(ttl), "%ld", c->token_ttl_ms);
    snprintf(status, sizeof(status), "%d", c->status);
    snprintf(updated, sizeof(updated), "%" PRId64, c->updated_at);
    snprintf(id_str, sizeof(id_str), "%" PRIu64, c->id);
    const char *params[12] = { c->client_id, c->client_secret_hash, c->redirect_uris, c->app_name, c->app_description, c->app_logo_url, c->allowed_scopes, c->allowed_grant_types, ttl, status, updated, id_str };
    PGresult *res = PQexecParams(priv->conn, "UPDATE oauth_clients SET client_id = $1, client_secret_hash = $2, redirect_uris = $3, app_name = $4, app_description = $5, app_logo_url = $6, allowed_scopes = $7, allowed_grant_types = $8, token_ttl_ms = $9, status = $10, updated_at = $11 WHERE id = $12", 12, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_client_delete(storage_backend_t *self, const char *client_id) {
    if (!self || !client_id) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    const char *params[1] = { client_id };
    PGresult *res = PQexecParams(priv->conn, "DELETE FROM oauth_clients WHERE client_id = $1", 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_oauth_client_list(storage_backend_t *self, int offset, int limit, oauth_client_t *clients, size_t *count, size_t max) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!self || !clients || !count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);
    char off[16], lim[16];
    snprintf(off, sizeof(off), "%d", offset);
    snprintf(lim, sizeof(lim), "%d", limit);
    const char *params[2] = { lim, off };
    PGresult *res = PQexecParams(priv->conn, "SELECT id, client_id, client_secret_hash, redirect_uris, app_name, app_description, app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, updated_at FROM oauth_clients LIMIT $1 OFFSET $2", 2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }
    int rows = PQntuples(res);
    int n = 0;
    for (int i = 0; i < rows && (size_t)n < max; i++) read_oauth_client(res, i, &clients[n++]);
    *count = (size_t)n;
    PQclear(res);
    return SSO_OK;
}

/* ========================================================================
 * OAuth Storage
 * ======================================================================== */

static sso_error_t postgres_rt_create(storage_backend_t *self, const refresh_token_t *rt) {
    if (!self || !rt) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at, issued_at, revoked) VALUES ($1, $2, $3, $4, $5, $6)";
    
    char user_id_str[32], expires_at_str[32], issued_at_str[32], revoked_str[16];
    snprintf(user_id_str, sizeof(user_id_str), "%" PRIu64, rt->user_id);
    snprintf(expires_at_str, sizeof(expires_at_str), "%" PRId64, rt->expires_at);
    snprintf(issued_at_str, sizeof(issued_at_str), "%" PRId64, rt->issued_at);
    snprintf(revoked_str, sizeof(revoked_str), "%d", rt->revoked);

    const char *params[6] = {
        rt->token_hash,
        user_id_str,
        rt->client_id,
        expires_at_str,
        issued_at_str,
        revoked_str
    };

    PGresult *res = PQexecParams(priv->conn, query, 6, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_rt_get(storage_backend_t *self, const char *token_hash, refresh_token_t *out) {
    if (!self || !token_hash || !out) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT token_hash, user_id, client_id, expires_at, issued_at, revoked FROM refresh_tokens WHERE token_hash = $1";
    const char *params[1] = { token_hash };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return SSO_ERR_NOT_FOUND;
    }

    const char *val;
    strncpy(out->token_hash, PQgetvalue(res, 0, 0), sizeof(out->token_hash) - 1);
    out->token_hash[sizeof(out->token_hash) - 1] = '\0';
    
    val = PQgetvalue(res, 0, 1);
    out->user_id = (sso_id_t)(val ? strtoull(val, NULL, 10) : 0);
    
    strncpy(out->client_id, PQgetvalue(res, 0, 2), sizeof(out->client_id) - 1);
    out->client_id[sizeof(out->client_id) - 1] = '\0';
    
    val = PQgetvalue(res, 0, 3);
    out->expires_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    
    val = PQgetvalue(res, 0, 4);
    out->issued_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    
    val = PQgetvalue(res, 0, 5);
    out->revoked = val ? atoi(val) : 0;

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_rt_revoke(storage_backend_t *self, const char *token_hash) {
    if (!self || !token_hash) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = $1";
    const char *params[1] = { token_hash };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_jti_revoke(storage_backend_t *self, const char *jti, sso_timestamp_t expires_at) {
    if (!self || !jti) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "INSERT INTO revoked_jtis (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at";
    
    char expires_at_str[32];
    snprintf(expires_at_str, sizeof(expires_at_str), "%" PRId64, expires_at);

    const char *params[2] = { jti, expires_at_str };

    PGresult *res = PQexecParams(priv->conn, query, 2, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static bool postgres_jti_is_revoked(storage_backend_t *self, const char *jti) {
    if (!self || !jti) return false;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "SELECT expires_at FROM revoked_jtis WHERE jti = $1";
    const char *params[1] = { jti };

    PGresult *res = PQexecParams(priv->conn, query, 1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return false;
    }

    const char *val = PQgetvalue(res, 0, 0);
    sso_timestamp_t expires_at = (sso_timestamp_t)(val ? strtoll(val, NULL, 10) : 0);
    sso_timestamp_t now = sso_timestamp_now();
    bool revoked = (expires_at > now);

    PQclear(res);
    return revoked;
}

static void escape_json_string(const char *src, char *dst, size_t dst_max) {
    if (!src) { dst[0] = '\0'; return; }
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_max - 3; i++) {
        if (src[i] == '"') { dst[j++] = '\\'; dst[j++] = '"'; }
        else if (src[i] == '\\') { dst[j++] = '\\'; dst[j++] = '\\'; }
        else if (src[i] == '\n') { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (src[i] == '\t') { dst[j++] = '\\'; dst[j++] = 't'; }
        else if (src[i] == '\r') { dst[j++] = '\\'; dst[j++] = 'r'; }
        else dst[j++] = src[i];
    }
    dst[j] = '\0';
}

static sso_error_t postgres_audit_log_write(storage_backend_t *self, const audit_log_entry_t *entry) {
    if (!self || !entry) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    const char *query = "INSERT INTO audit_logs (action, timestamp_ms, user_id, username, ip_address, operation, resource, resource_id, status, details, duration_ms, cache_hit, trace) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)";

    char ts_str[32], uid_str[32], res_id_str[32], dur_str[32];
    snprintf(ts_str, sizeof(ts_str), "%" PRIu64, entry->timestamp_ms);
    snprintf(uid_str, sizeof(uid_str), "%" PRId64, entry->user_id);
    snprintf(res_id_str, sizeof(res_id_str), "%" PRId64, entry->resource_id);
    snprintf(dur_str, sizeof(dur_str), "%" PRIu64, entry->duration_ms);
    const char *ch_str = entry->cache_hit ? "true" : "false";

    const char *params[13] = {
        entry->action,
        ts_str,
        uid_str,
        entry->username ? entry->username : "",
        entry->ip_address ? entry->ip_address : "",
        entry->operation ? entry->operation : "",
        entry->resource ? entry->resource : "",
        res_id_str,
        entry->status ? entry->status : "",
        entry->details ? entry->details : "",
        dur_str,
        ch_str,
        entry->trace ? entry->trace : ""
    };

    PGresult *res = PQexecParams(priv->conn, query, 13, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    PQclear(res);
    return SSO_OK;
}

static sso_error_t postgres_audit_log_list(storage_backend_t *self, sso_id_t user_id, int offset, int limit, char **json_out, size_t *total_count) {
    if (!self || !json_out || !total_count) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = postgres_get_priv(self);

    // Count total
    PGresult *res_count;
    if (user_id != SSO_ID_NONE) {
        char uid_str[32];
        snprintf(uid_str, sizeof(uid_str), "%" PRId64, user_id);
        const char *params[1] = { uid_str };
        res_count = PQexecParams(priv->conn, "SELECT COUNT(*) FROM audit_logs WHERE user_id = $1", 1, NULL, params, NULL, NULL, 0);
    } else {
        res_count = PQexec(priv->conn, "SELECT COUNT(*) FROM audit_logs");
    }

    if (PQresultStatus(res_count) == PGRES_TUPLES_OK && PQntuples(res_count) > 0) {
        *total_count = (size_t)atoll(PQgetvalue(res_count, 0, 0));
    } else {
        *total_count = 0;
    }
    PQclear(res_count);

    // Query records
    PGresult *res;
    char limit_str[32], offset_str[32];
    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    snprintf(offset_str, sizeof(offset_str), "%d", offset);

    if (user_id != SSO_ID_NONE) {
        char uid_str[32];
        snprintf(uid_str, sizeof(uid_str), "%" PRId64, user_id);
        const char *params[3] = { uid_str, limit_str, offset_str };
        res = PQexecParams(priv->conn, "SELECT action, timestamp_ms, user_id, username, ip_address, operation, resource, resource_id, status, details, duration_ms, cache_hit, trace FROM audit_logs WHERE user_id = $1 ORDER BY id DESC LIMIT $2 OFFSET $3", 3, NULL, params, NULL, NULL, 0);
    } else {
        const char *params[2] = { limit_str, offset_str };
        res = PQexecParams(priv->conn, "SELECT action, timestamp_ms, user_id, username, ip_address, operation, resource, resource_id, status, details, duration_ms, cache_hit, trace FROM audit_logs ORDER BY id DESC LIMIT $1 OFFSET $2", 2, NULL, params, NULL, NULL, 0);
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return SSO_ERR_STORAGE;
    }

    int rows = PQntuples(res);
    size_t cap = 4096;
    size_t len = 0;
    char *json = malloc(cap);
    if (!json) { PQclear(res); return SSO_ERR_OUT_OF_MEMORY; }
    json[len++] = '[';
    json[len] = '\0';

    bool first = true;
    for (int i = 0; i < rows; i++) {
        const char *action = PQgetvalue(res, i, 0);
        uint64_t ts = (uint64_t)atoll(PQgetvalue(res, i, 1));
        sso_id_t uid = (sso_id_t)atoll(PQgetvalue(res, i, 2));
        const char *username = PQgetvalue(res, i, 3);
        const char *ip = PQgetvalue(res, i, 4);
        const char *op = PQgetvalue(res, i, 5);
        const char *resource = PQgetvalue(res, i, 6);
        sso_id_t res_id = (sso_id_t)atoll(PQgetvalue(res, i, 7));
        const char *status = PQgetvalue(res, i, 8);
        const char *details = PQgetvalue(res, i, 9);
        uint64_t dur = (uint64_t)atoll(PQgetvalue(res, i, 10));
        const char *ch_val = PQgetvalue(res, i, 11);
        bool ch = (ch_val[0] == 't' || ch_val[0] == '1');
        const char *trace = PQgetvalue(res, i, 12);

        char esc_det[2048] = "", esc_trace[16384] = "";
        escape_json_string(details, esc_det, sizeof(esc_det));
        escape_json_string(trace, esc_trace, sizeof(esc_trace));

        char row[20480];
        if (strcmp(action, "admin") == 0) {
            snprintf(row, sizeof(row),
                "{\"action\":\"admin\",\"timestamp_ms\":%llu,\"user_id\":%llu,\"username\":\"%s\",\"ip_address\":\"%s\",\"operation\":\"%s\",\"resource\":\"%s\",\"resource_id\":%llu,\"status\":\"%s\",\"details\":\"%s\"}",
                (unsigned long long)ts, (unsigned long long)uid, username ? username : "", ip ? ip : "", op ? op : "", resource ? resource : "", (unsigned long long)res_id, status ? status : "", esc_det);
        } else {
            snprintf(row, sizeof(row),
                "{\"action\":\"eval\",\"timestamp_ms\":%llu,\"user_id\":%llu,\"decision\":\"%s\",\"duration_ms\":%llu,\"cache_hit\":%s,\"trace\":\"%s\"}",
                (unsigned long long)ts, (unsigned long long)uid, status ? status : "", (unsigned long long)dur, ch ? "true" : "false", esc_trace);
        }

        size_t row_len = strlen(row);
        if (len + row_len + 3 > cap) {
            cap = (len + row_len + 3) * 2;
            char *new_json = realloc(json, cap);
            if (!new_json) { free(json); PQclear(res); return SSO_ERR_OUT_OF_MEMORY; }
            json = new_json;
        }

        if (!first) {
            json[len++] = ',';
        }
        first = false;
        memcpy(json + len, row, row_len);
        len += row_len;
        json[len] = '\0';
    }

    json[len++] = ']';
    json[len] = '\0';
    PQclear(res);

    *json_out = json;
    return SSO_OK;
}

/* ========================================================================
 * Public constructor
 * ======================================================================== */

sso_error_t storage_postgres_create(storage_backend_t **backend) {
    if (!backend) return SSO_ERR_INVALID_PARAM;

    *backend = (storage_backend_t *)calloc(1, sizeof(storage_backend_t));
    if (!*backend) return SSO_ERR_OUT_OF_MEMORY;

    postgres_priv_t *priv = (postgres_priv_t *)calloc(1, sizeof(postgres_priv_t));
    if (!priv) {
        free(*backend);
        *backend = NULL;
        return SSO_ERR_OUT_OF_MEMORY;
    }

    (*backend)->handle = priv;
    strncpy((*backend)->name, "postgres", sizeof((*backend)->name) - 1);
    (*backend)->name[sizeof((*backend)->name) - 1] = '\0';

    /* Lifecycle */
    (*backend)->open           = postgres_open;
    (*backend)->close          = postgres_close;
    (*backend)->begin          = postgres_begin;
    (*backend)->commit         = postgres_commit;
    (*backend)->rollback       = postgres_rollback;
    (*backend)->thread_init    = postgres_thread_init;
    (*backend)->thread_cleanup = postgres_thread_cleanup;

    /* User */
    (*backend)->user_create       = postgres_user_create;
    (*backend)->user_get_by_id    = postgres_user_get_by_id;
    (*backend)->user_get_by_name  = postgres_user_get_by_name;
    (*backend)->user_get_by_phone = postgres_user_get_by_phone;
    (*backend)->user_update       = postgres_user_update;
    (*backend)->user_delete       = postgres_user_delete;
    (*backend)->user_list         = postgres_user_list;

    /* SMS */
    (*backend)->save_sms_code     = postgres_save_sms_code;
    (*backend)->get_sms_code      = postgres_get_sms_code;
    (*backend)->delete_sms_code   = postgres_delete_sms_code;

    /* Role */
    (*backend)->role_create       = postgres_role_create;
    (*backend)->role_get_by_id    = postgres_role_get_by_id;
    (*backend)->role_get_by_name  = postgres_role_get_by_name;
    (*backend)->role_update       = postgres_role_update;
    (*backend)->role_delete       = postgres_role_delete;
    (*backend)->role_list         = postgres_role_list;

    /* Group */
    (*backend)->group_create      = postgres_group_create;
    (*backend)->group_get_by_id   = postgres_group_get_by_id;
    (*backend)->group_get_by_name = postgres_group_get_by_name;
    (*backend)->group_update      = postgres_group_update;
    (*backend)->group_delete      = postgres_group_delete;
    (*backend)->group_list        = postgres_group_list;

    /* Policy */
    (*backend)->policy_create      = postgres_policy_create;
    (*backend)->policy_get_by_id   = postgres_policy_get_by_id;
    (*backend)->policy_get_by_name = postgres_policy_get_by_name;
    (*backend)->policy_update      = postgres_policy_update;
    (*backend)->policy_delete      = postgres_policy_delete;
    (*backend)->policy_list        = postgres_policy_list;

    /* Assignments */
    (*backend)->assign_role_to_user     = postgres_assign_role_to_user;
    (*backend)->unassign_role_from_user = postgres_unassign_role_from_user;
    (*backend)->get_user_roles           = postgres_get_user_roles;
    (*backend)->get_role_users           = postgres_get_role_users;

    (*backend)->assign_role_to_group     = postgres_assign_role_to_group;
    (*backend)->unassign_role_from_group   = postgres_unassign_role_from_group;

    (*backend)->add_user_to_group        = postgres_add_user_to_group;
    (*backend)->remove_user_from_group   = postgres_remove_user_from_group;
    (*backend)->get_user_groups          = postgres_get_user_groups;
    (*backend)->get_group_users          = postgres_get_group_users;

    (*backend)->assign_policy            = postgres_assign_policy;
    (*backend)->unassign_policy          = postgres_unassign_policy;
    (*backend)->get_policy_targets       = postgres_get_policy_targets;
    (*backend)->get_target_policies      = postgres_get_target_policies;

    /* Hierarchy */
    (*backend)->role_get_parent               = postgres_role_get_parent;
    (*backend)->group_get_parent              = postgres_group_get_parent;
    (*backend)->get_user_roles_with_ancestors = postgres_get_user_roles_with_ancestors;

    /* OAuth authorization codes */
    (*backend)->oauth_code_create    = postgres_oauth_code_create;
    (*backend)->oauth_code_get       = postgres_oauth_code_get;
    (*backend)->oauth_code_mark_used = postgres_oauth_code_mark_used;
    (*backend)->oauth_code_cleanup   = postgres_oauth_code_cleanup;

    (*backend)->oauth_client_create  = postgres_oauth_client_create;
    (*backend)->oauth_client_get     = postgres_oauth_client_get;
    (*backend)->oauth_client_update  = postgres_oauth_client_update;
    (*backend)->oauth_client_delete  = postgres_oauth_client_delete;
    (*backend)->oauth_client_list    = postgres_oauth_client_list;

    (*backend)->refresh_token_create = postgres_rt_create;
    (*backend)->refresh_token_get    = postgres_rt_get;
    (*backend)->refresh_token_revoke = postgres_rt_revoke;
    (*backend)->jti_revoke           = postgres_jti_revoke;
    (*backend)->jti_is_revoked       = postgres_jti_is_revoked;
    (*backend)->audit_log_write      = postgres_audit_log_write;
    (*backend)->audit_log_list       = postgres_audit_log_list;

    return SSO_OK;
}
