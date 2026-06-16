#include "storage.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include <libpq-fe.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ========================================================================
 * Backend private data
 * ======================================================================== */
typedef struct {
    PGconn *conn;
} postgres_priv_t;

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

static sso_error_t postgres_open(storage_backend_t *self, const char *dsn) {
    if (!self || !dsn) return SSO_ERR_INVALID_PARAM;

    postgres_priv_t *priv = (postgres_priv_t *)self->handle;
    priv->conn = PQconnectdb(dsn);

    if (PQstatus(priv->conn) != CONNECTION_OK) {
        PQfinish(priv->conn);
        priv->conn = NULL;
        return SSO_ERR_STORAGE;
    }

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
        "CREATE TABLE IF NOT EXISTS refresh_tokens ("
        "  token_hash TEXT PRIMARY KEY,"
        "  user_id BIGINT NOT NULL,"
        "  client_id TEXT,"
        "  expires_at BIGINT NOT NULL,"
        "  issued_at BIGINT NOT NULL,"
        "  revoked INTEGER DEFAULT 0"
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
    postgres_priv_t *priv = (postgres_priv_t *)self->handle;
    if (priv) {
        if (priv->conn) {
            PQfinish(priv->conn);
            priv->conn = NULL;
        }
        free(priv);
        self->handle = NULL;
    }
}

/* ========================================================================
 * Stubs for not implemented functions
 * ======================================================================== */

static sso_error_t postgres_stub_err(storage_backend_t *self) {
    (void)self; return SSO_ERR_NOT_IMPLEMENTED;
}

/* User */
static sso_error_t postgres_stub_user_get_name(storage_backend_t *s, const char *n, user_t *u) { (void)s; (void)n; (void)u; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_user_update(storage_backend_t *s, const user_t *u) { (void)s; (void)u; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_id(storage_backend_t *s, sso_id_t id) { (void)s; (void)id; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_list(storage_backend_t *s, const char *q, int st, int o, int l, sso_id_t *ids, size_t *c, size_t *t) { (void)s; (void)q; (void)st; (void)o; (void)l; (void)ids; (void)c; (void)t; return SSO_ERR_NOT_IMPLEMENTED; }

/* SMS */
static sso_error_t postgres_stub_sms_save(storage_backend_t *s, const char *p, const char *c, sso_timestamp_t e) { (void)s; (void)p; (void)c; (void)e; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_sms_get(storage_backend_t *s, const char *p, char *c) { (void)s; (void)p; (void)c; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_pchar(storage_backend_t *s, const char *p) { (void)s; (void)p; return SSO_ERR_NOT_IMPLEMENTED; }

/* Role */
static sso_error_t postgres_stub_role_create(storage_backend_t *s, role_t *r) { (void)s; (void)r; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_role_get_id(storage_backend_t *s, sso_id_t id, role_t *r) { (void)s; (void)id; (void)r; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_role_get_name(storage_backend_t *s, const char *n, role_t *r) { (void)s; (void)n; (void)r; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_role_update(storage_backend_t *s, const role_t *r) { (void)s; (void)r; return SSO_ERR_NOT_IMPLEMENTED; }

/* Group */
static sso_error_t postgres_stub_group_create(storage_backend_t *s, group_t *g) { (void)s; (void)g; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_group_get_id(storage_backend_t *s, sso_id_t id, group_t *g) { (void)s; (void)id; (void)g; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_group_get_name(storage_backend_t *s, const char *n, group_t *g) { (void)s; (void)n; (void)g; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_group_update(storage_backend_t *s, const group_t *g) { (void)s; (void)g; return SSO_ERR_NOT_IMPLEMENTED; }

/* Policy */
static sso_error_t postgres_stub_policy_create(storage_backend_t *s, policy_t *p) { (void)s; (void)p; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_policy_get_id(storage_backend_t *s, sso_id_t id, policy_t *p) { (void)s; (void)id; (void)p; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_policy_get_name(storage_backend_t *s, const char *n, policy_t *p) { (void)s; (void)n; (void)p; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_policy_update(storage_backend_t *s, const policy_t *p) { (void)s; (void)p; return SSO_ERR_NOT_IMPLEMENTED; }

/* Assignments */
static sso_error_t postgres_stub_assign_id_id(storage_backend_t *s, sso_id_t id1, sso_id_t id2) { (void)s; (void)id1; (void)id2; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_get_ids(storage_backend_t *s, sso_id_t id, sso_id_t *ids, size_t *c, size_t m) { (void)s; (void)id; (void)ids; (void)c; (void)m; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_assign_policy(storage_backend_t *s, sso_id_t id1, policy_target_type_t t, sso_id_t id2) { (void)s; (void)id1; (void)t; (void)id2; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_get_policy_targets(storage_backend_t *s, sso_id_t id, policy_target_type_t t, sso_id_t *ids, size_t *c, size_t m) { (void)s; (void)id; (void)t; (void)ids; (void)c; (void)m; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_get_target_policies(storage_backend_t *s, policy_target_type_t t, sso_id_t id, sso_id_t *ids, size_t *c, size_t m) { (void)s; (void)t; (void)id; (void)ids; (void)c; (void)m; return SSO_ERR_NOT_IMPLEMENTED; }

/* Hierarchy */
static sso_error_t postgres_stub_get_parent(storage_backend_t *s, sso_id_t id, sso_id_t *pid) { (void)s; (void)id; (void)pid; return SSO_ERR_NOT_IMPLEMENTED; }

/* OAuth */
static sso_error_t postgres_stub_oauth_code_create(storage_backend_t *s, const oauth_auth_code_t *c) { (void)s; (void)c; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_oauth_code_get(storage_backend_t *s, const char *c, oauth_auth_code_t *o) { (void)s; (void)c; (void)o; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_oauth_client_create(storage_backend_t *s, oauth_client_t *c) { (void)s; (void)c; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_oauth_client_get(storage_backend_t *s, const char *id, oauth_client_t *c) { (void)s; (void)id; (void)c; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_oauth_client_update(storage_backend_t *s, const oauth_client_t *c) { (void)s; (void)c; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_oauth_client_list(storage_backend_t *s, int o, int l, oauth_client_t *cs, size_t *c, size_t m) { (void)s; (void)o; (void)l; (void)cs; (void)c; (void)m; return SSO_ERR_NOT_IMPLEMENTED; }

/* Refresh Token */


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

/* ========================================================================
 * User CRUD
 * ======================================================================== */

static sso_error_t postgres_user_create(storage_backend_t *self, user_t *u) {
    if (!self || !u) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = (postgres_priv_t *)self->handle;

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
    postgres_priv_t *priv = (postgres_priv_t *)self->handle;

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
    postgres_priv_t *priv = (postgres_priv_t *)self->handle;

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

/* ========================================================================
 * Refresh Token storage
 * ======================================================================== */

static sso_error_t postgres_rt_create(storage_backend_t *self, const refresh_token_t *rt) {
    if (!self || !rt) return SSO_ERR_INVALID_PARAM;
    postgres_priv_t *priv = (postgres_priv_t *)self->handle;

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
    postgres_priv_t *priv = (postgres_priv_t *)self->handle;

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
    postgres_priv_t *priv = (postgres_priv_t *)self->handle;

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
    (*backend)->open       = postgres_open;
    (*backend)->close      = postgres_close;
    (*backend)->begin      = postgres_stub_err;
    (*backend)->commit     = postgres_stub_err;
    (*backend)->rollback   = postgres_stub_err;

    /* User */
    (*backend)->user_create       = postgres_user_create;
    (*backend)->user_get_by_id    = postgres_user_get_by_id;
    (*backend)->user_get_by_name  = postgres_user_get_by_name;
    (*backend)->user_get_by_phone = postgres_stub_user_get_name;
    (*backend)->user_update       = postgres_stub_user_update;
    (*backend)->user_delete       = postgres_stub_id;
    (*backend)->user_list         = postgres_stub_list;

    /* SMS */
    (*backend)->save_sms_code     = postgres_stub_sms_save;
    (*backend)->get_sms_code      = postgres_stub_sms_get;
    (*backend)->delete_sms_code   = postgres_stub_pchar;

    /* Role */
    (*backend)->role_create       = postgres_stub_role_create;
    (*backend)->role_get_by_id    = postgres_stub_role_get_id;
    (*backend)->role_get_by_name  = postgres_stub_role_get_name;
    (*backend)->role_update       = postgres_stub_role_update;
    (*backend)->role_delete       = postgres_stub_id;
    (*backend)->role_list         = postgres_stub_list;

    /* Group */
    (*backend)->group_create      = postgres_stub_group_create;
    (*backend)->group_get_by_id   = postgres_stub_group_get_id;
    (*backend)->group_get_by_name = postgres_stub_group_get_name;
    (*backend)->group_update      = postgres_stub_group_update;
    (*backend)->group_delete      = postgres_stub_id;
    (*backend)->group_list        = postgres_stub_list;

    /* Policy */
    (*backend)->policy_create      = postgres_stub_policy_create;
    (*backend)->policy_get_by_id   = postgres_stub_policy_get_id;
    (*backend)->policy_get_by_name = postgres_stub_policy_get_name;
    (*backend)->policy_update      = postgres_stub_policy_update;
    (*backend)->policy_delete      = postgres_stub_id;
    (*backend)->policy_list        = postgres_stub_list;

    /* Assignments */
    (*backend)->assign_role_to_user     = postgres_stub_assign_id_id;
    (*backend)->unassign_role_from_user = postgres_stub_assign_id_id;
    (*backend)->get_user_roles           = postgres_stub_get_ids;
    (*backend)->get_role_users           = postgres_stub_get_ids;

    (*backend)->assign_role_to_group     = postgres_stub_assign_id_id;
    (*backend)->unassign_role_from_group   = postgres_stub_assign_id_id;

    (*backend)->add_user_to_group        = postgres_stub_assign_id_id;
    (*backend)->remove_user_from_group   = postgres_stub_assign_id_id;
    (*backend)->get_user_groups          = postgres_stub_get_ids;
    (*backend)->get_group_users          = postgres_stub_get_ids;

    (*backend)->assign_policy            = postgres_stub_assign_policy;
    (*backend)->unassign_policy          = postgres_stub_assign_policy;
    (*backend)->get_policy_targets       = postgres_stub_get_policy_targets;
    (*backend)->get_target_policies      = postgres_stub_get_target_policies;

    /* Hierarchy */
    (*backend)->role_get_parent               = postgres_stub_get_parent;
    (*backend)->group_get_parent              = postgres_stub_get_parent;
    (*backend)->get_user_roles_with_ancestors = postgres_stub_get_ids;

    /* OAuth authorization codes */
    (*backend)->oauth_code_create    = postgres_stub_oauth_code_create;
    (*backend)->oauth_code_get       = postgres_stub_oauth_code_get;
    (*backend)->oauth_code_mark_used = postgres_stub_pchar;
    (*backend)->oauth_code_cleanup   = postgres_stub_err;

    (*backend)->oauth_client_create  = postgres_stub_oauth_client_create;
    (*backend)->oauth_client_get     = postgres_stub_oauth_client_get;
    (*backend)->oauth_client_update  = postgres_stub_oauth_client_update;
    (*backend)->oauth_client_delete  = postgres_stub_pchar;
    (*backend)->oauth_client_list    = postgres_stub_oauth_client_list;

    (*backend)->refresh_token_create = postgres_rt_create;
    (*backend)->refresh_token_get    = postgres_rt_get;
    (*backend)->refresh_token_revoke = postgres_rt_revoke;

    return SSO_OK;
}
