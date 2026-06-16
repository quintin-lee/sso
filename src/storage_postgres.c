#include "storage.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include <libpq-fe.h>
#include <stdlib.h>
#include <string.h>

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
static sso_error_t postgres_stub_user_create(storage_backend_t *s, user_t *u) { (void)s; (void)u; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_user_get_id(storage_backend_t *s, sso_id_t id, user_t *u) { (void)s; (void)id; (void)u; return SSO_ERR_NOT_IMPLEMENTED; }
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
static sso_error_t postgres_stub_rt_create(storage_backend_t *s, const refresh_token_t *rt) { (void)s; (void)rt; return SSO_ERR_NOT_IMPLEMENTED; }
static sso_error_t postgres_stub_rt_get(storage_backend_t *s, const char *t, refresh_token_t *o) { (void)s; (void)t; (void)o; return SSO_ERR_NOT_IMPLEMENTED; }

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

    /* Lifecycle */
    (*backend)->open       = postgres_open;
    (*backend)->close      = postgres_close;
    (*backend)->begin      = postgres_stub_err;
    (*backend)->commit     = postgres_stub_err;
    (*backend)->rollback   = postgres_stub_err;

    /* User */
    (*backend)->user_create       = postgres_stub_user_create;
    (*backend)->user_get_by_id    = postgres_stub_user_get_id;
    (*backend)->user_get_by_name  = postgres_stub_user_get_name;
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

    (*backend)->refresh_token_create = postgres_stub_rt_create;
    (*backend)->refresh_token_get    = postgres_stub_rt_get;
    (*backend)->refresh_token_revoke = postgres_stub_pchar;

    return SSO_OK;
}
