/*
 * storage_sqlite.c — SQLite storage backend.
 *
 * Implements the full storage_backend vtable using SQLite3.
 * Auto-creates tables on first open.
 *
 * Schema:
 *   users(id INTEGER PK, username UNIQUE, password_hash, email,
 *         display_name, status, created_at, updated_at, attributes)
 *
 *   roles(id INTEGER PK, name UNIQUE, description, parent_role_id,
 *         created_at, updated_at)
 *
 *   groups(id INTEGER PK, name UNIQUE, description, parent_group_id,
 *          created_at, updated_at)
 *
 *   policies(id INTEGER PK, name UNIQUE, strategy_type, effect, priority,
 *            rules, status, created_at, updated_at)
 *
 *   user_roles(user_id, role_id)         PK(user_id, role_id)
 *   user_groups(user_id, group_id)       PK(user_id, group_id)
 *   role_groups(role_id, group_id)       PK(role_id, group_id)
 *   policy_assignments(policy_id, target_type, target_id)
 *                                        PK(policy_id, target_type, target_id)
 */

#include "sso.h"
#include "storage.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sqlite3.h>

/* ========================================================================
 * Backend private data
 * ======================================================================== */
typedef struct {
    sqlite3 *db;
} sqlite_priv_t;

/* ========================================================================
 * Schema DDL
 * ======================================================================== */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS users ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  username TEXT UNIQUE,"
    "  phone TEXT UNIQUE,"
    "  password_hash TEXT,"
    "  email TEXT DEFAULT '',"
    "  display_name TEXT DEFAULT '',"
    "  status INTEGER DEFAULT 1,"
    "  created_at INTEGER DEFAULT 0,"
    "  updated_at INTEGER DEFAULT 0,"
    "  attributes TEXT DEFAULT '{}'"
    ");"

    "CREATE TABLE IF NOT EXISTS sms_codes ("
    "  phone TEXT PRIMARY KEY,"
    "  code TEXT NOT NULL,"
    "  expires_at INTEGER NOT NULL,"
    "  attempts INTEGER DEFAULT 0"
    ");"

    "CREATE TABLE IF NOT EXISTS roles ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name TEXT UNIQUE NOT NULL,"
    "  description TEXT DEFAULT '',"
    "  parent_role_id INTEGER DEFAULT 0,"
    "  created_at INTEGER DEFAULT 0,"
    "  updated_at INTEGER DEFAULT 0"
    ");"

    "CREATE TABLE IF NOT EXISTS groups_t ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name TEXT UNIQUE NOT NULL,"
    "  description TEXT DEFAULT '',"
    "  parent_group_id INTEGER DEFAULT 0,"
    "  created_at INTEGER DEFAULT 0,"
    "  updated_at INTEGER DEFAULT 0"
    ");"

    "CREATE TABLE IF NOT EXISTS policies ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name TEXT UNIQUE NOT NULL,"
    "  strategy_type INTEGER NOT NULL,"
    "  effect INTEGER NOT NULL DEFAULT 1,"
    "  priority INTEGER NOT NULL DEFAULT 0,"
    "  rules TEXT NOT NULL DEFAULT '{}',"
    "  status INTEGER NOT NULL DEFAULT 1,"
    "  created_at INTEGER DEFAULT 0,"
    "  updated_at INTEGER DEFAULT 0"
    ");"

    "CREATE TABLE IF NOT EXISTS user_roles ("
    "  user_id INTEGER NOT NULL,"
    "  role_id INTEGER NOT NULL,"
    "  PRIMARY KEY (user_id, role_id)"
    ");"

    "CREATE TABLE IF NOT EXISTS user_groups ("
    "  user_id INTEGER NOT NULL,"
    "  group_id INTEGER NOT NULL,"
    "  PRIMARY KEY (user_id, group_id)"
    ");"

    "CREATE TABLE IF NOT EXISTS role_groups ("
    "  role_id INTEGER NOT NULL,"
    "  group_id INTEGER NOT NULL,"
    "  PRIMARY KEY (role_id, group_id)"
    ");"

    "CREATE TABLE IF NOT EXISTS policy_assignments ("
    "  policy_id INTEGER NOT NULL,"
    "  target_type INTEGER NOT NULL,"
    "  target_id INTEGER NOT NULL,"
    "  PRIMARY KEY (policy_id, target_type, target_id)"
    ");";

/* ========================================================================
 * Generic binding helpers
 * ======================================================================== */

/* Bind a user_t to a prepared INSERT statement (indices 1-9). */
static void bind_user(sqlite3_stmt *stmt, const user_t *u) {
    if (u->username[0] != '\0')
        sqlite3_bind_text(stmt, 1, u->username, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 1);

    if (u->phone[0] != '\0')
        sqlite3_bind_text(stmt, 2, u->phone, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 2);

    sqlite3_bind_text(stmt, 3, u->password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, u->email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, u->display_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, u->status);
    sqlite3_bind_int64(stmt, 7, u->created_at);
    sqlite3_bind_int64(stmt, 8, u->updated_at);
    sqlite3_bind_text(stmt, 9, u->attributes, -1, SQLITE_STATIC);
}

/* Read columns into a user_t (indices 0-9). */
static void read_user(sqlite3_stmt *stmt, user_t *u) {
    memset(u, 0, sizeof(*u));
    u->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
    const char *username = (const char *)sqlite3_column_text(stmt, 1);
    if (username) strncpy(u->username, username, SSO_MAX_USERNAME - 1);
    const char *phone = (const char *)sqlite3_column_text(stmt, 2);
    if (phone) strncpy(u->phone, phone, SSO_MAX_PHONE - 1);
    const char *phash = (const char *)sqlite3_column_text(stmt, 3);
    if (phash) strncpy(u->password_hash, phash, SSO_MAX_PASSWORD_HASH - 1);
    const char *email = (const char *)sqlite3_column_text(stmt, 4);
    if (email) strncpy(u->email, email, SSO_MAX_EMAIL - 1);
    const char *disp = (const char *)sqlite3_column_text(stmt, 5);
    if (disp) strncpy(u->display_name, disp, SSO_MAX_DISPLAY_NAME - 1);
    u->status = (user_status_t)sqlite3_column_int(stmt, 6);
    u->created_at = sqlite3_column_int64(stmt, 7);
    u->updated_at = sqlite3_column_int64(stmt, 8);
    const char *attrs = (const char *)sqlite3_column_text(stmt, 9);
    if (attrs) strncpy(u->attributes, attrs, SSO_MAX_ATTRIBUTES - 1);
}

/* Similar for role, group, policy — in production, factor out with macros. */
static void bind_role(sqlite3_stmt *stmt, const role_t *r) {
    sqlite3_bind_text(stmt, 1, r->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, r->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, r->parent_role_id);
    sqlite3_bind_int64(stmt, 4, r->created_at);
    sqlite3_bind_int64(stmt, 5, r->updated_at);
}

static void read_role(sqlite3_stmt *stmt, role_t *r) {
    memset(r, 0, sizeof(*r));
    r->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
    strncpy(r->name, (const char *)sqlite3_column_text(stmt, 1), SSO_MAX_ROLE_NAME - 1);
    strncpy(r->description, (const char *)sqlite3_column_text(stmt, 2), SSO_MAX_DESCRIPTION - 1);
    r->parent_role_id = (sso_id_t)sqlite3_column_int64(stmt, 3);
    r->created_at = sqlite3_column_int64(stmt, 4);
    r->updated_at = sqlite3_column_int64(stmt, 5);
}

static void bind_group(sqlite3_stmt *stmt, const group_t *g) {
    sqlite3_bind_text(stmt, 1, g->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, g->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, g->parent_group_id);
    sqlite3_bind_int64(stmt, 4, g->created_at);
    sqlite3_bind_int64(stmt, 5, g->updated_at);
}

static void read_group(sqlite3_stmt *stmt, group_t *g) {
    memset(g, 0, sizeof(*g));
    g->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
    strncpy(g->name, (const char *)sqlite3_column_text(stmt, 1), SSO_MAX_GROUP_NAME - 1);
    strncpy(g->description, (const char *)sqlite3_column_text(stmt, 2), SSO_MAX_DESCRIPTION - 1);
    g->parent_group_id = (sso_id_t)sqlite3_column_int64(stmt, 3);
    g->created_at = sqlite3_column_int64(stmt, 4);
    g->updated_at = sqlite3_column_int64(stmt, 5);
}

static void bind_policy(sqlite3_stmt *stmt, const policy_t *p) {
    sqlite3_bind_text(stmt, 1, p->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, p->strategy_type);
    sqlite3_bind_int(stmt, 3, p->effect);
    sqlite3_bind_int(stmt, 4, p->priority);
    sqlite3_bind_text(stmt, 5, p->rules, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, p->status);
    sqlite3_bind_int64(stmt, 7, p->created_at);
    sqlite3_bind_int64(stmt, 8, p->updated_at);
}

static void read_policy(sqlite3_stmt *stmt, policy_t *p) {
    memset(p, 0, sizeof(*p));
    p->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
    strncpy(p->name, (const char *)sqlite3_column_text(stmt, 1), SSO_MAX_POLICY_NAME - 1);
    p->strategy_type = (perm_strategy_type_t)sqlite3_column_int(stmt, 2);
    p->effect = (policy_effect_t)sqlite3_column_int(stmt, 3);
    p->priority = sqlite3_column_int(stmt, 4);
    const char *rules = (const char *)sqlite3_column_text(stmt, 5);
    if (rules) strncpy(p->rules, rules, SSO_MAX_RULES_JSON - 1);
    p->status = (policy_status_t)sqlite3_column_int(stmt, 6);
    p->created_at = sqlite3_column_int64(stmt, 7);
    p->updated_at = sqlite3_column_int64(stmt, 8);
}

/* ========================================================================
 * Prepared statement helper
 * ======================================================================== */
#define PREP(db, sql, stmt) \
    sqlite3_prepare_v2(db, sql, -1, stmt, NULL)

#define STEP(stmt) \
    sqlite3_step(stmt)

#define FINALIZE(stmt) \
    sqlite3_finalize(stmt)

#define COL_ID(stmt, col) \
    ((sso_id_t)sqlite3_column_int64(stmt, col))

/* ========================================================================
 * vtable implementations
 * ======================================================================== */

/* --- open --- */
static sso_error_t sqlite_open(storage_backend_t *self, const char *dsn) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv) return SSO_ERR_INVALID_PARAM;

    int rc = sqlite3_open(dsn, &priv->db);
    if (rc != SQLITE_OK) {
        return SSO_ERR_STORAGE;
    }

    /* Performance optimization: WAL mode + NORMAL synchronous */
    sqlite3_exec(priv->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(priv->db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    /* Create tables */
    char *errmsg = NULL;
    rc = sqlite3_exec(priv->db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        sqlite3_close(priv->db);
        priv->db = NULL;
        return SSO_ERR_STORAGE;
    }

    return SSO_OK;
}

/* --- close --- */
static void sqlite_close(storage_backend_t *self) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (priv && priv->db) {
        /* Merge WAL into main database and truncate log for safety */
        sqlite3_exec(priv->db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
        sqlite3_close(priv->db);
        priv->db = NULL;
    }
}

/* ========================================================================
 * User CRUD
 * ======================================================================== */
static sso_error_t sqlite_user_create(storage_backend_t *self, user_t *user) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    const char *sql = "INSERT INTO users (username, phone, password_hash, email, display_name, "
                      "status, created_at, updated_at, attributes) "
                      "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return SSO_ERR_STORAGE;
    }

    bind_user(stmt, user);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_CONSTRAINT) {
        sqlite3_finalize(stmt);
        return SSO_ERR_ALREADY_EXISTS;
    }
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return SSO_ERR_STORAGE;
    }

    sso_id_t id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
    sqlite3_finalize(stmt);

    /* Update the user struct with the assigned ID (hack: cast away const — caller owns it) */
    user->id = id;
    return SSO_OK;
}

#define MAKE_GETTER(type, type_name, table, reader) \
static sso_error_t sqlite_##type_name##_get_by_id(storage_backend_t *self, sso_id_t id, type##_t *out) { \
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle; \
    if (!priv || !priv->db) return SSO_ERR_STORAGE; \
    char sql[128]; \
    snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE id=?1", #table); \
    sqlite3_stmt *stmt = NULL; \
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) \
        return SSO_ERR_STORAGE; \
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id); \
    int rc = sqlite3_step(stmt); \
    if (rc != SQLITE_ROW) { \
        sqlite3_finalize(stmt); \
        return SSO_ERR_NOT_FOUND; \
    } \
    reader(stmt, out); \
    sqlite3_finalize(stmt); \
    return SSO_OK; \
}

/* Generate getter implementations */
MAKE_GETTER(user, user, users, read_user)
MAKE_GETTER(role, role, roles, read_role)
MAKE_GETTER(group, group, groups_t, read_group)
MAKE_GETTER(policy, policy, policies, read_policy)

/* --- user_get_by_name --- */
static sso_error_t sqlite_user_get_by_name(storage_backend_t *self, const char *name, user_t *out) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT * FROM users WHERE username=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return SSO_ERR_NOT_FOUND;
    }
    read_user(stmt, out);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

/* --- user_get_by_phone --- */
static sso_error_t sqlite_user_get_by_phone(storage_backend_t *self, const char *phone, user_t *out) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT * FROM users WHERE phone=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_text(stmt, 1, phone, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return SSO_ERR_NOT_FOUND;
    }
    read_user(stmt, out);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

#define MAKE_GET_BY_NAME(name_type, table, reader) \
static sso_error_t sqlite_##name_type##_get_by_name(storage_backend_t *self, const char *name, name_type##_t *out) { \
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle; \
    if (!priv || !priv->db) return SSO_ERR_STORAGE; \
    char sql[128]; \
    snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE name=?1", #table); \
    sqlite3_stmt *stmt = NULL; \
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) \
        return SSO_ERR_STORAGE; \
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC); \
    int rc = sqlite3_step(stmt); \
    if (rc != SQLITE_ROW) { \
        sqlite3_finalize(stmt); \
        return SSO_ERR_NOT_FOUND; \
    } \
    reader(stmt, out); \
    sqlite3_finalize(stmt); \
    return SSO_OK; \
}

MAKE_GET_BY_NAME(role, roles, read_role)
MAKE_GET_BY_NAME(group, groups_t, read_group)
MAKE_GET_BY_NAME(policy, policies, read_policy)

/* --- user_update --- */
static sso_error_t sqlite_user_update(storage_backend_t *self, const user_t *user) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE users SET phone=?1, password_hash=?2, email=?3, display_name=?4, "
                      "status=?5, updated_at=?6, attributes=?7 WHERE id=?8";
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, user->phone, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->password_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, user->email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, user->display_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, user->status);
    sqlite3_bind_int64(stmt, 6, user->updated_at);
    sqlite3_bind_text(stmt, 7, user->attributes, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)user->id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

/* --- user_delete --- */
#define MAKE_DELETE(table) \
static sso_error_t sqlite_##table##_delete(storage_backend_t *self, sso_id_t id) { \
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle; \
    if (!priv || !priv->db) return SSO_ERR_STORAGE; \
    char sql[128]; \
    snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE id=?1", #table); \
    sqlite3_stmt *stmt = NULL; \
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) \
        return SSO_ERR_STORAGE; \
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id); \
    int rc = sqlite3_step(stmt); \
    sqlite3_finalize(stmt); \
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE; \
}

MAKE_DELETE(users)
MAKE_DELETE(roles)
MAKE_DELETE(groups_t)
MAKE_DELETE(policies)

/* --- user_list --- */
#define MAKE_LIST(table, reader) \
static sso_error_t sqlite_##table##_list(storage_backend_t *self, sso_id_t *ids, size_t *count, size_t max) { \
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle; \
    if (!priv || !priv->db) return SSO_ERR_STORAGE; \
    char sql[128]; \
    snprintf(sql, sizeof(sql), "SELECT id FROM %s ORDER BY id", #table); \
    sqlite3_stmt *stmt = NULL; \
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) \
        return SSO_ERR_STORAGE; \
    size_t n = 0; \
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) { \
        ids[n++] = (sso_id_t)sqlite3_column_int64(stmt, 0); \
    } \
    *count = n; \
    sqlite3_finalize(stmt); \
    return SSO_OK; \
}

MAKE_LIST(users, read_user)
MAKE_LIST(roles, read_role)
MAKE_LIST(groups_t, read_group)
MAKE_LIST(policies, read_policy)

/* --- role/group update --- */
#define MAKE_UPDATE(table, set_clause, id_col) \
static sso_error_t sqlite_##table##_update(storage_backend_t *self, const table##_t *obj) { \
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle; \
    if (!priv || !priv->db) return SSO_ERR_STORAGE; \
    char sql[512]; \
    snprintf(sql, sizeof(sql), "UPDATE %s SET " set_clause " WHERE " id_col "=?%d", \
             #table, obj->id); \
    sqlite3_stmt *stmt = NULL; \
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) \
        return SSO_ERR_STORAGE; \
    int rc = sqlite3_step(stmt); \
    sqlite3_finalize(stmt); \
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE; \
}

/* Manual role update (simpler than macro for this case) */
static sso_error_t sqlite_role_update(storage_backend_t *self, const role_t *role) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE roles SET name=?1, description=?2, parent_role_id=?3, updated_at=?4 WHERE id=?5";
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, role->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, role->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)role->parent_role_id);
    sqlite3_bind_int64(stmt, 4, role->updated_at);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)role->id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_group_update(storage_backend_t *self, const group_t *group) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE groups_t SET name=?1, description=?2, parent_group_id=?3, updated_at=?4 WHERE id=?5";
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, group->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, group->description, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)group->parent_group_id);
    sqlite3_bind_int64(stmt, 4, group->updated_at);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)group->id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_policy_update(storage_backend_t *self, const policy_t *policy) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE policies SET name=?1, strategy_type=?2, effect=?3, "
                      "priority=?4, rules=?5, status=?6, updated_at=?7 WHERE id=?8";
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, policy->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, policy->strategy_type);
    sqlite3_bind_int(stmt, 3, policy->effect);
    sqlite3_bind_int(stmt, 4, policy->priority);
    sqlite3_bind_text(stmt, 5, policy->rules, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, policy->status);
    sqlite3_bind_int64(stmt, 7, policy->updated_at);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)policy->id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

/* --- role/group create --- */
static sso_error_t sqlite_role_create(storage_backend_t *self, role_t *role) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db,
            "INSERT INTO roles (name, description, parent_role_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5)",
            -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    bind_role(stmt, role);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_CONSTRAINT) { sqlite3_finalize(stmt); return SSO_ERR_ALREADY_EXISTS; }
    if (rc != SQLITE_DONE) { sqlite3_finalize(stmt); return SSO_ERR_STORAGE; }
    role->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

static sso_error_t sqlite_group_create(storage_backend_t *self, group_t *group) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db,
            "INSERT INTO groups_t (name, description, parent_group_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5)",
            -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    bind_group(stmt, group);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_CONSTRAINT) { sqlite3_finalize(stmt); return SSO_ERR_ALREADY_EXISTS; }
    if (rc != SQLITE_DONE) { sqlite3_finalize(stmt); return SSO_ERR_STORAGE; }
    group->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

static sso_error_t sqlite_policy_create(storage_backend_t *self, policy_t *policy) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db,
            "INSERT INTO policies (name, strategy_type, effect, priority, rules, status, created_at, updated_at) "
            "VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    bind_policy(stmt, policy);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_CONSTRAINT) { sqlite3_finalize(stmt); return SSO_ERR_ALREADY_EXISTS; }
    if (rc != SQLITE_DONE) { sqlite3_finalize(stmt); return SSO_ERR_STORAGE; }
    policy->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

/* ========================================================================
 * Assignment helpers
 * ======================================================================== */

/* Helper to execute a simple INSERT/DELETE with two ID bindings */
#define ASSIGN_SIMPLE2(sql_pattern, id1, id2) \
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle; \
    if (!priv || !priv->db) return SSO_ERR_STORAGE; \
    sqlite3_stmt *stmt = NULL; \
    char sql[128]; \
    snprintf(sql, sizeof(sql), sql_pattern); \
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) \
        return SSO_ERR_STORAGE; \
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id1); \
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)id2); \
    int rc = sqlite3_step(stmt); \
    sqlite3_finalize(stmt); \
    return (rc == SQLITE_DONE || rc == SQLITE_CONSTRAINT) ? SSO_OK : SSO_ERR_STORAGE;

static sso_error_t sqlite_assign_role_to_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    ASSIGN_SIMPLE2("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?1,?2)", user_id, role_id);
}
static sso_error_t sqlite_unassign_role_user(storage_backend_t *self, sso_id_t role_id, sso_id_t user_id) {
    ASSIGN_SIMPLE2("DELETE FROM user_roles WHERE user_id=?1 AND role_id=?2", user_id, role_id);
}
static sso_error_t sqlite_assign_role_to_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    ASSIGN_SIMPLE2("INSERT OR IGNORE INTO role_groups VALUES (?1,?2)", role_id, group_id);
}
static sso_error_t sqlite_unassign_role_group(storage_backend_t *self, sso_id_t role_id, sso_id_t group_id) {
    ASSIGN_SIMPLE2("DELETE FROM role_groups WHERE role_id=?1 AND group_id=?2", role_id, group_id);
}
static sso_error_t sqlite_add_user_to_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    ASSIGN_SIMPLE2("INSERT OR IGNORE INTO user_groups VALUES (?1,?2)", user_id, group_id);
}
static sso_error_t sqlite_remove_user_from_group(storage_backend_t *self, sso_id_t group_id, sso_id_t user_id) {
    ASSIGN_SIMPLE2("DELETE FROM user_groups WHERE user_id=?1 AND group_id=?2", user_id, group_id);
}

/* --- get_user_roles --- */
static sso_error_t sqlite_get_user_roles(storage_backend_t *self, sso_id_t user_id, sso_id_t *role_ids, size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT role_id FROM user_roles WHERE user_id=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user_id);

    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) {
        role_ids[n++] = COL_ID(stmt, 0);
    }
    *count = n;
    sqlite3_finalize(stmt);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* --- get_role_users --- */
static sso_error_t sqlite_get_role_users(storage_backend_t *self, sso_id_t role_id, sso_id_t *user_ids, size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT user_id FROM user_roles WHERE role_id=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)role_id);

    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) {
        user_ids[n++] = COL_ID(stmt, 0);
    }
    *count = n;
    sqlite3_finalize(stmt);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* --- get_user_groups --- */
static sso_error_t sqlite_get_user_groups(storage_backend_t *self, sso_id_t user_id, sso_id_t *group_ids, size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT group_id FROM user_groups WHERE user_id=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user_id);

    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) {
        group_ids[n++] = COL_ID(stmt, 0);
    }
    *count = n;
    sqlite3_finalize(stmt);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* --- get_group_users --- */
static sso_error_t sqlite_get_group_users(storage_backend_t *self, sso_id_t group_id, sso_id_t *user_ids, size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT user_id FROM user_groups WHERE group_id=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)group_id);

    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) {
        user_ids[n++] = COL_ID(stmt, 0);
    }
    *count = n;
    sqlite3_finalize(stmt);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* --- policy assignments --- */
static sso_error_t sqlite_assign_policy(storage_backend_t *self, sso_id_t policy_id,
                                        policy_target_type_t target_type, sso_id_t target_id) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db,
            "INSERT OR IGNORE INTO policy_assignments VALUES (?1,?2,?3)",
            -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)policy_id);
    sqlite3_bind_int(stmt, 2, (int)target_type);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)target_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE || rc == SQLITE_CONSTRAINT) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_unassign_policy(storage_backend_t *self, sso_id_t policy_id,
                                          policy_target_type_t target_type, sso_id_t target_id) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db,
            "DELETE FROM policy_assignments WHERE policy_id=?1 AND target_type=?2 AND target_id=?3",
            -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)policy_id);
    sqlite3_bind_int(stmt, 2, (int)target_type);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)target_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_get_policy_targets(storage_backend_t *self, sso_id_t policy_id,
                                              policy_target_type_t target_type,
                                              sso_id_t *target_ids, size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db,
            "SELECT target_id FROM policy_assignments WHERE policy_id=?1 AND target_type=?2",
            -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)policy_id);
    sqlite3_bind_int(stmt, 2, (int)target_type);

    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) {
        target_ids[n++] = COL_ID(stmt, 0);
    }
    *count = n;
    sqlite3_finalize(stmt);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

static sso_error_t sqlite_get_target_policies(storage_backend_t *self,
                                               policy_target_type_t target_type, sso_id_t target_id,
                                               sso_id_t *policy_ids, size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db,
            "SELECT policy_id FROM policy_assignments WHERE target_type=?1 AND target_id=?2",
            -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int(stmt, 1, (int)target_type);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)target_id);

    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) {
        policy_ids[n++] = COL_ID(stmt, 0);
    }
    *count = n;
    sqlite3_finalize(stmt);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* --- Hierarchy helpers --- */
static sso_error_t sqlite_role_get_parent(storage_backend_t *self, sso_id_t role_id, sso_id_t *parent_id) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT parent_role_id FROM roles WHERE id=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)role_id);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return SSO_ERR_NOT_FOUND; }
    *parent_id = COL_ID(stmt, 0);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

static sso_error_t sqlite_group_get_parent(storage_backend_t *self, sso_id_t group_id, sso_id_t *parent_id) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "SELECT parent_group_id FROM groups_t WHERE id=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)group_id);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return SSO_ERR_NOT_FOUND; }
    *parent_id = COL_ID(stmt, 0);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

/* --- get_user_roles_with_ancestors --- */
static sso_error_t sqlite_get_user_roles_with_ancestors(storage_backend_t *self,
                                                         sso_id_t user_id,
                                                         sso_id_t *role_ids,
                                                         size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    /* Use a recursive CTE to get all roles (directly assigned + inherited
     * through parent_role_id hierarchy) in a single query. */
    const char *sql =
        "WITH RECURSIVE user_role_tree(role_id) AS ("
        "  SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = ?1"
        "  UNION"
        "  SELECT r.parent_role_id FROM roles r"
        "  INNER JOIN user_role_tree ut ON r.id = ut.role_id"
        "  WHERE r.parent_role_id != 0"
        ")"
        "SELECT DISTINCT role_id FROM user_role_tree";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)user_id);

    size_t n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && n < max) {
        role_ids[n++] = COL_ID(stmt, 0);
    }
    *count = n;
    sqlite3_finalize(stmt);
    return n > 0 ? SSO_OK : SSO_ERR_NOT_FOUND;
}

/* ========================================================================
 * SMS Storage
 * ======================================================================== */

static sso_error_t sqlite_save_sms_code(storage_backend_t *self, const char *phone, const char *code, sso_timestamp_t expires_at) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    const char *sql = "INSERT INTO sms_codes (phone, code, expires_at, attempts) VALUES (?1, ?2, ?3, 0) "
                      "ON CONFLICT(phone) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at, attempts=0";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return SSO_ERR_STORAGE;
    }

    sqlite3_bind_text(stmt, 1, phone, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, code, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, expires_at);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_get_sms_code(storage_backend_t *self, const char *phone, char *code_out) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    const char *sql = "SELECT code, expires_at FROM sms_codes WHERE phone=?1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return SSO_ERR_STORAGE;
    }

    sqlite3_bind_text(stmt, 1, phone, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return SSO_ERR_NOT_FOUND;
    }

    sso_timestamp_t expires_at = sqlite3_column_int64(stmt, 1);
    if (sso_timestamp_now() > expires_at) {
        sqlite3_finalize(stmt);
        return SSO_ERR_TOKEN_EXPIRED; /* Reusing token expired error */
    }

    const char *code = (const char *)sqlite3_column_text(stmt, 0);
    if (code) {
        strncpy(code_out, code, 15);
        code_out[15] = '\0';
    } else {
        code_out[0] = '\0';
    }

    sqlite3_finalize(stmt);
    return SSO_OK;
}

static sso_error_t sqlite_delete_sms_code(storage_backend_t *self, const char *phone) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    if (!priv || !priv->db) return SSO_ERR_STORAGE;

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(priv->db, "DELETE FROM sms_codes WHERE phone=?1", -1, &stmt, NULL) != SQLITE_OK)
        return SSO_ERR_STORAGE;

    sqlite3_bind_text(stmt, 1, phone, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

/* ========================================================================
 * Backend constructor
 * ======================================================================== */
sso_error_t storage_sqlite_create(storage_backend_t **backend) {
    if (!backend) return SSO_ERR_INVALID_PARAM;

    *backend = (storage_backend_t *)calloc(1, sizeof(storage_backend_t));
    if (!*backend) return SSO_ERR_OUT_OF_MEMORY;

    sqlite_priv_t *priv = (sqlite_priv_t *)calloc(1, sizeof(sqlite_priv_t));
    if (!priv) {
        free(*backend);
        *backend = NULL;
        return SSO_ERR_OUT_OF_MEMORY;
    }

    (*backend)->handle = priv;
    strncpy((*backend)->name, "sqlite", sizeof((*backend)->name) - 1);

    /* Lifecycle */
    (*backend)->open       = sqlite_open;
    (*backend)->close      = sqlite_close;

    /* User */
    (*backend)->user_create       = sqlite_user_create;
    (*backend)->user_get_by_id    = sqlite_user_get_by_id;
    (*backend)->user_get_by_name  = sqlite_user_get_by_name;
    (*backend)->user_get_by_phone = sqlite_user_get_by_phone;
    (*backend)->user_update       = sqlite_user_update;
    (*backend)->user_delete       = sqlite_users_delete;
    (*backend)->user_list         = sqlite_users_list;

    /* SMS */
    (*backend)->save_sms_code     = sqlite_save_sms_code;
    (*backend)->get_sms_code      = sqlite_get_sms_code;
    (*backend)->delete_sms_code   = sqlite_delete_sms_code;

    /* Role */
    (*backend)->role_create       = sqlite_role_create;
    (*backend)->role_get_by_id    = sqlite_role_get_by_id;
    (*backend)->role_get_by_name  = sqlite_role_get_by_name;
    (*backend)->role_update       = sqlite_role_update;
    (*backend)->role_delete       = sqlite_roles_delete;
    (*backend)->role_list         = sqlite_roles_list;

    /* Group */
    (*backend)->group_create      = sqlite_group_create;
    (*backend)->group_get_by_id   = sqlite_group_get_by_id;
    (*backend)->group_get_by_name = sqlite_group_get_by_name;
    (*backend)->group_update      = sqlite_group_update;
    (*backend)->group_delete      = sqlite_groups_t_delete;
    (*backend)->group_list        = sqlite_groups_t_list;

    /* Policy */
    (*backend)->policy_create       = sqlite_policy_create;
    (*backend)->policy_get_by_id    = sqlite_policy_get_by_id;
    (*backend)->policy_get_by_name  = sqlite_policy_get_by_name;
    (*backend)->policy_update       = sqlite_policy_update;
    (*backend)->policy_delete       = sqlite_policies_delete;
    (*backend)->policy_list         = sqlite_policies_list;

    /* Assignments */
    (*backend)->assign_role_to_user       = sqlite_assign_role_to_user;
    (*backend)->unassign_role_from_user   = sqlite_unassign_role_user;
    (*backend)->get_user_roles            = sqlite_get_user_roles;
    (*backend)->get_role_users            = sqlite_get_role_users;
    (*backend)->assign_role_to_group      = sqlite_assign_role_to_group;
    (*backend)->unassign_role_from_group  = sqlite_unassign_role_group;
    (*backend)->add_user_to_group         = sqlite_add_user_to_group;
    (*backend)->remove_user_from_group    = sqlite_remove_user_from_group;
    (*backend)->get_user_groups           = sqlite_get_user_groups;
    (*backend)->get_group_users           = sqlite_get_group_users;
    (*backend)->assign_policy             = sqlite_assign_policy;
    (*backend)->unassign_policy           = sqlite_unassign_policy;
    (*backend)->get_policy_targets        = sqlite_get_policy_targets;
    (*backend)->get_target_policies       = sqlite_get_target_policies;

    /* Hierarchy */
    (*backend)->role_get_parent                 = sqlite_role_get_parent;
    (*backend)->group_get_parent                = sqlite_group_get_parent;
    (*backend)->get_user_roles_with_ancestors   = sqlite_get_user_roles_with_ancestors;

    (*backend)->handle = priv;
    return SSO_OK;
}
