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
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sqlite3.h>

#include <pthread.h>
#include <strings.h>

typedef struct {
	sqlite3* db;
	char	 dsn[SSO_MAX_PATH];
} sqlite_priv_t;

static _Thread_local sqlite3* t_read_db = NULL;
static pthread_key_t		  g_sqlite_key;
static pthread_once_t		  g_sqlite_key_once = PTHREAD_ONCE_INIT;

static void sqlite_db_destructor(void* ptr) {
	sqlite3* db = (sqlite3*)ptr;
	if (db) {
		sqlite3_close(db);
	}
}

static void init_sqlite_key(void) {
	pthread_key_create(&g_sqlite_key, sqlite_db_destructor);
}

#include <time.h>

static inline sqlite3* sqlite_route_conn(sqlite3* db, const char* sql) {
	if (!sql || !t_read_db)
		return db;
	const char* p = sql;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;
	if (strncasecmp(p, "SELECT", 6) == 0) {
		return t_read_db;
	}
	return db;
}

static inline uint64_t get_time_us(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + (ts.tv_nsec / 1000);
}

static inline int wrapped_sqlite3_prepare_v2(sqlite3* db, const char* sql, int len, sqlite3_stmt** stmt,
											 const char** tail) {
	sqlite3* routed	  = sqlite_route_conn(db, sql);
	bool	 is_read  = (routed == t_read_db);
	uint64_t start	  = get_time_us();
	int		 rc		  = (sqlite3_prepare_v2)(routed, sql, len, stmt, tail);
	uint64_t duration = get_time_us() - start;
	if (is_read) {
		atomic_fetch_add(&g_metric_db_read_count, 1);
		atomic_fetch_add(&g_metric_db_read_duration_us, duration);
	} else {
		atomic_fetch_add(&g_metric_db_write_count, 1);
		atomic_fetch_add(&g_metric_db_write_duration_us, duration);
	}
	return rc;
}

static inline int wrapped_sqlite3_exec(sqlite3* db, const char* sql, int (*callback)(void*, int, char**, char**),
									   void* arg, char** errmsg) {
	sqlite3* routed	  = sqlite_route_conn(db, sql);
	bool	 is_read  = (routed == t_read_db);
	uint64_t start	  = get_time_us();
	int		 rc		  = (sqlite3_exec)(routed, sql, callback, arg, errmsg);
	uint64_t duration = get_time_us() - start;
	if (is_read) {
		atomic_fetch_add(&g_metric_db_read_count, 1);
		atomic_fetch_add(&g_metric_db_read_duration_us, duration);
	} else {
		atomic_fetch_add(&g_metric_db_write_count, 1);
		atomic_fetch_add(&g_metric_db_write_duration_us, duration);
	}
	return rc;
}

#undef sqlite3_prepare_v2
#define sqlite3_prepare_v2 wrapped_sqlite3_prepare_v2

#undef sqlite3_exec
#define sqlite3_exec wrapped_sqlite3_exec

/* ========================================================================
 * Schema DDL
 * ======================================================================== */
static const char* SCHEMA_SQL = "CREATE TABLE IF NOT EXISTS users ("
								"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
								"  username TEXT UNIQUE,"
								"  phone TEXT UNIQUE,"
								"  password_hash TEXT,"
								"  email TEXT DEFAULT '',"
								"  display_name TEXT DEFAULT '',"
								"  status INTEGER DEFAULT 1,"
								"  created_at INTEGER DEFAULT 0,"
								"  updated_at INTEGER DEFAULT 0,"
								"  password_set_at INTEGER DEFAULT 0,"
								"  attributes TEXT DEFAULT '{}',"
								"  mfa_enabled INTEGER DEFAULT 0,"
								"  mfa_secret TEXT DEFAULT ''"
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
								"  status INTEGER DEFAULT 1,"
								"  created_at INTEGER DEFAULT 0,"
								"  updated_at INTEGER DEFAULT 0"
								");"

								"CREATE TABLE IF NOT EXISTS groups_t ("
								"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
								"  name TEXT UNIQUE NOT NULL,"
								"  description TEXT DEFAULT '',"
								"  parent_group_id INTEGER DEFAULT 0,"
								"  status INTEGER DEFAULT 1,"
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
								"  policy_id INTEGER,"
								"  target_type INTEGER,"
								"  target_id INTEGER,"
								"  PRIMARY KEY(policy_id, target_type, target_id)"
								");"

								"CREATE TABLE IF NOT EXISTS oauth_auth_codes ("
								"  code TEXT PRIMARY KEY,"
								"  client_id TEXT NOT NULL,"
								"  user_id INTEGER NOT NULL,"
								"  redirect_uri TEXT NOT NULL,"
								"  scope TEXT DEFAULT '',"
								"  nonce TEXT DEFAULT '',"
								"  code_challenge TEXT DEFAULT '',"
								"  code_challenge_method TEXT DEFAULT '',"
								"  expires_at INTEGER NOT NULL,"
								"  used INTEGER DEFAULT 0"
								");"

								"CREATE TABLE IF NOT EXISTS oauth_clients ("
								"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
								"  client_id TEXT UNIQUE NOT NULL,"
								"  client_secret_hash TEXT NOT NULL,"
								"  redirect_uris TEXT NOT NULL,"
								"  app_name TEXT DEFAULT '',"
								"  app_description TEXT DEFAULT '',"
								"  app_logo_url TEXT DEFAULT '',"
								"  allowed_scopes TEXT DEFAULT '',"
								"  allowed_grant_types TEXT DEFAULT '',"
								"  token_ttl_ms INTEGER DEFAULT 0,"
								"  status INTEGER DEFAULT 1,"
								"  created_at INTEGER DEFAULT 0,"
								"  updated_at INTEGER DEFAULT 0"
								");"

								"CREATE TABLE IF NOT EXISTS refresh_tokens ("
								"  token_hash TEXT PRIMARY KEY,"
								"  user_id INTEGER NOT NULL,"
								"  client_id TEXT,"
								"  expires_at INTEGER NOT NULL,"
								"  issued_at INTEGER NOT NULL,"
								"  revoked INTEGER DEFAULT 0"
								");"

								"CREATE TABLE IF NOT EXISTS revoked_jtis ("
								"  jti TEXT PRIMARY KEY,"
								"  expires_at INTEGER NOT NULL"
								");"

								"CREATE TABLE IF NOT EXISTS audit_logs ("
								"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
								"  action TEXT,"
								"  timestamp_ms INTEGER,"
								"  user_id INTEGER,"
								"  username TEXT,"
								"  ip_address TEXT,"
								"  operation TEXT,"
								"  resource TEXT,"
								"  resource_id INTEGER,"
								"  status TEXT,"
								"  details TEXT,"
								"  duration_ms INTEGER,"
								"  cache_hit INTEGER,"
								"  trace TEXT"
								");";

/* ========================================================================
 * Generic binding helpers
 * ======================================================================== */

/* Bind a user_t to a prepared INSERT statement (indices 1-12). */
static void bind_user(sqlite3_stmt* stmt, const user_t* u) {
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
	sqlite3_bind_int(stmt, 10, u->mfa_enabled);
	sqlite3_bind_text(stmt, 11, u->mfa_secret, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 12, u->password_set_at);
}

/* Read columns into a user_t (indices 0-12). */
static void read_user(sqlite3_stmt* stmt, user_t* u) {
	memset(u, 0, sizeof(*u));
	u->id				 = (sso_id_t)sqlite3_column_int64(stmt, 0);
	const char* username = (const char*)sqlite3_column_text(stmt, 1);
	if (username)
		sso_strlcpy(u->username, username, SSO_MAX_USERNAME);
	const char* phone = (const char*)sqlite3_column_text(stmt, 2);
	if (phone)
		sso_strlcpy(u->phone, phone, SSO_MAX_PHONE);
	const char* phash = (const char*)sqlite3_column_text(stmt, 3);
	if (phash)
		sso_strlcpy(u->password_hash, phash, SSO_MAX_PASSWORD_HASH);
	const char* email = (const char*)sqlite3_column_text(stmt, 4);
	if (email)
		sso_strlcpy(u->email, email, SSO_MAX_EMAIL);
	const char* disp = (const char*)sqlite3_column_text(stmt, 5);
	if (disp)
		sso_strlcpy(u->display_name, disp, SSO_MAX_DISPLAY_NAME);
	u->status		  = (user_status_t)sqlite3_column_int(stmt, 6);
	u->created_at	  = sqlite3_column_int64(stmt, 7);
	u->updated_at	  = sqlite3_column_int64(stmt, 8);
	const char* attrs = (const char*)sqlite3_column_text(stmt, 9);
	if (attrs)
		sso_strlcpy(u->attributes, attrs, SSO_MAX_ATTRIBUTES);
	u->mfa_enabled	= sqlite3_column_int(stmt, 10);
	const char* sec = (const char*)sqlite3_column_text(stmt, 11);
	if (sec)
		sso_strlcpy(u->mfa_secret, sec, sizeof(u->mfa_secret));
	u->password_set_at = sqlite3_column_int64(stmt, 12);
}

/* Similar for role, group, policy — in production, factor out with macros. */
static void bind_role(sqlite3_stmt* stmt, const role_t* r) {
	sqlite3_bind_text(stmt, 1, r->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, r->description, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, r->parent_role_id);
	sqlite3_bind_int(stmt, 4, r->status);
	sqlite3_bind_int64(stmt, 5, r->created_at);
	sqlite3_bind_int64(stmt, 6, r->updated_at);
}

static void read_role(sqlite3_stmt* stmt, role_t* r) {
	memset(r, 0, sizeof(*r));
	r->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
	sso_strlcpy(r->name, (const char*)sqlite3_column_text(stmt, 1), SSO_MAX_ROLE_NAME);
	sso_strlcpy(r->description, (const char*)sqlite3_column_text(stmt, 2), SSO_MAX_DESCRIPTION);
	r->parent_role_id = (sso_id_t)sqlite3_column_int64(stmt, 3);
	r->status		  = (role_status_t)sqlite3_column_int(stmt, 4);
	r->created_at	  = sqlite3_column_int64(stmt, 5);
	r->updated_at	  = sqlite3_column_int64(stmt, 6);
}

static void bind_group(sqlite3_stmt* stmt, const group_t* g) {
	sqlite3_bind_text(stmt, 1, g->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, g->description, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, g->parent_group_id);
	sqlite3_bind_int(stmt, 4, g->status);
	sqlite3_bind_int64(stmt, 5, g->created_at);
	sqlite3_bind_int64(stmt, 6, g->updated_at);
}

static void read_group(sqlite3_stmt* stmt, group_t* g) {
	memset(g, 0, sizeof(*g));
	g->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
	sso_strlcpy(g->name, (const char*)sqlite3_column_text(stmt, 1), SSO_MAX_GROUP_NAME);
	sso_strlcpy(g->description, (const char*)sqlite3_column_text(stmt, 2), SSO_MAX_DESCRIPTION);
	g->parent_group_id = (sso_id_t)sqlite3_column_int64(stmt, 3);
	g->status		   = (group_status_t)sqlite3_column_int(stmt, 4);
	g->created_at	   = sqlite3_column_int64(stmt, 5);
	g->updated_at	   = sqlite3_column_int64(stmt, 6);
}

static void bind_policy(sqlite3_stmt* stmt, const policy_t* p) {
	sqlite3_bind_text(stmt, 1, p->name, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, p->strategy_type);
	sqlite3_bind_int(stmt, 3, p->effect);
	sqlite3_bind_int(stmt, 4, p->priority);
	sqlite3_bind_text(stmt, 5, p->rules, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 6, p->status);
	sqlite3_bind_int64(stmt, 7, p->created_at);
	sqlite3_bind_int64(stmt, 8, p->updated_at);
}

static void read_policy(sqlite3_stmt* stmt, policy_t* p) {
	memset(p, 0, sizeof(*p));
	p->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
	sso_strlcpy(p->name, (const char*)sqlite3_column_text(stmt, 1), SSO_MAX_POLICY_NAME);
	p->strategy_type  = (perm_strategy_type_t)sqlite3_column_int(stmt, 2);
	p->effect		  = (policy_effect_t)sqlite3_column_int(stmt, 3);
	p->priority		  = sqlite3_column_int(stmt, 4);
	const char* rules = (const char*)sqlite3_column_text(stmt, 5);
	if (rules)
		sso_strlcpy(p->rules, rules, SSO_MAX_RULES_JSON);
	p->status	  = (policy_status_t)sqlite3_column_int(stmt, 6);
	p->created_at = sqlite3_column_int64(stmt, 7);
	p->updated_at = sqlite3_column_int64(stmt, 8);
}

/* ========================================================================
 * Prepared statement helper
 * ======================================================================== */
#define PREP(db, sql, stmt) sqlite3_prepare_v2(db, sql, -1, stmt, NULL)

#define STEP(stmt) sqlite3_step(stmt)

#define FINALIZE(stmt) sqlite3_finalize(stmt)

#define COL_ID(stmt, col) ((sso_id_t)sqlite3_column_int64(stmt, col))

/* ========================================================================
 * vtable implementations
 * ======================================================================== */

/* --- open --- */
static sso_error_t sqlite_open(storage_backend_t* self, const char* dsn) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv)
		return SSO_ERR_INVALID_PARAM;

	sso_strlcpy(priv->dsn, dsn, sizeof(priv->dsn));
	priv->dsn[sizeof(priv->dsn) - 1] = '\0';

	int rc = sqlite3_open(dsn, &priv->db);
	if (rc != SQLITE_OK) {
		return SSO_ERR_STORAGE;
	}

	sqlite3_busy_timeout(priv->db, 5000);

	/* Performance optimization: WAL mode + NORMAL synchronous */
	sqlite3_exec(priv->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	sqlite3_exec(priv->db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

	/* Create tables */
	char* errmsg = NULL;
	rc			 = sqlite3_exec(priv->db, SCHEMA_SQL, NULL, NULL, &errmsg);
	if (rc != SQLITE_OK) {
		sqlite3_close(priv->db);
		priv->db = NULL;
		return SSO_ERR_STORAGE;
	}

	/* Schema migration metadata */
	sqlite3_exec(priv->db,
				 "CREATE TABLE IF NOT EXISTS _migrations ("
				 "  version INTEGER PRIMARY KEY,"
				 "  applied_at INTEGER NOT NULL"
				 ")",
				 NULL, NULL, NULL);

	/* Determine if we just created the tables.
	 * If the database was just created (Schema SQL just ran and _migrations is empty),
	 * we initialize _migrations to the latest version to avoid running redundant migrations. */
	int			  current_version = 0;
	sqlite3_stmt* s				  = NULL;
	if (sqlite3_prepare_v2(priv->db, "SELECT COALESCE(MAX(version),0) FROM _migrations", -1, &s, NULL) == SQLITE_OK) {
		if (sqlite3_step(s) == SQLITE_ROW)
			current_version = sqlite3_column_int(s, 0);
		sqlite3_finalize(s);
	}

	if (current_version == 0) {
		/* New database: set current version to latest (v3) to skip existing migrations */
		sqlite3_prepare_v2(priv->db, "INSERT INTO _migrations (version, applied_at) VALUES (3, ?1)", -1, &s, NULL);
		sqlite3_bind_int64(s, 1, (sqlite3_int64)sso_timestamp_now());
		sqlite3_step(s);
		sqlite3_finalize(s);
		current_version = 3;
	}

	/* Run pending migrations (if any) */
	for (int v = current_version + 1;; v++) {
		const char* migration = NULL;
		if (v == 1) {
			migration = "CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);"
						"CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);"
						"CREATE INDEX IF NOT EXISTS idx_user_groups_user ON user_groups(user_id);"
						"CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);"
						"CREATE INDEX IF NOT EXISTS idx_role_groups_role ON role_groups(role_id);"
						"CREATE INDEX IF NOT EXISTS idx_role_groups_group ON role_groups(group_id);"
						"CREATE INDEX IF NOT EXISTS idx_policy_assignments_target ON policy_assignments(target_type, "
						"target_id);";
		} else if (v == 2) {
			migration = "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;"
						"ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT '';"
						"CREATE TABLE IF NOT EXISTS refresh_tokens ("
						"  token_hash TEXT PRIMARY KEY,"
						"  user_id INTEGER NOT NULL,"
						"  client_id TEXT,"
						"  expires_at INTEGER NOT NULL,"
						"  issued_at INTEGER NOT NULL,"
						"  revoked INTEGER DEFAULT 0"
						");";
		} else if (v == 3) {
			migration = "CREATE TABLE IF NOT EXISTS revoked_jtis ("
						"  jti TEXT PRIMARY KEY,"
						"  expires_at INTEGER NOT NULL"
						");";
		} else {
			break;
		}
		if (!migration)
			break;
		char* merr = NULL;
		if (sqlite3_exec(priv->db, migration, NULL, NULL, &merr) != SQLITE_OK) {
			sqlite3_close(priv->db);
			priv->db = NULL;
			return SSO_ERR_STORAGE;
		}
		sqlite3_stmt* insert = NULL;
		if (sqlite3_prepare_v2(priv->db, "INSERT INTO _migrations (version, applied_at) VALUES (?1, ?2)", -1, &insert,
							   NULL) == SQLITE_OK) {
			sqlite3_bind_int(insert, 1, v);
			sqlite3_bind_int64(insert, 2, (sqlite3_int64)sso_timestamp_now());
			sqlite3_step(insert);
			sqlite3_finalize(insert);
		}
	}

	return SSO_OK;
}

/* --- close --- */
static void sqlite_close(storage_backend_t* self) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (priv) {
		if (priv->db) {
			sqlite3_exec(priv->db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, NULL);
			sqlite3_close(priv->db);
		}
		free(priv);
		self->handle = NULL;
	}
}

/* --- transactions --- */
static sso_error_t sqlite_begin(storage_backend_t* self) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;
	char* errmsg = NULL;
	if (sqlite3_exec(priv->db, "BEGIN", NULL, NULL, &errmsg) != SQLITE_OK) {
		return SSO_ERR_STORAGE;
	}
	return SSO_OK;
}

static sso_error_t sqlite_commit(storage_backend_t* self) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;
	char* errmsg = NULL;
	if (sqlite3_exec(priv->db, "COMMIT", NULL, NULL, &errmsg) != SQLITE_OK) {
		return SSO_ERR_STORAGE;
	}
	return SSO_OK;
}

static sso_error_t sqlite_rollback(storage_backend_t* self) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;
	char* errmsg = NULL;
	sqlite3_exec(priv->db, "ROLLBACK", NULL, NULL, &errmsg);
	return SSO_OK;
}

/* ========================================================================
 * User CRUD
 * ======================================================================== */
static sso_error_t sqlite_user_create(storage_backend_t* self, user_t* user) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	const char*	  sql  = "INSERT INTO users (username, phone, password_hash, email, display_name, "
						 "status, created_at, updated_at, attributes, mfa_enabled, mfa_secret) "
						 "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)";
	sqlite3_stmt* stmt = NULL;
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

#define MAKE_GETTER(type, type_name, table, reader)                                                                    \
	static sso_error_t sqlite_##type_name##_get_by_id(storage_backend_t* self, sso_id_t id, type##_t* out) {           \
		sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;                                                            \
		if (!priv || !priv->db)                                                                                        \
			return SSO_ERR_STORAGE;                                                                                    \
		char sql[128];                                                                                                 \
		snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE id=?1", #table);                                            \
		sqlite3_stmt* stmt = NULL;                                                                                     \
		if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)                                           \
			return SSO_ERR_STORAGE;                                                                                    \
		sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);                                                                \
		int rc = sqlite3_step(stmt);                                                                                   \
		if (rc != SQLITE_ROW) {                                                                                        \
			sqlite3_finalize(stmt);                                                                                    \
			return SSO_ERR_NOT_FOUND;                                                                                  \
		}                                                                                                              \
		reader(stmt, out);                                                                                             \
		sqlite3_finalize(stmt);                                                                                        \
		return SSO_OK;                                                                                                 \
	}

/* Generate getter implementations */
MAKE_GETTER(user, user, users, read_user)
MAKE_GETTER(role, role, roles, read_role)
MAKE_GETTER(group, group, groups_t, read_group)
MAKE_GETTER(policy, policy, policies, read_policy)

/* --- user_get_by_name --- */
static sso_error_t sqlite_user_get_by_name(storage_backend_t* self, const char* name, user_t* out) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
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
static sso_error_t sqlite_user_get_by_phone(storage_backend_t* self, const char* phone, user_t* out) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
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

#define MAKE_GET_BY_NAME(name_type, table, reader)                                                                     \
	static sso_error_t sqlite_##name_type##_get_by_name(storage_backend_t* self, const char* name,                     \
														name_type##_t* out) {                                          \
		sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;                                                            \
		if (!priv || !priv->db)                                                                                        \
			return SSO_ERR_STORAGE;                                                                                    \
		char sql[128];                                                                                                 \
		snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE name=?1", #table);                                          \
		sqlite3_stmt* stmt = NULL;                                                                                     \
		if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)                                           \
			return SSO_ERR_STORAGE;                                                                                    \
		sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);                                                           \
		int rc = sqlite3_step(stmt);                                                                                   \
		if (rc != SQLITE_ROW) {                                                                                        \
			sqlite3_finalize(stmt);                                                                                    \
			return SSO_ERR_NOT_FOUND;                                                                                  \
		}                                                                                                              \
		reader(stmt, out);                                                                                             \
		sqlite3_finalize(stmt);                                                                                        \
		return SSO_OK;                                                                                                 \
	}

MAKE_GET_BY_NAME(role, roles, read_role)
MAKE_GET_BY_NAME(group, groups_t, read_group)
MAKE_GET_BY_NAME(policy, policies, read_policy)

/* --- user_update --- */
static sso_error_t sqlite_user_update(storage_backend_t* self, const user_t* user) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	const char*	  sql  = "UPDATE users SET phone=?1, password_hash=?2, email=?3, display_name=?4, "
						 "status=?5, updated_at=?6, attributes=?7, mfa_enabled=?8, mfa_secret=?9 "
						 "WHERE id=?10";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;

	sqlite3_bind_text(stmt, 1, user->phone, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, user->password_hash, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, user->email, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, user->display_name, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 5, user->status);
	sqlite3_bind_int64(stmt, 6, user->updated_at);
	sqlite3_bind_text(stmt, 7, user->attributes, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 8, user->mfa_enabled);
	sqlite3_bind_text(stmt, 9, user->mfa_secret, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 10, (sqlite3_int64)user->id);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

/* --- user_delete --- */
#define MAKE_DELETE(table)                                                                                             \
	static sso_error_t sqlite_##table##_delete(storage_backend_t* self, sso_id_t id) {                                 \
		sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;                                                            \
		if (!priv || !priv->db)                                                                                        \
			return SSO_ERR_STORAGE;                                                                                    \
		char sql[128];                                                                                                 \
		snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE id=?1", #table);                                              \
		sqlite3_stmt* stmt = NULL;                                                                                     \
		if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)                                           \
			return SSO_ERR_STORAGE;                                                                                    \
		sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);                                                                \
		int rc = sqlite3_step(stmt);                                                                                   \
		sqlite3_finalize(stmt);                                                                                        \
		return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;                                                         \
	}

/* Cascade delete helper: execute a parameterized SQL with one int64 arg */
static sso_error_t cascade_delete(sqlite3* db, const char* sql, sqlite3_int64 id) {
	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

/* Custom delete with cascade for users */
static sso_error_t sqlite_users_delete(storage_backend_t* self, sso_id_t id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;
	cascade_delete(priv->db, "DELETE FROM user_roles WHERE user_id=?1", id);
	cascade_delete(priv->db, "DELETE FROM user_groups WHERE user_id=?1", id);
	cascade_delete(priv->db, "DELETE FROM policy_assignments WHERE target_type=0 AND target_id=?1", id);
	const char*	  sql  = "DELETE FROM users WHERE id=?1";
	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

/* Custom delete with cascade for roles */
static sso_error_t sqlite_roles_delete(storage_backend_t* self, sso_id_t id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;
	cascade_delete(priv->db, "DELETE FROM user_roles WHERE role_id=?1", id);
	cascade_delete(priv->db, "DELETE FROM role_groups WHERE role_id=?1", id);
	cascade_delete(priv->db, "DELETE FROM policy_assignments WHERE target_type=1 AND target_id=?1", id);
	const char*	  sql  = "DELETE FROM roles WHERE id=?1";
	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

/* Custom delete with cascade for groups_t */
static sso_error_t sqlite_groups_t_delete(storage_backend_t* self, sso_id_t id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;
	cascade_delete(priv->db, "DELETE FROM user_groups WHERE group_id=?1", id);
	cascade_delete(priv->db, "DELETE FROM role_groups WHERE group_id=?1", id);
	cascade_delete(priv->db, "DELETE FROM policy_assignments WHERE target_type=2 AND target_id=?1", id);
	const char*	  sql  = "DELETE FROM groups_t WHERE id=?1";
	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

MAKE_DELETE(policies)

/* --- Paginated List helper --- */
#define MAKE_LIST_PAGINATED(table, search_clause)                                                                      \
	static sso_error_t sqlite_##table##_list(storage_backend_t* self, const char* q, int status, int offset,           \
											 int limit, sso_id_t* ids, size_t* count, size_t* total_count) {           \
		sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;                                                            \
		if (!priv || !priv->db)                                                                                        \
			return SSO_ERR_STORAGE;                                                                                    \
		char where[512] = "";                                                                                          \
		if ((q && q[0] != '\0') || status != -1) {                                                                     \
			strcat(where, " WHERE ");                                                                                  \
			if (status != -1) {                                                                                        \
				strcat(where, "status = ? ");                                                                          \
			}                                                                                                          \
			if (q && q[0] != '\0') {                                                                                   \
				if (status != -1)                                                                                      \
					strcat(where, " AND ");                                                                            \
				strcat(where, "(");                                                                                    \
				strcat(where, search_clause);                                                                          \
				strcat(where, ")");                                                                                    \
			}                                                                                                          \
		}                                                                                                              \
		char		  sql[1024];                                                                                       \
		sqlite3_stmt* stmt = NULL;                                                                                     \
		/* Total count query */                                                                                        \
		snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s %s", #table, where);                                       \
		if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)                                           \
			return SSO_ERR_STORAGE;                                                                                    \
		int p = 1;                                                                                                     \
		if (status != -1)                                                                                              \
			sqlite3_bind_int(stmt, p++, status);                                                                       \
		if (q && q[0] != '\0') {                                                                                       \
			char q_pattern[SSO_MAX_QUERY + 2];                                                                         \
			snprintf(q_pattern, sizeof(q_pattern), "%%%s%%", q);                                                       \
			int			n_search = 0;                                                                                  \
			const char* tmp		 = search_clause;                                                                      \
			while ((tmp = strstr(tmp, "?"))) {                                                                         \
				n_search++;                                                                                            \
				tmp++;                                                                                                 \
			}                                                                                                          \
			for (int i = 0; i < n_search; i++)                                                                         \
				sqlite3_bind_text(stmt, p++, q_pattern, -1, SQLITE_TRANSIENT);                                         \
		}                                                                                                              \
		if (sqlite3_step(stmt) == SQLITE_ROW)                                                                          \
			*total_count = (size_t)sqlite3_column_int64(stmt, 0);                                                      \
		sqlite3_finalize(stmt);                                                                                        \
		/* Data query */                                                                                               \
		snprintf(sql, sizeof(sql), "SELECT id FROM %s %s ORDER BY id LIMIT ? OFFSET ?", #table, where);                \
		if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)                                           \
			return SSO_ERR_STORAGE;                                                                                    \
		p = 1;                                                                                                         \
		if (status != -1)                                                                                              \
			sqlite3_bind_int(stmt, p++, status);                                                                       \
		if (q && q[0] != '\0') {                                                                                       \
			char q_pattern[SSO_MAX_QUERY + 2];                                                                         \
			snprintf(q_pattern, sizeof(q_pattern), "%%%s%%", q);                                                       \
			int			n_search = 0;                                                                                  \
			const char* tmp		 = search_clause;                                                                      \
			while ((tmp = strstr(tmp, "?"))) {                                                                         \
				n_search++;                                                                                            \
				tmp++;                                                                                                 \
			}                                                                                                          \
			for (int i = 0; i < n_search; i++)                                                                         \
				sqlite3_bind_text(stmt, p++, q_pattern, -1, SQLITE_TRANSIENT);                                         \
		}                                                                                                              \
		sqlite3_bind_int(stmt, p++, limit);                                                                            \
		sqlite3_bind_int(stmt, p++, offset);                                                                           \
		size_t n = 0;                                                                                                  \
		while (sqlite3_step(stmt) == SQLITE_ROW)                                                                       \
			ids[n++] = (sso_id_t)sqlite3_column_int64(stmt, 0);                                                        \
		*count = n;                                                                                                    \
		sqlite3_finalize(stmt);                                                                                        \
		return SSO_OK;                                                                                                 \
	}

MAKE_LIST_PAGINATED(users, "username LIKE ? OR display_name LIKE ? OR email LIKE ? OR phone LIKE ?")
MAKE_LIST_PAGINATED(roles, "name LIKE ? OR description LIKE ?")
MAKE_LIST_PAGINATED(groups_t, "name LIKE ? OR description LIKE ?")
MAKE_LIST_PAGINATED(policies, "name LIKE ?")

/* --- role/group update --- */
#define MAKE_UPDATE(table, set_clause, id_col)                                                                         \
	static sso_error_t sqlite_##table##_update(storage_backend_t* self, const table##_t* obj) {                        \
		sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;                                                            \
		if (!priv || !priv->db)                                                                                        \
			return SSO_ERR_STORAGE;                                                                                    \
		char sql[512];                                                                                                 \
		snprintf(sql, sizeof(sql), "UPDATE %s SET " set_clause " WHERE " id_col "=?%d", #table, obj->id);              \
		sqlite3_stmt* stmt = NULL;                                                                                     \
		if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)                                           \
			return SSO_ERR_STORAGE;                                                                                    \
		int rc = sqlite3_step(stmt);                                                                                   \
		sqlite3_finalize(stmt);                                                                                        \
		return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;                                                         \
	}

/* Manual role update (simpler than macro for this case) */
static sso_error_t sqlite_role_update(storage_backend_t* self, const role_t* role) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	const char*	  sql =
			"UPDATE roles SET name=?1, description=?2, parent_role_id=?3, status=?4, updated_at=?5 WHERE id=?6";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;

	sqlite3_bind_text(stmt, 1, role->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, role->description, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)role->parent_role_id);
	sqlite3_bind_int(stmt, 4, role->status);
	sqlite3_bind_int64(stmt, 5, role->updated_at);
	sqlite3_bind_int64(stmt, 6, (sqlite3_int64)role->id);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_group_update(storage_backend_t* self, const group_t* group) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	const char*	  sql =
			"UPDATE groups_t SET name=?1, description=?2, parent_group_id=?3, status=?4, updated_at=?5 WHERE id=?6";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;

	sqlite3_bind_text(stmt, 1, group->name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, group->description, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)group->parent_group_id);
	sqlite3_bind_int(stmt, 4, group->status);
	sqlite3_bind_int64(stmt, 5, group->updated_at);
	sqlite3_bind_int64(stmt, 6, (sqlite3_int64)group->id);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_policy_update(storage_backend_t* self, const policy_t* policy) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	const char*	  sql  = "UPDATE policies SET name=?1, strategy_type=?2, effect=?3, "
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
static sso_error_t sqlite_role_create(storage_backend_t* self, role_t* role) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db,
						   "INSERT INTO roles (name, description, parent_role_id, status, created_at, updated_at) "
						   "VALUES (?1,?2,?3,?4,?5,?6)",
						   -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	bind_role(stmt, role);
	int rc = sqlite3_step(stmt);
	if (rc == SQLITE_CONSTRAINT) {
		sqlite3_finalize(stmt);
		return SSO_ERR_ALREADY_EXISTS;
	}
	if (rc != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return SSO_ERR_STORAGE;
	}
	role->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

static sso_error_t sqlite_group_create(storage_backend_t* self, group_t* group) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db,
						   "INSERT INTO groups_t (name, description, parent_group_id, status, created_at, updated_at) "
						   "VALUES (?1,?2,?3,?4,?5,?6)",
						   -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	bind_group(stmt, group);
	int rc = sqlite3_step(stmt);
	if (rc == SQLITE_CONSTRAINT) {
		sqlite3_finalize(stmt);
		return SSO_ERR_ALREADY_EXISTS;
	}
	if (rc != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return SSO_ERR_STORAGE;
	}
	group->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

static sso_error_t sqlite_policy_create(storage_backend_t* self, policy_t* policy) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(
				priv->db,
				"INSERT INTO policies (name, strategy_type, effect, priority, rules, status, created_at, updated_at) "
				"VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
				-1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	bind_policy(stmt, policy);
	int rc = sqlite3_step(stmt);
	if (rc == SQLITE_CONSTRAINT) {
		sqlite3_finalize(stmt);
		return SSO_ERR_ALREADY_EXISTS;
	}
	if (rc != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return SSO_ERR_STORAGE;
	}
	policy->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

/* ========================================================================
 * Assignment helpers
 * ======================================================================== */

/* Helper to execute a simple INSERT/DELETE with two ID bindings */
#define ASSIGN_SIMPLE2(sql_pattern, id1, id2)                                                                          \
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;                                                                \
	if (!priv || !priv->db)                                                                                            \
		return SSO_ERR_STORAGE;                                                                                        \
	sqlite3_stmt* stmt = NULL;                                                                                         \
	char		  sql[128];                                                                                            \
	snprintf(sql, sizeof(sql), sql_pattern);                                                                           \
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)                                               \
		return SSO_ERR_STORAGE;                                                                                        \
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)id1);                                                                   \
	sqlite3_bind_int64(stmt, 2, (sqlite3_int64)id2);                                                                   \
	int rc = sqlite3_step(stmt);                                                                                       \
	sqlite3_finalize(stmt);                                                                                            \
	return (rc == SQLITE_DONE || rc == SQLITE_CONSTRAINT) ? SSO_OK : SSO_ERR_STORAGE;

static sso_error_t sqlite_assign_role_to_user(storage_backend_t* self, sso_id_t role_id, sso_id_t user_id) {
	ASSIGN_SIMPLE2("INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?1,?2)", user_id, role_id);
}
static sso_error_t sqlite_unassign_role_user(storage_backend_t* self, sso_id_t role_id, sso_id_t user_id) {
	ASSIGN_SIMPLE2("DELETE FROM user_roles WHERE user_id=?1 AND role_id=?2", user_id, role_id);
}
static sso_error_t sqlite_assign_role_to_group(storage_backend_t* self, sso_id_t role_id, sso_id_t group_id) {
	ASSIGN_SIMPLE2("INSERT OR IGNORE INTO role_groups VALUES (?1,?2)", role_id, group_id);
}
static sso_error_t sqlite_unassign_role_group(storage_backend_t* self, sso_id_t role_id, sso_id_t group_id) {
	ASSIGN_SIMPLE2("DELETE FROM role_groups WHERE role_id=?1 AND group_id=?2", role_id, group_id);
}
static sso_error_t sqlite_add_user_to_group(storage_backend_t* self, sso_id_t group_id, sso_id_t user_id) {
	ASSIGN_SIMPLE2("INSERT OR IGNORE INTO user_groups VALUES (?1,?2)", user_id, group_id);
}
static sso_error_t sqlite_remove_user_from_group(storage_backend_t* self, sso_id_t group_id, sso_id_t user_id) {
	ASSIGN_SIMPLE2("DELETE FROM user_groups WHERE user_id=?1 AND group_id=?2", user_id, group_id);
}

/* --- get_user_roles --- */
static sso_error_t sqlite_get_user_roles(storage_backend_t* self, sso_id_t user_id, sso_id_t* role_ids, size_t* count,
										 size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
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
static sso_error_t sqlite_get_role_users(storage_backend_t* self, sso_id_t role_id, sso_id_t* user_ids, size_t* count,
										 size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
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
static sso_error_t sqlite_get_user_groups(storage_backend_t* self, sso_id_t user_id, sso_id_t* group_ids, size_t* count,
										  size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
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
static sso_error_t sqlite_get_group_users(storage_backend_t* self, sso_id_t group_id, sso_id_t* user_ids, size_t* count,
										  size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
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
static sso_error_t sqlite_assign_policy(storage_backend_t* self, sso_id_t policy_id, policy_target_type_t target_type,
										sso_id_t target_id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "INSERT OR IGNORE INTO policy_assignments VALUES (?1,?2,?3)", -1, &stmt, NULL) !=
		SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)policy_id);
	sqlite3_bind_int(stmt, 2, (int)target_type);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)target_id);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE || rc == SQLITE_CONSTRAINT) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_unassign_policy(storage_backend_t* self, sso_id_t policy_id, policy_target_type_t target_type,
										  sso_id_t target_id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db,
						   "DELETE FROM policy_assignments WHERE policy_id=?1 AND target_type=?2 AND target_id=?3", -1,
						   &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)policy_id);
	sqlite3_bind_int(stmt, 2, (int)target_type);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)target_id);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_get_policy_targets(storage_backend_t* self, sso_id_t policy_id,
											 policy_target_type_t target_type, sso_id_t* target_ids, size_t* count,
											 size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "SELECT target_id FROM policy_assignments WHERE policy_id=?1 AND target_type=?2",
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

static sso_error_t sqlite_get_target_policies(storage_backend_t* self, policy_target_type_t target_type,
											  sso_id_t target_id, sso_id_t* policy_ids, size_t* count, size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "SELECT policy_id FROM policy_assignments WHERE target_type=?1 AND target_id=?2",
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
static sso_error_t sqlite_role_get_parent(storage_backend_t* self, sso_id_t role_id, sso_id_t* parent_id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "SELECT parent_role_id FROM roles WHERE id=?1", -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)role_id);

	int rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return SSO_ERR_NOT_FOUND;
	}
	*parent_id = COL_ID(stmt, 0);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

static sso_error_t sqlite_group_get_parent(storage_backend_t* self, sso_id_t group_id, sso_id_t* parent_id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "SELECT parent_group_id FROM groups_t WHERE id=?1", -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)group_id);

	int rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return SSO_ERR_NOT_FOUND;
	}
	*parent_id = COL_ID(stmt, 0);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

/* --- get_user_roles_with_ancestors --- */
static sso_error_t sqlite_get_user_roles_with_ancestors(storage_backend_t* self, sso_id_t user_id, sso_id_t* role_ids,
														size_t* count, size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	/* Use a recursive CTE to get all roles (directly assigned + inherited
	 * through parent_role_id hierarchy) in a single query. */
	const char* sql = "WITH RECURSIVE user_role_tree(role_id) AS ("
					  "  SELECT ur.role_id FROM user_roles ur WHERE ur.user_id = ?1"
					  "  UNION"
					  "  SELECT r.parent_role_id FROM roles r"
					  "  INNER JOIN user_role_tree ut ON r.id = ut.role_id"
					  "  WHERE r.parent_role_id != 0 AND r.status = 1"
					  ")"
					  "SELECT DISTINCT t.role_id FROM user_role_tree t "
					  "INNER JOIN roles r ON t.role_id = r.id WHERE r.status = 1";

	sqlite3_stmt* stmt = NULL;
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

static sso_error_t sqlite_save_sms_code(storage_backend_t* self, const char* phone, const char* code,
										sso_timestamp_t expires_at) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	const char*	  sql  = "INSERT INTO sms_codes (phone, code, expires_at, attempts) VALUES (?1, ?2, ?3, 0) "
						 "ON CONFLICT(phone) DO UPDATE SET code=excluded.code, expires_at=excluded.expires_at, attempts=0";
	sqlite3_stmt* stmt = NULL;
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

static sso_error_t sqlite_get_sms_code(storage_backend_t* self, const char* phone, char* code_out) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	const char*	  sql  = "SELECT code, expires_at FROM sms_codes WHERE phone=?1";
	sqlite3_stmt* stmt = NULL;
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

	const char* code = (const char*)sqlite3_column_text(stmt, 0);
	if (code) {
		sso_strlcpy(code_out, code, 15);
		code_out[15] = '\0';
	} else {
		code_out[0] = '\0';
	}

	sqlite3_finalize(stmt);
	return SSO_OK;
}

static sso_error_t sqlite_delete_sms_code(storage_backend_t* self, const char* phone) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "DELETE FROM sms_codes WHERE phone=?1", -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;

	sqlite3_bind_text(stmt, 1, phone, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

/* ========================================================================
 * OAuth authorization codes
 * ======================================================================== */
static sso_error_t sqlite_oauth_code_create(storage_backend_t* self, const oauth_auth_code_t* code) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db || !code)
		return SSO_ERR_STORAGE;
	sqlite3_stmt* stmt = NULL;
	const char*	  sql =
			"INSERT INTO oauth_auth_codes "
			"(code,client_id,user_id,redirect_uri,scope,nonce,code_challenge,code_challenge_method,expires_at,used) "
			"VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, code->code, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, code->client_id, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)code->user_id);
	sqlite3_bind_text(stmt, 4, code->redirect_uri, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 5, code->scope, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 6, code->nonce, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 7, code->code_challenge, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 8, code->code_challenge_method, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 9, (sqlite3_int64)code->expires_at);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_oauth_code_get(storage_backend_t* self, const char* code, oauth_auth_code_t* out) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db || !code || !out)
		return SSO_ERR_STORAGE;
	sqlite3_stmt* stmt = NULL;
	const char*	  sql  = "SELECT code,client_id,user_id,redirect_uri,scope,nonce,"
						 "code_challenge,code_challenge_method,expires_at,used "
						 "FROM oauth_auth_codes WHERE code=?1";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	if (rc != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return SSO_ERR_NOT_FOUND;
	}
	memset(out, 0, sizeof(*out));
	sso_strlcpy(out->code, (const char*)sqlite3_column_text(stmt, 0), sizeof(out->code) - 1);
	sso_strlcpy(out->client_id, (const char*)sqlite3_column_text(stmt, 1), sizeof(out->client_id) - 1);
	out->user_id = (sso_id_t)sqlite3_column_int64(stmt, 2);
	sso_strlcpy(out->redirect_uri, (const char*)sqlite3_column_text(stmt, 3), sizeof(out->redirect_uri) - 1);
	sso_strlcpy(out->scope, (const char*)sqlite3_column_text(stmt, 4), sizeof(out->scope) - 1);
	sso_strlcpy(out->nonce, (const char*)sqlite3_column_text(stmt, 5), sizeof(out->nonce) - 1);
	sso_strlcpy(out->code_challenge, (const char*)sqlite3_column_text(stmt, 6), sizeof(out->code_challenge) - 1);
	sso_strlcpy(out->code_challenge_method, (const char*)sqlite3_column_text(stmt, 7),
				sizeof(out->code_challenge_method) - 1);
	out->expires_at = (sso_timestamp_t)sqlite3_column_int64(stmt, 8);
	out->used		= sqlite3_column_int(stmt, 9);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

static sso_error_t sqlite_oauth_code_mark_used(storage_backend_t* self, const char* code) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db || !code)
		return SSO_ERR_STORAGE;
	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "UPDATE oauth_auth_codes SET used=1 WHERE code=?1", -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, code, -1, SQLITE_STATIC);
	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_oauth_code_cleanup(storage_backend_t* self) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv || !priv->db)
		return SSO_ERR_STORAGE;
	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(priv->db, "DELETE FROM oauth_auth_codes WHERE expires_at < ?1 OR used=1", -1, &stmt, NULL) !=
		SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int64(stmt, 1, (sqlite3_int64)sso_timestamp_now());
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

/* ========================================================================
 * OAuth clients
 * ======================================================================== */
static void bind_oauth_client(sqlite3_stmt* stmt, const oauth_client_t* c) {
	sqlite3_bind_text(stmt, 1, c->client_id, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, c->client_secret_hash, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, c->redirect_uris, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, c->app_name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 5, c->app_description, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 6, c->app_logo_url, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 7, c->allowed_scopes, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 8, c->allowed_grant_types, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 9, c->token_ttl_ms);
	sqlite3_bind_int(stmt, 10, c->status);
	sqlite3_bind_int64(stmt, 11, c->created_at);
	sqlite3_bind_int64(stmt, 12, c->updated_at);
}

static void read_oauth_client(sqlite3_stmt* stmt, oauth_client_t* c) {
	memset(c, 0, sizeof(*c));
	c->id				  = (sso_id_t)sqlite3_column_int64(stmt, 0);
	const char* client_id = (const char*)sqlite3_column_text(stmt, 1);
	if (client_id)
		sso_strlcpy(c->client_id, client_id, sizeof(c->client_id) - 1);
	const char* hash = (const char*)sqlite3_column_text(stmt, 2);
	if (hash)
		sso_strlcpy(c->client_secret_hash, hash, sizeof(c->client_secret_hash) - 1);
	const char* uris = (const char*)sqlite3_column_text(stmt, 3);
	if (uris)
		sso_strlcpy(c->redirect_uris, uris, sizeof(c->redirect_uris) - 1);
	const char* name = (const char*)sqlite3_column_text(stmt, 4);
	if (name)
		sso_strlcpy(c->app_name, name, sizeof(c->app_name) - 1);
	const char* desc = (const char*)sqlite3_column_text(stmt, 5);
	if (desc)
		sso_strlcpy(c->app_description, desc, sizeof(c->app_description) - 1);
	const char* logo = (const char*)sqlite3_column_text(stmt, 6);
	if (logo)
		sso_strlcpy(c->app_logo_url, logo, sizeof(c->app_logo_url) - 1);
	const char* scopes = (const char*)sqlite3_column_text(stmt, 7);
	if (scopes)
		sso_strlcpy(c->allowed_scopes, scopes, sizeof(c->allowed_scopes) - 1);
	const char* grants = (const char*)sqlite3_column_text(stmt, 8);
	if (grants)
		sso_strlcpy(c->allowed_grant_types, grants, sizeof(c->allowed_grant_types) - 1);
	c->token_ttl_ms = (long)sqlite3_column_int64(stmt, 9);
	c->status		= sqlite3_column_int(stmt, 10);
	c->created_at	= (sso_timestamp_t)sqlite3_column_int64(stmt, 11);
	c->updated_at	= (sso_timestamp_t)sqlite3_column_int64(stmt, 12);
}

static sso_error_t sqlite_oauth_client_create(storage_backend_t* self, oauth_client_t* c) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	const char*	   sql = "INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris, app_name, "
						 "app_description, app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, "
						 "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	if (c->created_at == 0)
		c->created_at = sso_timestamp_now();
	if (c->updated_at == 0)
		c->updated_at = c->created_at;
	bind_oauth_client(stmt, c);
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return SSO_ERR_STORAGE;
	}
	c->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
	sqlite3_finalize(stmt);
	return SSO_OK;
}

static sso_error_t sqlite_oauth_client_get(storage_backend_t* self, const char* client_id, oauth_client_t* c) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	if (sqlite3_prepare_v2(priv->db,
						   "SELECT id, client_id, client_secret_hash, redirect_uris, app_name, app_description, "
						   "app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, "
						   "updated_at FROM oauth_clients WHERE client_id = ?",
						   -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		read_oauth_client(stmt, c);
		sqlite3_finalize(stmt);
		return SSO_OK;
	}
	sqlite3_finalize(stmt);
	return SSO_ERR_NOT_FOUND;
}

static sso_error_t sqlite_oauth_client_update(storage_backend_t* self, const oauth_client_t* c) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	const char*	   sql = "UPDATE oauth_clients SET client_id=?, client_secret_hash=?, redirect_uris=?, app_name=?, "
						 "app_description=?, app_logo_url=?, allowed_scopes=?, allowed_grant_types=?, token_ttl_ms=?, "
						 "status=?, created_at=?, updated_at=? WHERE id=?";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	bind_oauth_client(stmt, c);
	sqlite3_bind_int64(stmt, 13, (sqlite3_int64)c->id);
	sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
	sqlite3_finalize(stmt);
	return err;
}

static sso_error_t sqlite_oauth_client_delete(storage_backend_t* self, const char* client_id) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	if (sqlite3_prepare_v2(priv->db, "DELETE FROM oauth_clients WHERE client_id=?", -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_STATIC);
	sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
	sqlite3_finalize(stmt);
	return err;
}

static sso_error_t sqlite_oauth_client_list(storage_backend_t* self, int offset, int limit, oauth_client_t* clients,
											size_t* count, size_t max) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	if (sqlite3_prepare_v2(priv->db,
						   "SELECT id, client_id, client_secret_hash, redirect_uris, app_name, app_description, "
						   "app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, "
						   "updated_at FROM oauth_clients LIMIT ? OFFSET ?",
						   -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_int(stmt, 1, limit);
	sqlite3_bind_int(stmt, 2, offset);
	size_t c = 0;
	while (sqlite3_step(stmt) == SQLITE_ROW && c < max) {
		read_oauth_client(stmt, &clients[c]);
		c++;
	}
	sqlite3_finalize(stmt);
	if (count)
		*count = c;
	return SSO_OK;
}

static sso_error_t sqlite_refresh_token_create(storage_backend_t* self, const refresh_token_t* rt) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	const char*	   sql = "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at, issued_at, revoked) "
						 "VALUES (?, ?, ?, ?, ?, ?)";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, rt->token_hash, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 2, rt->user_id);
	if (rt->client_id[0])
		sqlite3_bind_text(stmt, 3, rt->client_id, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(stmt, 3);
	sqlite3_bind_int64(stmt, 4, rt->expires_at);
	sqlite3_bind_int64(stmt, 5, rt->issued_at);
	sqlite3_bind_int(stmt, 6, rt->revoked);
	sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
	sqlite3_finalize(stmt);
	return err;
}

static sso_error_t sqlite_refresh_token_get(storage_backend_t* self, const char* token_hash, refresh_token_t* out) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	if (sqlite3_prepare_v2(priv->db,
						   "SELECT token_hash, user_id, client_id, expires_at, issued_at, revoked FROM refresh_tokens "
						   "WHERE token_hash = ?",
						   -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		memset(out, 0, sizeof(*out));
		const char* token_hash_val = (const char*)sqlite3_column_text(stmt, 0);
		if (token_hash_val)
			sso_strlcpy(out->token_hash, token_hash_val, sizeof(out->token_hash) - 1);
		out->user_id			  = sqlite3_column_int64(stmt, 1);
		const char* client_id_val = (const char*)sqlite3_column_text(stmt, 2);
		if (client_id_val)
			sso_strlcpy(out->client_id, client_id_val, sizeof(out->client_id) - 1);
		out->expires_at = sqlite3_column_int64(stmt, 3);
		out->issued_at	= sqlite3_column_int64(stmt, 4);
		out->revoked	= sqlite3_column_int(stmt, 5);
		sqlite3_finalize(stmt);
		return SSO_OK;
	}
	sqlite3_finalize(stmt);
	return SSO_ERR_NOT_FOUND;
}

static sso_error_t sqlite_refresh_token_revoke(storage_backend_t* self, const char* token_hash) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	if (sqlite3_prepare_v2(priv->db, "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", -1, &stmt, NULL) !=
		SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_STATIC);
	sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
	sqlite3_finalize(stmt);
	return err;
}

static sso_error_t sqlite_jti_revoke(storage_backend_t* self, const char* jti, sso_timestamp_t expires_at) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	const char*	   sql = "INSERT OR REPLACE INTO revoked_jtis (jti, expires_at) VALUES (?, ?)";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return SSO_ERR_STORAGE;
	sqlite3_bind_text(stmt, 1, jti, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 2, expires_at);
	sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
	sqlite3_finalize(stmt);
	return err;
}

static bool sqlite_jti_is_revoked(storage_backend_t* self, const char* jti) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3_stmt*  stmt;
	const char*	   sql = "SELECT expires_at FROM revoked_jtis WHERE jti = ?";
	if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK)
		return false;
	sqlite3_bind_text(stmt, 1, jti, -1, SQLITE_STATIC);
	bool found = false;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		sso_timestamp_t expires_at = sqlite3_column_int64(stmt, 0);
		sso_timestamp_t now		   = sso_timestamp_now();
		if (expires_at > now) {
			found = true;
		}
	}
	sqlite3_finalize(stmt);
	return found;
}

static void sqlite_thread_init(storage_backend_t* self) {
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	if (!priv)
		return;

	pthread_once(&g_sqlite_key_once, init_sqlite_key);

	t_read_db = (sqlite3*)pthread_getspecific(g_sqlite_key);
	if (!t_read_db) {
		int rc = sqlite3_open(priv->dsn, &t_read_db);
		if (rc == SQLITE_OK) {
			sqlite3_busy_timeout(t_read_db, 5000);
			(sqlite3_exec)(t_read_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
			(sqlite3_exec)(t_read_db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
			pthread_setspecific(g_sqlite_key, t_read_db);
		} else {
			t_read_db = NULL;
			LOG_WARN("Failed to open thread-local read SQLite connection: %s", sqlite3_errmsg(t_read_db));
		}
	}
}

static void sqlite_thread_cleanup(storage_backend_t* self) {
	(void)self;
	/* Destructor handles close automatically at thread exit, so no-op here */
}

static void escape_json_string(const char* src, char* dst, size_t dst_max) {
	if (!src) {
		dst[0] = '\0';
		return;
	}
	size_t j = 0;
	for (size_t i = 0; src[i] && j < dst_max - 3; i++) {
		if (src[i] == '"') {
			dst[j++] = '\\';
			dst[j++] = '"';
		} else if (src[i] == '\\') {
			dst[j++] = '\\';
			dst[j++] = '\\';
		} else if (src[i] == '\n') {
			dst[j++] = '\\';
			dst[j++] = 'n';
		} else if (src[i] == '\t') {
			dst[j++] = '\\';
			dst[j++] = 't';
		} else if (src[i] == '\r') {
			dst[j++] = '\\';
			dst[j++] = 'r';
		} else
			dst[j++] = src[i];
	}
	dst[j] = '\0';
}

static sso_error_t sqlite_audit_log_write(storage_backend_t* self, const audit_log_entry_t* entry) {
	if (!self || !entry)
		return SSO_ERR_INVALID_PARAM;
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3*	   db	= priv->db;

	const char*	  sql  = "INSERT INTO audit_logs (action, timestamp_ms, user_id, username, ip_address, operation, "
						 "resource, resource_id, status, details, duration_ms, cache_hit, trace) "
						 "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return SSO_ERR_STORAGE;
	}
	sqlite3_bind_text(stmt, 1, entry->action, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 2, (sqlite3_int64)entry->timestamp_ms);
	sqlite3_bind_int64(stmt, 3, (sqlite3_int64)entry->user_id);
	sqlite3_bind_text(stmt, 4, entry->username ? entry->username : "", -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 5, entry->ip_address ? entry->ip_address : "", -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 6, entry->operation ? entry->operation : "", -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 7, entry->resource ? entry->resource : "", -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 8, (sqlite3_int64)entry->resource_id);
	sqlite3_bind_text(stmt, 9, entry->status ? entry->status : "", -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 10, entry->details ? entry->details : "", -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 11, (sqlite3_int64)entry->duration_ms);
	sqlite3_bind_int(stmt, 12, entry->cache_hit ? 1 : 0);
	sqlite3_bind_text(stmt, 13, entry->trace ? entry->trace : "", -1, SQLITE_STATIC);

	int rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
}

static sso_error_t sqlite_audit_log_list(storage_backend_t* self, sso_id_t user_id, int offset, int limit,
										 char** json_out, size_t* total_count) {
	if (!self || !json_out || !total_count)
		return SSO_ERR_INVALID_PARAM;
	sqlite_priv_t* priv = (sqlite_priv_t*)self->handle;
	sqlite3*	   db	= priv->db;

	// Count total
	char count_sql[512];
	if (user_id != SSO_ID_NONE) {
		snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(*) FROM audit_logs WHERE user_id = %llu;",
				 (unsigned long long)user_id);
	} else {
		snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(*) FROM audit_logs;");
	}
	sqlite3_stmt* count_stmt = NULL;
	*total_count			 = 0;
	if (sqlite3_prepare_v2(db, count_sql, -1, &count_stmt, NULL) == SQLITE_OK) {
		if (sqlite3_step(count_stmt) == SQLITE_ROW) {
			*total_count = (size_t)sqlite3_column_int64(count_stmt, 0);
		}
		sqlite3_finalize(count_stmt);
	}

	// Query records
	char sql[512];
	if (user_id != SSO_ID_NONE) {
		snprintf(sql, sizeof(sql),
				 "SELECT action, timestamp_ms, user_id, username, ip_address, operation, resource, resource_id, "
				 "status, details, duration_ms, cache_hit, trace FROM audit_logs WHERE user_id = %llu ORDER BY id DESC "
				 "LIMIT %d OFFSET %d;",
				 (unsigned long long)user_id, limit, offset);
	} else {
		snprintf(sql, sizeof(sql),
				 "SELECT action, timestamp_ms, user_id, username, ip_address, operation, resource, resource_id, "
				 "status, details, duration_ms, cache_hit, trace FROM audit_logs ORDER BY id DESC LIMIT %d OFFSET %d;",
				 limit, offset);
	}

	sqlite3_stmt* stmt = NULL;
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return SSO_ERR_STORAGE;
	}

	size_t cap	= 4096;
	size_t len	= 0;
	char*  json = malloc(cap);
	if (!json) {
		sqlite3_finalize(stmt);
		return SSO_ERR_OUT_OF_MEMORY;
	}
	json[len++] = '[';
	json[len]	= '\0';

	bool first = true;

	char* esc_det	= (char*)malloc(2048);
	char* esc_trace = (char*)malloc(16384);
	char* row		= (char*)malloc(20480);
	if (!esc_det || !esc_trace || !row) {
		free(esc_det);
		free(esc_trace);
		free(row);
		free(json);
		sqlite3_finalize(stmt);
		return SSO_ERR_OUT_OF_MEMORY;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* action	 = (const char*)sqlite3_column_text(stmt, 0);
		uint64_t	ts		 = (uint64_t)sqlite3_column_int64(stmt, 1);
		sso_id_t	uid		 = (sso_id_t)sqlite3_column_int64(stmt, 2);
		const char* username = (const char*)sqlite3_column_text(stmt, 3);
		const char* ip		 = (const char*)sqlite3_column_text(stmt, 4);
		const char* op		 = (const char*)sqlite3_column_text(stmt, 5);
		const char* res		 = (const char*)sqlite3_column_text(stmt, 6);
		sso_id_t	res_id	 = (sso_id_t)sqlite3_column_int64(stmt, 7);
		const char* status	 = (const char*)sqlite3_column_text(stmt, 8);
		const char* details	 = (const char*)sqlite3_column_text(stmt, 9);
		uint64_t	dur		 = (uint64_t)sqlite3_column_int64(stmt, 10);
		int			ch		 = sqlite3_column_int(stmt, 11);
		const char* trace	 = (const char*)sqlite3_column_text(stmt, 12);

		esc_det[0]	 = '\0';
		esc_trace[0] = '\0';
		escape_json_string(details, esc_det, 2048);
		escape_json_string(trace, esc_trace, 16384);

		if (strcmp(action, "admin") == 0) {
			snprintf(row, 20480,
					 "{\"action\":\"admin\",\"timestamp_ms\":%llu,\"user_id\":%llu,\"username\":\"%s\",\"ip_address\":"
					 "\"%s\",\"operation\":\"%s\",\"resource\":\"%s\",\"resource_id\":%llu,\"status\":\"%s\","
					 "\"details\":\"%s\"}",
					 (unsigned long long)ts, (unsigned long long)uid, username ? username : "", ip ? ip : "",
					 op ? op : "", res ? res : "", (unsigned long long)res_id, status ? status : "", esc_det);
		} else {
			snprintf(row, 20480,
					 "{\"action\":\"eval\",\"timestamp_ms\":%llu,\"user_id\":%llu,\"decision\":\"%s\",\"duration_ms\":%"
					 "llu,\"cache_hit\":%s,\"trace\":\"%s\"}",
					 (unsigned long long)ts, (unsigned long long)uid, status ? status : "", (unsigned long long)dur,
					 ch ? "true" : "false", esc_trace);
		}

		size_t row_len = strlen(row);
		if (len + row_len + 3 > cap) {
			cap			   = (len + row_len + 3) * 2;
			char* new_json = realloc(json, cap);
			if (!new_json) {
				free(json);
				free(esc_det);
				free(esc_trace);
				free(row);
				sqlite3_finalize(stmt);
				return SSO_ERR_OUT_OF_MEMORY;
			}
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

	free(esc_det);
	free(esc_trace);
	free(row);
	json[len++] = ']';
	json[len]	= '\0';
	sqlite3_finalize(stmt);

	*json_out = json;
	return SSO_OK;
}

/* ========================================================================
 * Backend constructor
 * ======================================================================== */
sso_error_t storage_sqlite_create(storage_backend_t** backend) {
	if (!backend)
		return SSO_ERR_INVALID_PARAM;

	*backend = (storage_backend_t*)calloc(1, sizeof(storage_backend_t));
	if (!*backend)
		return SSO_ERR_OUT_OF_MEMORY;

	sqlite_priv_t* priv = (sqlite_priv_t*)calloc(1, sizeof(sqlite_priv_t));
	if (!priv) {
		free(*backend);
		*backend = NULL;
		return SSO_ERR_OUT_OF_MEMORY;
	}

	(*backend)->handle = priv;
	sso_strlcpy((*backend)->name, "sqlite", sizeof((*backend)->name));

	/* Lifecycle */
	(*backend)->open		   = sqlite_open;
	(*backend)->close		   = sqlite_close;
	(*backend)->begin		   = sqlite_begin;
	(*backend)->commit		   = sqlite_commit;
	(*backend)->rollback	   = sqlite_rollback;
	(*backend)->thread_init	   = sqlite_thread_init;
	(*backend)->thread_cleanup = sqlite_thread_cleanup;

	/* User */
	(*backend)->user_create		  = sqlite_user_create;
	(*backend)->user_get_by_id	  = sqlite_user_get_by_id;
	(*backend)->user_get_by_name  = sqlite_user_get_by_name;
	(*backend)->user_get_by_phone = sqlite_user_get_by_phone;
	(*backend)->user_update		  = sqlite_user_update;
	(*backend)->user_delete		  = sqlite_users_delete;
	(*backend)->user_list		  = sqlite_users_list;

	/* SMS */
	(*backend)->save_sms_code	= sqlite_save_sms_code;
	(*backend)->get_sms_code	= sqlite_get_sms_code;
	(*backend)->delete_sms_code = sqlite_delete_sms_code;

	/* Role */
	(*backend)->role_create		 = sqlite_role_create;
	(*backend)->role_get_by_id	 = sqlite_role_get_by_id;
	(*backend)->role_get_by_name = sqlite_role_get_by_name;
	(*backend)->role_update		 = sqlite_role_update;
	(*backend)->role_delete		 = sqlite_roles_delete;
	(*backend)->role_list		 = sqlite_roles_list;

	/* Group */
	(*backend)->group_create	  = sqlite_group_create;
	(*backend)->group_get_by_id	  = sqlite_group_get_by_id;
	(*backend)->group_get_by_name = sqlite_group_get_by_name;
	(*backend)->group_update	  = sqlite_group_update;
	(*backend)->group_delete	  = sqlite_groups_t_delete;
	(*backend)->group_list		  = sqlite_groups_t_list;

	/* Policy */
	(*backend)->policy_create	   = sqlite_policy_create;
	(*backend)->policy_get_by_id   = sqlite_policy_get_by_id;
	(*backend)->policy_get_by_name = sqlite_policy_get_by_name;
	(*backend)->policy_update	   = sqlite_policy_update;
	(*backend)->policy_delete	   = sqlite_policies_delete;
	(*backend)->policy_list		   = sqlite_policies_list;

	/* Assignments */
	(*backend)->assign_role_to_user		 = sqlite_assign_role_to_user;
	(*backend)->unassign_role_from_user	 = sqlite_unassign_role_user;
	(*backend)->get_user_roles			 = sqlite_get_user_roles;
	(*backend)->get_role_users			 = sqlite_get_role_users;
	(*backend)->assign_role_to_group	 = sqlite_assign_role_to_group;
	(*backend)->unassign_role_from_group = sqlite_unassign_role_group;
	(*backend)->add_user_to_group		 = sqlite_add_user_to_group;
	(*backend)->remove_user_from_group	 = sqlite_remove_user_from_group;
	(*backend)->get_user_groups			 = sqlite_get_user_groups;
	(*backend)->get_group_users			 = sqlite_get_group_users;
	(*backend)->assign_policy			 = sqlite_assign_policy;
	(*backend)->unassign_policy			 = sqlite_unassign_policy;
	(*backend)->get_policy_targets		 = sqlite_get_policy_targets;
	(*backend)->get_target_policies		 = sqlite_get_target_policies;

	/* Hierarchy */
	(*backend)->role_get_parent				  = sqlite_role_get_parent;
	(*backend)->group_get_parent			  = sqlite_group_get_parent;
	(*backend)->get_user_roles_with_ancestors = sqlite_get_user_roles_with_ancestors;

	/* OAuth */
	(*backend)->oauth_code_create	 = sqlite_oauth_code_create;
	(*backend)->oauth_code_get		 = sqlite_oauth_code_get;
	(*backend)->oauth_code_mark_used = sqlite_oauth_code_mark_used;
	(*backend)->oauth_code_cleanup	 = sqlite_oauth_code_cleanup;

	(*backend)->oauth_client_create = sqlite_oauth_client_create;
	(*backend)->oauth_client_get	= sqlite_oauth_client_get;
	(*backend)->oauth_client_update = sqlite_oauth_client_update;
	(*backend)->oauth_client_delete = sqlite_oauth_client_delete;
	(*backend)->oauth_client_list	= sqlite_oauth_client_list;

	(*backend)->refresh_token_create = sqlite_refresh_token_create;
	(*backend)->refresh_token_get	 = sqlite_refresh_token_get;
	(*backend)->refresh_token_revoke = sqlite_refresh_token_revoke;
	(*backend)->jti_revoke			 = sqlite_jti_revoke;
	(*backend)->jti_is_revoked		 = sqlite_jti_is_revoked;
	(*backend)->audit_log_write		 = sqlite_audit_log_write;
	(*backend)->audit_log_list		 = sqlite_audit_log_list;

	(*backend)->handle = priv;
	return SSO_OK;
}
