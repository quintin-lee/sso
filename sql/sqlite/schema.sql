-- =============================================================================
-- SSO System — Database Schema (DDL)
--
-- This file contains the complete DDL for the SSO system database.
-- It is loaded at runtime by the SQLite storage backend on first open.
-- All CREATE statements use IF NOT EXISTS for idempotency across restarts.
-- =============================================================================

-- Schema version tracking ----------------------------------------------------
CREATE TABLE IF NOT EXISTS _migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

-- Users ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    phone TEXT UNIQUE,
    password_hash TEXT,
    email TEXT DEFAULT '',
    display_name TEXT DEFAULT '',
    status INTEGER DEFAULT 1,
    created_at INTEGER DEFAULT 0,
    updated_at INTEGER DEFAULT 0,
    password_set_at INTEGER DEFAULT 0,
    attributes TEXT DEFAULT '{}',
    mfa_enabled INTEGER DEFAULT 0,
    mfa_secret TEXT DEFAULT ''
);

-- SMS verification codes -----------------------------------------------------
CREATE TABLE IF NOT EXISTS sms_codes (
    phone TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER DEFAULT 0
);

-- Roles (with hierarchy via parent_role_id) ----------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    parent_role_id INTEGER DEFAULT 0,
    status INTEGER DEFAULT 1,
    created_at INTEGER DEFAULT 0,
    updated_at INTEGER DEFAULT 0
);

-- Groups (named groups_t because "group" is a SQLite keyword) ----------------
CREATE TABLE IF NOT EXISTS groups_t (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    parent_group_id INTEGER DEFAULT 0,
    status INTEGER DEFAULT 1,
    created_at INTEGER DEFAULT 0,
    updated_at INTEGER DEFAULT 0
);

-- Policies (strategy-specific rules stored as JSON) --------------------------
CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    strategy_type INTEGER NOT NULL,
    effect INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    rules TEXT NOT NULL DEFAULT '{}',
    status INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER DEFAULT 0,
    updated_at INTEGER DEFAULT 0
);

-- Many-to-many: user ↔ role --------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id)
);

-- Many-to-many: user ↔ group -------------------------------------------------
CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_id)
);

-- Many-to-many: role ↔ group -------------------------------------------------
CREATE TABLE IF NOT EXISTS role_groups (
    role_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, group_id)
);

-- Policy assignments (policy → user / role / group) ---------------------------
CREATE TABLE IF NOT EXISTS policy_assignments (
    policy_id INTEGER,
    target_type INTEGER,
    target_id INTEGER,
    PRIMARY KEY (policy_id, target_type, target_id)
);

-- OAuth 2.0 authorization codes ----------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT DEFAULT '',
    nonce TEXT DEFAULT '',
    code_challenge TEXT DEFAULT '',
    code_challenge_method TEXT DEFAULT '',
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0
);

-- OAuth 2.0 client registrations ---------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    app_name TEXT DEFAULT '',
    app_description TEXT DEFAULT '',
    app_logo_url TEXT DEFAULT '',
    allowed_scopes TEXT DEFAULT '',
    allowed_grant_types TEXT DEFAULT '',
    token_ttl_ms INTEGER DEFAULT 0,
    status INTEGER DEFAULT 1,
    created_at INTEGER DEFAULT 0,
    updated_at INTEGER DEFAULT 0
);

-- Refresh tokens -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    client_id TEXT,
    expires_at INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    revoked INTEGER DEFAULT 0
);

-- Revoked JWT IDs (for token invalidation) -----------------------------------
CREATE TABLE IF NOT EXISTS revoked_jtis (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

-- Audit log ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    timestamp_ms INTEGER,
    user_id INTEGER,
    username TEXT,
    ip_address TEXT,
    operation TEXT,
    resource TEXT,
    resource_id INTEGER,
    status TEXT,
    details TEXT,
    duration_ms INTEGER,
    cache_hit INTEGER,
    trace TEXT
);

-- =============================================================================
-- Indexes
-- =============================================================================

-- user_roles lookups
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

-- user_groups lookups
CREATE INDEX IF NOT EXISTS idx_user_groups_user ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);

-- role_groups lookups
CREATE INDEX IF NOT EXISTS idx_role_groups_role ON role_groups(role_id);
CREATE INDEX IF NOT EXISTS idx_role_groups_group ON role_groups(group_id);

-- policy_assignments lookups
CREATE INDEX IF NOT EXISTS idx_policy_assignments_target
    ON policy_assignments(target_type, target_id);
