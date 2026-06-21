-- =============================================================================
-- SSO System — Seed Data
--
-- Default roles, policies, and policy-to-role assignments for initial bootstrap.
-- Uses INSERT OR IGNORE so it is safe to run on every server start.
-- The admin user is created separately by the C bootstrap (needs Argon2id).
-- =============================================================================

-- Roles -----------------------------------------------------------------------
INSERT OR IGNORE INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (1, 'admin', 'Full system access', 0, 1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

INSERT OR IGNORE INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (2, 'editor', 'Can edit content', 1, 1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

INSERT OR IGNORE INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (3, 'viewer', 'Read-only access', 2, 1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

INSERT OR IGNORE INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (4, 'user', 'Regular member', 0, 1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- Policies --------------------------------------------------------------------

-- 1. System Functions  (admin: functional permissions)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (1, 'System Functions', 1, 1, 100,
       '{"functions":[{"code":"admin:*","effect":"allow"},{"code":"user:create","effect":"allow"},{"code":"user:view","effect":"allow"},{"code":"user:delete","effect":"deny"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- 2. System API  (admin: API endpoint access)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (2, 'System API', 2, 1, 90,
       '{"endpoints":[{"method":"GET","path":"/api/v1/*","effect":"allow"},{"method":"POST","path":"/api/v1/*","effect":"allow"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- 3. Content Editor Functions  (editor: functional permissions)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (3, 'Content Editor Functions', 1, 1, 80,
       '{"functions":[{"code":"content:*","effect":"allow"},{"code":"media:*","effect":"allow"},{"code":"report:view","effect":"allow"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- 4. Content Editor API  (editor: API endpoint access)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (4, 'Content Editor API', 2, 1, 75,
       '{"endpoints":[{"method":"GET","path":"/api/v1/content/*","effect":"allow"},{"method":"POST","path":"/api/v1/content/*","effect":"allow"},{"method":"PUT","path":"/api/v1/content/*","effect":"allow"},{"method":"DELETE","path":"/api/v1/content/*","effect":"deny"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- 5. Viewer Functions  (viewer: functional permissions)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (5, 'Viewer Functions', 1, 1, 60,
       '{"functions":[{"code":"content:view","effect":"allow"},{"code":"report:view","effect":"allow"},{"code":"dashboard:view","effect":"allow"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- 6. Viewer API  (viewer: API endpoint access)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (6, 'Viewer API', 2, 1, 55,
       '{"endpoints":[{"method":"GET","path":"/api/v1/*","effect":"allow"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- 7. User Self-service  (member: functional permissions)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (7, 'User Self-service', 1, 1, 50,
       '{"functions":[{"code":"profile:view","effect":"allow"},{"code":"profile:edit","effect":"allow"},{"code":"password:change","effect":"allow"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- 8. User Self-service API  (member: API endpoint access)
INSERT OR IGNORE INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (8, 'User Self-service API', 2, 1, 45,
       '{"endpoints":[{"method":"GET","path":"/api/v1/auth/me","effect":"allow"},{"method":"POST","path":"/api/v1/auth/password","effect":"allow"},{"method":"PUT","path":"/api/v1/auth/me","effect":"allow"}]}',
        1,
        (CAST(strftime('%s','now') AS INTEGER) * 1000),
        (CAST(strftime('%s','now') AS INTEGER) * 1000));

-- Policy-to-Role Assignments --------------------------------------------------

-- Admin role → System Functions, System API
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (1, 1, 1);
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (2, 1, 1);

-- Editor role → Content Editor Functions, Content Editor API
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (3, 1, 2);
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (4, 1, 2);

-- Viewer role → Viewer Functions, Viewer API
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (5, 1, 3);
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (6, 1, 3);

-- Member role → User Self-service, User Self-service API
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (7, 1, 4);
INSERT OR IGNORE INTO policy_assignments (policy_id, target_type, target_id) VALUES (8, 1, 4);
