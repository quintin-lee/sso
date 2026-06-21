-- =============================================================================
-- SSO System — Seed Data (PostgreSQL)
--
-- Default roles, policies, and policy-to-role assignments for initial bootstrap.
-- Uses INSERT ... ON CONFLICT DO NOTHING for idempotency across restarts.
-- The admin user is created separately by the C bootstrap (needs Argon2id).
-- =============================================================================

-- Roles -----------------------------------------------------------------------
INSERT INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (1, 'admin', 'Full system access', 0, 1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (2, 'editor', 'Can edit content', 1, 1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (3, 'viewer', 'Read-only access', 2, 1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

INSERT INTO roles (id, name, description, parent_role_id, status, created_at, updated_at)
VALUES (4, 'user', 'Regular member', 0, 1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- Policies --------------------------------------------------------------------

-- 1. System Functions  (admin: functional permissions)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (1, 'System Functions', 1, 1, 100,
       '{"functions":[{"code":"admin:*","effect":"allow"},{"code":"user:create","effect":"allow"},{"code":"user:view","effect":"allow"},{"code":"user:delete","effect":"deny"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- 2. System API  (admin: API endpoint access)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (2, 'System API', 2, 1, 90,
       '{"endpoints":[{"method":"GET","path":"/api/v1/*","effect":"allow"},{"method":"POST","path":"/api/v1/*","effect":"allow"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- 3. Content Editor Functions  (editor: functional permissions)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (3, 'Content Editor Functions', 1, 1, 80,
       '{"functions":[{"code":"content:*","effect":"allow"},{"code":"media:*","effect":"allow"},{"code":"report:view","effect":"allow"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- 4. Content Editor API  (editor: API endpoint access)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (4, 'Content Editor API', 2, 1, 75,
       '{"endpoints":[{"method":"GET","path":"/api/v1/content/*","effect":"allow"},{"method":"POST","path":"/api/v1/content/*","effect":"allow"},{"method":"PUT","path":"/api/v1/content/*","effect":"allow"},{"method":"DELETE","path":"/api/v1/content/*","effect":"deny"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- 5. Viewer Functions  (viewer: functional permissions)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (5, 'Viewer Functions', 1, 1, 60,
       '{"functions":[{"code":"content:view","effect":"allow"},{"code":"report:view","effect":"allow"},{"code":"dashboard:view","effect":"allow"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- 6. Viewer API  (viewer: API endpoint access)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (6, 'Viewer API', 2, 1, 55,
       '{"endpoints":[{"method":"GET","path":"/api/v1/*","effect":"allow"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- 7. User Self-service  (member: functional permissions)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (7, 'User Self-service', 1, 1, 50,
       '{"functions":[{"code":"profile:view","effect":"allow"},{"code":"profile:edit","effect":"allow"},{"code":"password:change","effect":"allow"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- 8. User Self-service API  (member: API endpoint access)
INSERT INTO policies
    (id, name, strategy_type, effect, priority, rules, status, created_at, updated_at)
VALUES (8, 'User Self-service API', 2, 1, 45,
       '{"endpoints":[{"method":"GET","path":"/api/v1/auth/me","effect":"allow"},{"method":"POST","path":"/api/v1/auth/password","effect":"allow"},{"method":"PUT","path":"/api/v1/auth/me","effect":"allow"}]}',
        1,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT,
        (EXTRACT(EPOCH FROM NOW()) * 1000)::BIGINT)
ON CONFLICT (id) DO NOTHING;

-- Policy-to-Role Assignments --------------------------------------------------

-- Admin role → System Functions, System API
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (1, 1, 1) ON CONFLICT DO NOTHING;
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (2, 1, 1) ON CONFLICT DO NOTHING;

-- Editor role → Content Editor Functions, Content Editor API
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (3, 1, 2) ON CONFLICT DO NOTHING;
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (4, 1, 2) ON CONFLICT DO NOTHING;

-- Viewer role → Viewer Functions, Viewer API
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (5, 1, 3) ON CONFLICT DO NOTHING;
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (6, 1, 3) ON CONFLICT DO NOTHING;

-- Member role → User Self-service, User Self-service API
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (7, 1, 4) ON CONFLICT DO NOTHING;
INSERT INTO policy_assignments (policy_id, target_type, target_id)
VALUES (8, 1, 4) ON CONFLICT DO NOTHING;
