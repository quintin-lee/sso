#!/bin/bash
# ============================================================================
# HTTP API Integration Tests (curl-based)
#
# Tests all SSO HTTP endpoints end-to-end by:
#   1. Starting the SSO server with a test config on a dynamic port
#   2. Running curl commands against every endpoint
#   3. Validating JSON responses with basic checks
#   4. Cleaning up the server process
# ============================================================================
set -euo pipefail

PORT="${SSO_TEST_PORT:-18080}"
BASE="http://127.0.0.1:${PORT}"
PASSED=0
FAILED=0
SERVER_PID=""

# Colours
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { PASSED=$((PASSED+1)); echo -e "  ${GREEN}PASS${NC}: $1"; }
fail() { FAILED=$((FAILED+1)); echo -e "  ${RED}FAIL${NC}: $1"; }

# --- Setup: test config + server ---
setup() {
    local test_dir
    test_dir="$(mktemp -d)"
    cat > "${test_dir}/sso.toml" <<EOF
[server]
host = "127.0.0.1"
port = ${PORT}
thread_pool_size = 2
queue_size = 64

[database]
path = "${test_dir}/sso_test.db"

[logging]
level = "error"

[ratelimit]
max_ips = 100

[oauth]
client_id = "test-client"
client_secret = "test-secret"
redirect_uris = "http://localhost:3000/callback"
issuer = "http://localhost:${PORT}"
auth_code_ttl_ms = 30000
EOF

    echo "=== Starting SSO server on port ${PORT} ==="
    export SSO_TOKEN_SECRET="test-token-secret-32-bytes-long!!"
    export SSO_ADMIN_PASSWORD="Admin@123"
    export SSO_OAUTH_CLIENT_ID="test-client"
    export SSO_OAUTH_CLIENT_SECRET="test-secret"

    # Use a temp directory for working dir so the binary finds sso.toml
    cp sso_system "${test_dir}/"
    cd "${test_dir}"
    ./sso_system --server &
    SERVER_PID=$!
    cd - >/dev/null

    # Wait for server to be ready
    for i in $(seq 1 30); do
        if curl -sf "${BASE}/api/v1/health" >/dev/null 2>&1; then
            echo "  Server ready (attempt $i)"
            return 0
        fi
        sleep 0.3
    done
    echo "  Server failed to start within 10s"
    return 1
}

# --- Teardown ---
teardown() {
    if [ -n "$SERVER_PID" ]; then
        echo "  Stopping server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

# --- Helpers ---
extract_json() {
    # Extract a value from JSON by key (simple, doesn't handle nesting)
    local key="$1"
    echo "$2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('${key}',''))" 2>/dev/null || echo ""
}

# --- Test suites ---
test_health() {
    echo ""
    echo "--- Health Endpoint ---"
    local resp
    resp=$(curl -sf "${BASE}/api/v1/health" 2>&1) || { fail "health endpoint (curl exit $?)"; return; }
    local status
    status=$(extract_json "status" "$resp")
    if [ "$status" = "ok" ]; then pass "health endpoint returns ok"; else fail "health endpoint expected ok, got: $resp"; fi
}

test_login() {
    echo ""
    echo "--- Authentication ---"

    # Login with bootstrap admin
    local resp
    resp=$(curl -sf -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Admin@123"}' 2>&1) || { fail "login"; return; }

    TOKEN=$(extract_json "token" "$resp")
    if [ -z "$TOKEN" ]; then
        # Try to get token from X-SSO-Access-Token header instead
        # The login endpoint returns token in header
        TOKEN=$(echo "$resp" | grep -oP 'X-SSO-Access-Token: \K\S+' || echo "")
    fi

    # The login endpoint stores token in header X-SSO-Access-Token, but curl -sf doesn't show headers
    # Re-login with -D to capture headers
    local headers
    headers=$(mktemp)
    resp=$(curl -sf -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Admin@123"}' \
        -D "$headers" 2>&1) || { fail "login (header capture)"; rm -f "$headers"; return; }

    TOKEN=$(grep -i 'X-SSO-Access-Token:' "$headers" | sed 's/.*: //' | tr -d '\r\n')
    rm -f "$headers"

    if [ -z "$TOKEN" ]; then
        fail "login - no access token in response headers"
        return
    fi
    pass "login with admin credentials (token: ${TOKEN:0:16}...)"

    # Verify token
    local verify_resp
    verify_resp=$(curl -sf -X POST "${BASE}/api/v1/auth/verify" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"${TOKEN}\"}" 2>&1) || { fail "verify token"; return; }
    local valid
    valid=$(extract_json "valid" "$verify_resp")
    if [ "$valid" = "True" ] || [ "$valid" = "true" ]; then
        pass "verify token - valid"
    else
        fail "verify token - expected true, got: $verify_resp"
    fi

    # Refresh token
    # The login also sets X-SSO-Refresh-Token
    # Re-login to get both tokens
    local headers2
    headers2=$(mktemp)
    resp=$(curl -sf -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Admin@123"}' \
        -D "$headers2" 2>&1)
    local REFRESH
    REFRESH=$(grep -i 'X-SSO-Refresh-Token:' "$headers2" | sed 's/.*: //' | tr -d '\r\n')
    local ACCESS2
    ACCESS2=$(grep -i 'X-SSO-Access-Token:' "$headers2" | sed 's/.*: //' | tr -d '\r\n')
    rm -f "$headers2"

    if [ -n "$REFRESH" ]; then
        local refresh_resp
        refresh_resp=$(curl -sf -X POST "${BASE}/api/v1/auth/refresh" \
            -H "Content-Type: application/json" \
            -d "{\"refresh_token\":\"${REFRESH}\"}" 2>&1) || { fail "refresh token"; }
        # The refresh returns status in JSON body: {"status":"refreshed"}
        local ref_status
        ref_status=$(extract_json "status" "$refresh_resp")
        if [ "$ref_status" = "refreshed" ]; then pass "refresh token"; else fail "refresh token - unexpected: $refresh_resp"; fi
    else
        fail "refresh token - no refresh token available"
    fi

    # Wrong password
    local fail_resp
    fail_resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"wrong"}') && true
    if [ "$fail_resp" = "401" ]; then pass "login rejects wrong password (HTTP $fail_resp)"; else fail "login wrong password expected 401 got $fail_resp"; fi

    # Register new user
    local reg_resp
    reg_resp=$(curl -sf -X POST "${BASE}/api/v1/auth/register" \
        -H "Content-Type: application/json" \
        -d '{"username":"testuser","password":"Test@1234","email":"test@example.com"}' 2>&1) || { fail "register user"; }
    local created
    created=$(extract_json "created" "$reg_resp")
    if [ "$created" = "True" ] || [ "$created" = "true" ]; then pass "register new user"; else fail "register - unexpected: $reg_resp"; fi
}

test_management_crud() {
    echo ""
    echo "--- Management CRUD ---"

    # Need a valid token for admin endpoints
    local headers
    headers=$(mktemp)
    curl -sf -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Admin@123"}' \
        -D "$headers" >/dev/null 2>&1
    local ADMIN_TOKEN
    ADMIN_TOKEN=$(grep -i 'X-SSO-Access-Token:' "$headers" | sed 's/.*: //' | tr -d '\r\n')
    rm -f "$headers"
    local AUTH="Authorization: Bearer ${ADMIN_TOKEN}"

    # List users
    local users_resp
    users_resp=$(curl -sf "${BASE}/api/v1/users" -H "$AUTH" 2>&1) || { fail "list users"; return; }
    local total
    total=$(extract_json "total" "$users_resp")
    if [ -n "$total" ] && [ "$total" -ge 1 ]; then pass "list users ($total users)"; else fail "list users - unexpected: $users_resp"; fi

    # Create role
    local role_resp
    role_resp=$(curl -sf -X POST "${BASE}/api/v1/roles" \
        -H "Content-Type: application/json" \
        -H "$AUTH" \
        -d '{"name":"developer","description":"Developer role"}' 2>&1) || { fail "create role"; }
    local role_created
    role_created=$(extract_json "created" "$role_resp")
    if [ "$role_created" = "True" ] || [ "$role_created" = "true" ]; then pass "create role"; else fail "create role - unexpected: $role_resp"; fi

    # List roles
    local roles_resp
    roles_resp=$(curl -sf "${BASE}/api/v1/roles" -H "$AUTH" 2>&1) || { fail "list roles"; }
    local role_total
    role_total=$(extract_json "total" "$roles_resp")
    if [ -n "$role_total" ] && [ "$role_total" -ge 1 ]; then pass "list roles ($role_total roles)"; else fail "list roles - unexpected: $roles_resp"; fi

    # Create group
    local group_resp
    group_resp=$(curl -sf -X POST "${BASE}/api/v1/groups" \
        -H "Content-Type: application/json" \
        -H "$AUTH" \
        -d '{"name":"dev-team","description":"Development team"}' 2>&1) || { fail "create group"; }
    local group_created
    group_created=$(extract_json "created" "$group_resp")
    if [ "$group_created" = "True" ] || [ "$group_created" = "true" ]; then pass "create group"; else fail "create group - unexpected: $group_resp"; fi
}

test_oauth_endpoints() {
    echo ""
    echo "--- OAuth 2.0 / OIDC Endpoints ---"

    # Get admin token
    local headers
    headers=$(mktemp)
    curl -sf -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Admin@123"}' \
        -D "$headers" >/dev/null 2>&1
    local ADMIN_TOKEN
    ADMIN_TOKEN=$(grep -i 'X-SSO-Access-Token:' "$headers" | sed 's/.*: //' | tr -d '\r\n')
    rm -f "$headers"
    local AUTH="Authorization: Bearer ${ADMIN_TOKEN}"

    # 1. OIDC Discovery
    local oidc
    oidc=$(curl -sf "${BASE}/.well-known/openid-configuration" 2>&1) || { fail "OIDC discovery"; }
    local issuer
    issuer=$(extract_json "issuer" "$oidc")
    if [ -n "$issuer" ]; then pass "OIDC discovery (issuer: $issuer)"; else fail "OIDC discovery - no issuer: $oidc"; fi

    # 2. JWKS endpoint
    local jwks
    jwks=$(curl -sf "${BASE}/api/v1/auth/jwks" 2>&1) || { fail "JWKS endpoint"; }
    local jwks_keys
    jwks_keys=$(echo "$jwks" | grep -o '"keys"' || echo "")
    if [ -n "$jwks_keys" ]; then pass "JWKS endpoint"; else fail "JWKS - unexpected: $jwks"; fi

    # 3. UserInfo endpoint
    local ui_resp
    ui_resp=$(curl -sf "${BASE}/api/v1/auth/userinfo" -H "$AUTH" 2>&1) || { fail "UserInfo endpoint"; }
    local sub
    sub=$(extract_json "sub" "$ui_resp")
    if [ -n "$sub" ]; then pass "UserInfo (sub: $sub)"; else fail "UserInfo - no sub: $ui_resp"; fi

    # 4. OAuth Authorize endpoint — returns 302 with Location header
    local authz_headers
    authz_headers=$(mktemp)
    local authz_http_code
    authz_http_code=$(curl -s -o /dev/null -w "%{http_code}" -D "$authz_headers" \
        "${BASE}/api/v1/oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&scope=openid+profile" \
        -H "$AUTH" 2>&1) || true
    local location_header
    location_header=$(grep -i '^Location:' "$authz_headers" | sed 's/.*: //' | tr -d '\r\n')
    local authz_code
    authz_code=$(echo "$location_header" | sed 's/.*code=\([a-f0-9]*\).*/\1/')
    rm -f "$authz_headers"
    if [ "$authz_http_code" != "302" ]; then
        fail "OAuth authorize expected HTTP 302 got $authz_http_code"
        return
    fi
    if [ -n "$authz_code" ]; then
        pass "OAuth authorize (code: ${authz_code:0:16}...)"
    else
        fail "OAuth authorize - no code in response"
        return
    fi

    # 5. OAuth Token (authorization_code grant)
    local token_resp
    token_resp=$(curl -sf -X POST "${BASE}/api/v1/oauth/token" \
        -H "Content-Type: application/json" \
        -d "{\"grant_type\":\"authorization_code\",\"code\":\"${authz_code}\",\"redirect_uri\":\"http://localhost:3000/callback\",\"client_id\":\"test-client\",\"client_secret\":\"test-secret\"}" 2>&1) || { fail "OAuth token exchange"; }
    
    local access_token
    access_token=$(extract_json "access_token" "$token_resp")
    local id_token
    id_token=$(extract_json "id_token" "$token_resp")
    if [ -n "$access_token" ]; then pass "OAuth token exchange (access_token: ${access_token:0:16}...)"; else fail "OAuth token - no access_token: $token_resp"; fi
    if [ -n "$id_token" ]; then pass "OAuth ID token present (${id_token:0:16}...)"; fi

    # 6. OAuth Introspect
    local intro_resp
    intro_resp=$(curl -sf -X POST "${BASE}/api/v1/oauth/introspect" \
        -H "Content-Type: application/json" \
        -H "$AUTH" \
        -d "{\"token\":\"${access_token}\"}" 2>&1) || { fail "OAuth introspect"; }
    local active
    active=$(extract_json "active" "$intro_resp")
    if [ "$active" = "True" ] || [ "$active" = "true" ]; then pass "OAuth introspect (active: $active)"; else fail "OAuth introspect - not active: $intro_resp"; fi

    # 7. OAuth Revoke (always returns 200)
    local revoke_code
    revoke_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/api/v1/oauth/revoke" \
        -H "Content-Type: application/json" \
        -H "$AUTH" \
        -d "{\"token\":\"${access_token}\"}" 2>&1) || true
    if [ "$revoke_code" = "200" ]; then pass "OAuth revoke (HTTP 200)"; else fail "OAuth revoke expected 200 got $revoke_code"; fi
}

test_permission_checks() {
    echo ""
    echo "--- Permission Check Endpoints ---"

    # Get admin token
    local headers
    headers=$(mktemp)
    curl -sf -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Admin@123"}' \
        -D "$headers" >/dev/null 2>&1
    local ADMIN_TOKEN
    ADMIN_TOKEN=$(grep -i 'X-SSO-Access-Token:' "$headers" | sed 's/.*: //' | tr -d '\r\n')
    rm -f "$headers"
    local AUTH="Authorization: Bearer ${ADMIN_TOKEN}"

    # Functional check
    local func_resp
    func_resp=$(curl -sf -X POST "${BASE}/api/v1/check/functional" \
        -H "Content-Type: application/json" \
        -H "$AUTH" \
        -d '{"function_code":"user:view","user_id":1}' 2>&1) || { fail "functional check"; }
    local allowed
    allowed=$(extract_json "allowed" "$func_resp")
    if [ "$allowed" = "True" ] || [ "$allowed" = "true" ]; then pass "functional check (allowed: $allowed)"; else fail "functional check - unexpected: $func_resp"; fi

    # API check
    local api_resp
    api_resp=$(curl -sf -X POST "${BASE}/api/v1/check/api" \
        -H "Content-Type: application/json" \
        -H "$AUTH" \
        -d '{"method":"GET","path":"/api/v1/users","user_id":1}' 2>&1) || { fail "api check"; }
    allowed=$(extract_json "allowed" "$api_resp")
    if [ "$allowed" = "True" ] || [ "$allowed" = "true" ]; then pass "API check (allowed: $allowed)"; else fail "API check - unexpected: $api_resp"; fi
}

test_metrics() {
    echo ""
    echo "--- Metrics Endpoint ---"

    local resp
    resp=$(curl -sf "${BASE}/metrics" -H "Authorization: Bearer test" 2>&1) || true
    # Metrics endpoint requires auth, just check it returns something
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/metrics" -H "Authorization: Bearer test" 2>&1) || true
    # With invalid token we get 401, test with valid token
    local headers
    headers=$(mktemp)
    curl -sf -X POST "${BASE}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Admin@123"}' \
        -D "$headers" >/dev/null 2>&1
    local ADMIN_TOKEN
    ADMIN_TOKEN=$(grep -i 'X-SSO-Access-Token:' "$headers" | sed 's/.*: //' | tr -d '\r\n')
    rm -f "$headers"

    local metrics_resp
    metrics_resp=$(curl -sf "${BASE}/metrics" -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>&1) || { fail "metrics endpoint"; }
    if echo "$metrics_resp" | grep -q "perm_"; then pass "metrics endpoint (contains perm_ metrics)"; else fail "metrics - unexpected: $(echo "$metrics_resp" | head -c 100)"; fi
}

test_pages() {
    echo ""
    echo "--- HTML Pages ---"

    # Login page
    local page_code
    page_code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/" 2>&1)
    if [ "$page_code" = "200" ]; then pass "login page (HTTP 200)"; else fail "login page expected 200 got $page_code"; fi
}

# --- Summary ---
summary() {
    local total=$((PASSED + FAILED))
    echo ""
    echo "========================================="
    echo "  Integration Test Results"
    echo "  Passed: ${PASSED}/${total}"
    echo "  Failed: ${FAILED}/${total}"
    echo "========================================="
    if [ "$FAILED" -gt 0 ]; then
        return 1
    fi
    return 0
}

# --- Main ---
cleanup() {
    teardown
}
trap cleanup EXIT INT TERM

if ! setup; then
    echo "FAILED to start server"
    exit 1
fi

test_health
test_login
test_oauth_endpoints
test_permission_checks
test_management_crud
test_metrics
test_pages

summary
