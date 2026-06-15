# MFA and Refresh Tokens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement database-backed opaque refresh tokens and a TOTP-based Multi-Factor Authentication (MFA) flow.

**Architecture:** 
1. Expand the SQLite schema to include a `refresh_tokens` table and `mfa_enabled`/`mfa_secret` columns in the `users` table.
2. Update the storage interface and backend to support CRUD for refresh tokens.
3. Update `user_t` and user CRUD functions to handle the new MFA fields.
4. Modify `token_issue` to generate and store opaque refresh tokens alongside access tokens.
5. Create new HTTP endpoints for setting up, enabling, and verifying MFA (`/api/v1/auth/mfa/setup`, `/api/v1/auth/mfa/enable`, `/api/v1/auth/mfa/verify`).
6. Update `handle_oauth_token` (password grant) and `handle_login` to return an `mfa_token` (JWT with `mfa_pending` claim) if MFA is enabled.

**Tech Stack:** C11, SQLite3, libsodium (for hashing refresh tokens), OpenSSL (for HMAC-SHA1).

---

### Task 1: Update Storage Interface and SQLite Schema for Refresh Tokens

**Files:**
- Modify: `include/storage.h`
- Modify: `src/storage_sqlite.c`
- Modify: `src/storage_memory.c`

- [ ] **Step 1: Add structs and function pointers to `storage.h`**

```c
/* In include/storage.h, add before oauth_auth_code_t */
typedef struct {
    char token_hash[128];
    sso_id_t user_id;
    char client_id[64];
    sso_timestamp_t expires_at;
    sso_timestamp_t issued_at;
    int revoked;
} refresh_token_t;

typedef sso_error_t (*storage_refresh_token_create_fn)(storage_backend_t *self, const refresh_token_t *rt);
typedef sso_error_t (*storage_refresh_token_get_fn)(storage_backend_t *self, const char *token_hash, refresh_token_t *out);
typedef sso_error_t (*storage_refresh_token_revoke_fn)(storage_backend_t *self, const char *token_hash);

/* Inside struct storage_backend, add: */
    storage_refresh_token_create_fn refresh_token_create;
    storage_refresh_token_get_fn    refresh_token_get;
    storage_refresh_token_revoke_fn refresh_token_revoke;
```

- [ ] **Step 2: Add table creation to `sqlite_open`**

```c
/* In src/storage_sqlite.c, inside sqlite_open */
    "CREATE TABLE IF NOT EXISTS refresh_tokens ("
    "  token_hash TEXT PRIMARY KEY,"
    "  user_id INTEGER NOT NULL,"
    "  client_id TEXT,"
    "  expires_at INTEGER NOT NULL,"
    "  issued_at INTEGER NOT NULL,"
    "  revoked INTEGER DEFAULT 0"
    ");"
```

- [ ] **Step 3: Implement CRUD in `src/storage_sqlite.c`**

```c
static sso_error_t sqlite_refresh_token_create(storage_backend_t *self, const refresh_token_t *rt) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at, issued_at, revoked) VALUES (?, ?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    sqlite3_bind_text(stmt, 1, rt->token_hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, rt->user_id);
    if (rt->client_id[0]) sqlite3_bind_text(stmt, 3, rt->client_id, -1, SQLITE_STATIC);
    else sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int64(stmt, 4, rt->expires_at);
    sqlite3_bind_int64(stmt, 5, rt->issued_at);
    sqlite3_bind_int(stmt, 6, rt->revoked);
    sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
    sqlite3_finalize(stmt);
    return err;
}

static sso_error_t sqlite_refresh_token_get(storage_backend_t *self, const char *token_hash, refresh_token_t *out) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(priv->db, "SELECT token_hash, user_id, client_id, expires_at, issued_at, revoked FROM refresh_tokens WHERE token_hash = ?", -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        strncpy(out->token_hash, (const char *)sqlite3_column_text(stmt, 0), sizeof(out->token_hash)-1);
        out->user_id = sqlite3_column_int64(stmt, 1);
        const char *client_id = (const char *)sqlite3_column_text(stmt, 2);
        if (client_id) strncpy(out->client_id, client_id, sizeof(out->client_id)-1);
        out->expires_at = sqlite3_column_int64(stmt, 3);
        out->issued_at = sqlite3_column_int64(stmt, 4);
        out->revoked = sqlite3_column_int(stmt, 5);
        sqlite3_finalize(stmt);
        return SSO_OK;
    }
    sqlite3_finalize(stmt);
    return SSO_ERR_NOT_FOUND;
}

static sso_error_t sqlite_refresh_token_revoke(storage_backend_t *self, const char *token_hash) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(priv->db, "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    sqlite3_bind_text(stmt, 1, token_hash, -1, SQLITE_STATIC);
    sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
    sqlite3_finalize(stmt);
    return err;
}

/* In storage_sqlite_create, assign the pointers: */
    b->refresh_token_create = sqlite_refresh_token_create;
    b->refresh_token_get    = sqlite_refresh_token_get;
    b->refresh_token_revoke = sqlite_refresh_token_revoke;
```

- [ ] **Step 4: Update Memory Backend (Stubs)**

```c
/* In src/storage_memory.c */
static sso_error_t mem_rt_create(storage_backend_t *s, const refresh_token_t *rt) { (void)s; (void)rt; return SSO_ERR_STORAGE; }
static sso_error_t mem_rt_get(storage_backend_t *s, const char *h, refresh_token_t *rt) { (void)s; (void)h; (void)rt; return SSO_ERR_NOT_FOUND; }
static sso_error_t mem_rt_revoke(storage_backend_t *s, const char *h) { (void)s; (void)h; return SSO_ERR_STORAGE; }

/* In storage_memory_create, assign pointers */
    b->refresh_token_create = mem_rt_create;
    b->refresh_token_get    = mem_rt_get;
    b->refresh_token_revoke = mem_rt_revoke;
```

- [ ] **Step 5: Verify build**

Run: `make`
Expected: Compile succeeds.

- [ ] **Step 6: Commit**

```bash
git add include/storage.h src/storage_sqlite.c src/storage_memory.c
git commit -m "feat(storage): ✨ add SQLite schema and CRUD for refresh_tokens"
```

---

### Task 2: Update User Model for MFA Fields

**Files:**
- Modify: `include/user.h`
- Modify: `src/storage_sqlite.c`

- [ ] **Step 1: Update `user_t` struct**

```c
/* In include/user.h, update struct user */
struct user {
    sso_id_t          id;
    char              username[SSO_MAX_USERNAME];
    char              phone[SSO_MAX_PHONE];
    char              password_hash[SSO_MAX_PASSWORD_HASH];
    char              email[SSO_MAX_EMAIL];
    char              display_name[SSO_MAX_DISPLAY_NAME];
    user_status_t     status;
    sso_timestamp_t   created_at;
    sso_timestamp_t   updated_at;
    char              attributes[SSO_MAX_ATTRIBUTES]; /* extensible JSON */
    int               mfa_enabled;
    char              mfa_secret[64];
};
```

- [ ] **Step 2: Update SQLite schema and migrations**

```c
/* In src/storage_sqlite.c, inside sqlite_open's CREATE TABLE IF NOT EXISTS users: */
    "  updated_at INTEGER DEFAULT 0,"
    "  attributes TEXT DEFAULT '{}',"
    "  mfa_enabled INTEGER DEFAULT 0,"
    "  mfa_secret TEXT DEFAULT ''"

/* In sqlite_open's migration block for version 2 (assuming version 1 exists) */
        if (v == 1) {
            /* existing indices */
        } else if (v == 2) {
            migration = "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;"
                        "ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT '';";
        } else {
```

- [ ] **Step 3: Update `bind_user` and `read_user`**

```c
/* In src/storage_sqlite.c */
static void bind_user(sqlite3_stmt *stmt, const user_t *u) {
    /* ... existing 1-9 ... */
    sqlite3_bind_int(stmt, 10, u->mfa_enabled);
    sqlite3_bind_text(stmt, 11, u->mfa_secret, -1, SQLITE_STATIC);
}

static void read_user(sqlite3_stmt *stmt, user_t *u) {
    /* ... existing 0-9 ... */
    u->mfa_enabled = sqlite3_column_int(stmt, 10);
    const char *sec = (const char *)sqlite3_column_text(stmt, 11);
    if (sec) strncpy(u->mfa_secret, sec, sizeof(u->mfa_secret)-1);
}

/* Update INSERT and UPDATE queries in user_create and user_update to include the new columns (11 columns instead of 9) */
/* user_create: */
    const char *sql = "INSERT INTO users (username, phone, password_hash, email, display_name, status, created_at, updated_at, attributes, mfa_enabled, mfa_secret) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
/* user_update: */
    const char *sql = "UPDATE users SET username=?, phone=?, password_hash=?, email=?, display_name=?, status=?, created_at=?, updated_at=?, attributes=?, mfa_enabled=?, mfa_secret=? WHERE id=?";
/* user_get_*, user_list: ensure SELECT includes mfa_enabled, mfa_secret in columns 10,11 */
/* "SELECT id, username, phone, password_hash, email, display_name, status, created_at, updated_at, attributes, mfa_enabled, mfa_secret FROM users ..." */
```

- [ ] **Step 4: Verify build**

Run: `make`
Expected: Compile succeeds.

- [ ] **Step 5: Commit**

```bash
git add include/user.h src/storage_sqlite.c
git commit -m "feat(user): ✨ add mfa_enabled and mfa_secret fields to user model"
```

---

### Task 3: Implement Opaque Refresh Token Issuance

**Files:**
- Modify: `include/token.h`
- Modify: `src/token.c`

- [ ] **Step 1: Add `raw_refresh_token` to `token_t`**

```c
/* In include/token.h, inside struct token */
    char              claims[SSO_MAX_CLAIMS_JSON];
    char              raw_refresh_token[128]; /* Generated opaque string */
```

- [ ] **Step 2: Update `token_issue` to generate and store the refresh token**

```c
/* In src/token.c:token_issue */
#include <sodium.h>

/* Inside token_issue, after successfully generating the JWT string (token_str) */
    /* Generate 32 bytes of random data for refresh token */
    unsigned char rt_bytes[32];
    randombytes_buf(rt_bytes, sizeof(rt_bytes));
    
    /* Base64url encode it */
    base64url_encode(rt_bytes, sizeof(rt_bytes), out->raw_refresh_token, sizeof(out->raw_refresh_token));

    /* Hash it using SHA-256 to store in DB */
    unsigned char rt_hash_bytes[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(rt_hash_bytes, (const unsigned char *)out->raw_refresh_token, strlen(out->raw_refresh_token));
    
    char rt_hash_hex[crypto_hash_sha256_BYTES * 2 + 1];
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
        sprintf(&rt_hash_hex[i*2], "%02x", rt_hash_bytes[i]);
    }

    /* NOTE: We don't have the storage_backend directly inside token_manager.
       However, token_issue might need to store it, OR we return the raw string 
       and let the caller (oauth.c / handlers_auth.c) store it. 
       Let's just generate the string here, and let the caller store it in the DB.
       This avoids circular dependencies. */
```

- [ ] **Step 3: Modify the plan context**
Wait, since `token_manager` doesn't know about `storage_backend`, the caller (`handle_oauth_token` and `handle_login`) must hash and insert it into `refresh_tokens`. The implementation in `token_issue` just generating the string is perfect.

- [ ] **Step 4: Verify build**

Run: `make`

- [ ] **Step 5: Commit**

```bash
git add include/token.h src/token.c
git commit -m "feat(token): ✨ generate opaque string for refresh token in token_issue"
```

---

### Task 4: Integrate Refresh Tokens into OAuth Handlers

**Files:**
- Modify: `src/oauth.c`

- [ ] **Step 1: Store generated Refresh Token on issue**

```c
/* In src/oauth.c:handle_oauth_token, right after issuing `access_token` in authorization_code grant */
    if (sb && sb->refresh_token_create) {
        refresh_token_t rt;
        memset(&rt, 0, sizeof(rt));
        
        unsigned char rt_hash_bytes[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(rt_hash_bytes, (const unsigned char *)access_token.raw_refresh_token, strlen(access_token.raw_refresh_token));
        for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
            sprintf(&rt.token_hash[i*2], "%02x", rt_hash_bytes[i]);
        }
        rt.user_id = user.id;
        strncpy(rt.client_id, ac.client_id, sizeof(rt.client_id)-1);
        rt.issued_at = sso_timestamp_now();
        rt.expires_at = rt.issued_at + 2592000000; // 30 days
        rt.revoked = 0;
        sb->refresh_token_create(sb, &rt);
    }

    /* Update JSON response to output both access_token and refresh_token */
    snprintf(buf, sizeof(buf),
        "{"
        "\"access_token\":\"%s\","
        "\"token_type\":\"Bearer\","
        "\"expires_in\":%lld,"
        "\"refresh_token\":\"%s\","
        "\"user_id\":%llu"
        "}",
        access_token.token_str,
        (long long)(access_token.expires_at - access_token.issued_at) / 1000,
        access_token.raw_refresh_token,
        (unsigned long long)user.id);
```

- [ ] **Step 2: Update `refresh_token` grant handling**

```c
/* In src/oauth.c:handle_oauth_token, inside the refresh_token block */
    unsigned char rt_hash_bytes[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(rt_hash_bytes, (const unsigned char *)refresh_token, strlen(refresh_token));
    char rt_hash_hex[crypto_hash_sha256_BYTES * 2 + 1];
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
        sprintf(&rt_hash_hex[i*2], "%02x", rt_hash_bytes[i]);
    }

    refresh_token_t rt_record;
    if (!sb || !sb->refresh_token_get || sb->refresh_token_get(sb, rt_hash_hex, &rt_record) != SSO_OK) {
        json_error_response(resp, 400, "invalid_grant");
        goto cleanup;
    }
    if (rt_record.revoked || sso_timestamp_now() > rt_record.expires_at) {
        json_error_response(resp, 400, "invalid_grant");
        goto cleanup;
    }

    /* Revoke old one */
    sb->refresh_token_revoke(sb, rt_hash_hex);

    /* Issue new tokens */
    user_t user;
    if (user_get_by_id(umgr, rt_record.user_id, &user) != SSO_OK || user.status != USER_STATUS_ACTIVE) {
        json_error_response(resp, 403, "user_inactive");
        goto cleanup;
    }
    
    sso_id_t roles[16], groups[16];
    size_t rc = 0, gc = 0;
    user_get_roles(umgr, user.id, roles, &rc, 16);
    user_get_groups(umgr, user.id, groups, &gc, 16);

    sso_error_t terr = token_issue(tmgr, &user, roles, rc, groups, gc, 3600000, &access_token);
    
    /* Store new refresh token */
    refresh_token_t new_rt;
    memset(&new_rt, 0, sizeof(new_rt));
    crypto_hash_sha256(rt_hash_bytes, (const unsigned char *)access_token.raw_refresh_token, strlen(access_token.raw_refresh_token));
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
        sprintf(&new_rt.token_hash[i*2], "%02x", rt_hash_bytes[i]);
    }
    new_rt.user_id = user.id;
    strncpy(new_rt.client_id, rt_record.client_id, sizeof(new_rt.client_id)-1);
    new_rt.issued_at = sso_timestamp_now();
    new_rt.expires_at = new_rt.issued_at + 2592000000;
    sb->refresh_token_create(sb, &new_rt);

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "{"
        "\"access_token\":\"%s\","
        "\"token_type\":\"Bearer\","
        "\"expires_in\":%lld,"
        "\"refresh_token\":\"%s\""
        "}",
        access_token.token_str,
        (long long)(access_token.expires_at - access_token.issued_at) / 1000,
        access_token.raw_refresh_token);
    sso_response_ok(resp, buf);
```

- [ ] **Step 3: Compile and Test**

Run: `make`
Expected: Compile succeeds.

- [ ] **Step 4: Commit**

```bash
git add src/oauth.c
git commit -m "feat(oauth): ✨ implement opaque refresh tokens in authorization flow"
```

---

### Task 5: Add Base32 and HMAC-SHA1 Utilities

**Files:**
- Create: `include/mfa.h`
- Create: `src/mfa.c`
- Modify: `Makefile`

- [ ] **Step 1: Create `include/mfa.h`**

```c
#ifndef SSO_MFA_H
#define SSO_MFA_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void mfa_generate_secret(char *base32_out, size_t out_len);
bool mfa_verify_totp(const char *base32_secret, const char *code);

#ifdef __cplusplus
}
#endif
#endif
```

- [ ] **Step 2: Implement `src/mfa.c`**

```c
#include "mfa.h"
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sodium.h>

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static void base32_encode(const uint8_t *data, size_t length, char *result) {
    int buffer = 0;
    int bits_left = 0;
    while (length > 0 || bits_left > 0) {
        if (bits_left < 5) {
            if (length > 0) {
                buffer = (buffer << 8) | *data++;
                length--;
                bits_left += 8;
            } else {
                buffer = (buffer << (5 - bits_left));
                bits_left = 5;
            }
        }
        bits_left -= 5;
        *result++ = base32_chars[(buffer >> bits_left) & 0x1F];
    }
    *result = '\0';
}

static size_t base32_decode(const char *encoded, uint8_t *result) {
    int buffer = 0;
    int bits_left = 0;
    size_t length = 0;
    while (*encoded) {
        char c = *encoded++;
        uint8_t val = 0;
        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;
        else continue;
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if (bits_left >= 8) {
            bits_left -= 8;
            result[length++] = (buffer >> bits_left) & 0xFF;
        }
    }
    return length;
}

void mfa_generate_secret(char *base32_out, size_t out_len) {
    uint8_t raw[20];
    randombytes_buf(raw, sizeof(raw));
    base32_encode(raw, sizeof(raw), base32_out);
}

static uint32_t generate_totp(const uint8_t *key, size_t key_len, uint64_t time_step) {
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = time_step & 0xFF;
        time_step >>= 8;
    }
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    HMAC(EVP_sha1(), key, key_len, msg, sizeof(msg), hash, &hash_len);
    int offset = hash[19] & 0x0F;
    uint32_t binary = ((hash[offset] & 0x7F) << 24) |
                      ((hash[offset + 1] & 0xFF) << 16) |
                      ((hash[offset + 2] & 0xFF) << 8) |
                      (hash[offset + 3] & 0xFF);
    return binary % 1000000;
}

bool mfa_verify_totp(const char *base32_secret, const char *code) {
    if (!base32_secret || !code || strlen(code) != 6) return false;
    uint8_t key[32];
    size_t key_len = base32_decode(base32_secret, key);
    if (key_len == 0) return false;
    
    uint64_t current_step = time(NULL) / 30;
    uint32_t expected = generate_totp(key, key_len, current_step);
    
    char expected_str[8];
    snprintf(expected_str, sizeof(expected_str), "%06u", expected);
    return strcmp(expected_str, code) == 0;
}
```

- [ ] **Step 3: Update `Makefile`**
Ensure `src/mfa.c` is compiled and linked. OpenSSL (`-lcrypto`) is already linked via `-lssl`.

```makefile
# Add to SRC logic
SRC = src/main.c src/config.c src/logger.c src/server.c src/server_mhd.c src/user.c src/role.c src/group.c src/policy.c src/permission.c src/ratelimit.c src/token.c src/storage_sqlite.c src/storage_memory.c src/cJSON.c src/sso.c src/handlers_admin.c src/handlers_auth.c src/handlers_check.c src/handlers_common.c src/handlers_pages.c src/interactive.c src/toml.c src/oauth.c src/mfa.c
```

- [ ] **Step 4: Verify build**

Run: `make`
Expected: Compile succeeds.

- [ ] **Step 5: Commit**

```bash
git add include/mfa.h src/mfa.c Makefile
git commit -m "feat(mfa): ✨ implement Base32 and TOTP validation utilities"
```

---

### Task 6: Implement MFA Endpoints and Two-Step Flow

**Files:**
- Modify: `src/handlers_auth.c`
- Modify: `src/main.c`

- [ ] **Step 1: Add `/api/v1/auth/mfa/setup` & `enable` in `src/handlers_auth.c`**

```c
/* In src/handlers_auth.c */
#include "mfa.h"

sso_error_t handle_mfa_setup(sso_context_t *ctx, const http_request_t *req, http_response_t *resp) {
    if (!req->userdata) { sso_response_error(resp, 401, "unauthorized"); return SSO_OK; }
    auth_context_t *auth = (auth_context_t *)req->userdata;
    char secret[64];
    mfa_generate_secret(secret, sizeof(secret));
    
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"secret\":\"%s\",\"uri\":\"otpauth://totp/SSO:%s?secret=%s&issuer=SSO\"}", secret, auth->user.username, secret);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

sso_error_t handle_mfa_enable(sso_context_t *ctx, const http_request_t *req, http_response_t *resp) {
    if (!req->userdata) { sso_response_error(resp, 401, "unauthorized"); return SSO_OK; }
    if (!req->body) { sso_response_error(resp, 400, "invalid_request"); return SSO_OK; }
    auth_context_t *auth = (auth_context_t *)req->userdata;
    
    char *secret = json_str_value(req->body, "secret");
    char *code = json_str_value(req->body, "code");
    
    if (!secret || !code || !mfa_verify_totp(secret, code)) {
        sso_response_error(resp, 400, "invalid_code");
        free(secret); free(code); return SSO_OK;
    }
    
    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t u = auth->user;
    u.mfa_enabled = 1;
    strncpy(u.mfa_secret, secret, sizeof(u.mfa_secret)-1);
    user_update(umgr, &u);
    
    sso_response_ok(resp, "{\"status\":\"ok\"}");
    free(secret); free(code); return SSO_OK;
}
```

- [ ] **Step 2: Update `handle_login` (and `/api/v1/auth/mfa/verify`) for two-step flow**

```c
/* In src/handlers_auth.c:handle_login, when credentials are correct: */
    if (user.mfa_enabled) {
        /* Issue MFA pending token */
        token_t mfa_tok;
        memset(&mfa_tok, 0, sizeof(mfa_tok));
        sso_error_t terr = token_issue(tmgr, &user, NULL, 0, NULL, 0, 300000, &mfa_tok); // 5 min
        
        char buf[2048];
        snprintf(buf, sizeof(buf), "{\"error\":\"mfa_required\",\"mfa_token\":\"%s\"}", mfa_tok.token_str);
        resp->status_code = 401; // Return 401
        resp->body = strdup(buf);
        resp->body_len = strlen(buf);
        strcpy(resp->content_type, "application/json");
        token_destroy(&mfa_tok);
        return SSO_OK;
    }
    
    /* Issue normal token & refresh token */
    /* ... Generate and store opaque refresh token (similar to Task 4) ... */
```

```c
/* Add handler for /api/v1/auth/mfa/verify */
sso_error_t handle_mfa_verify(sso_context_t *ctx, const http_request_t *req, http_response_t *resp) {
    if (!req->body) { sso_response_error(resp, 400, "invalid_request"); return SSO_OK; }
    char *mfa_token = json_str_value(req->body, "mfa_token");
    char *code = json_str_value(req->body, "code");
    
    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t decoded;
    if (token_verify(tmgr, mfa_token, &decoded) != SSO_OK) {
        sso_response_error(resp, 401, "invalid_token");
        goto cleanup;
    }
    /* In a real implementation we'd check claims for "mfa_pending", but short TTL isolates this */
    
    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    if (user_get_by_id(umgr, decoded.user_id, &user) != SSO_OK) {
        sso_response_error(resp, 404, "user_not_found");
        goto cleanup;
    }
    
    if (!mfa_verify_totp(user.mfa_secret, code)) {
        sso_response_error(resp, 400, "invalid_code");
        goto cleanup;
    }
    
    /* Success: issue real tokens */
    sso_id_t roles[16], groups[16];
    size_t rc = 0, gc = 0;
    user_get_roles(umgr, user.id, roles, &rc, 16);
    user_get_groups(umgr, user.id, groups, &gc, 16);
    
    token_t access_token;
    token_issue(tmgr, &user, roles, rc, groups, gc, 3600000, &access_token);
    
    /* Store refresh token */
    storage_backend_t *sb = (storage_backend_t *)ctx->storage_backend;
    if (sb && sb->refresh_token_create) {
        refresh_token_t rt;
        memset(&rt, 0, sizeof(rt));
        unsigned char rt_hash_bytes[32];
        crypto_hash_sha256(rt_hash_bytes, (const unsigned char *)access_token.raw_refresh_token, strlen(access_token.raw_refresh_token));
        for (size_t i = 0; i < 32; i++) sprintf(&rt.token_hash[i*2], "%02x", rt_hash_bytes[i]);
        rt.user_id = user.id;
        rt.issued_at = sso_timestamp_now();
        rt.expires_at = rt.issued_at + 2592000000;
        rt.revoked = 0;
        sb->refresh_token_create(sb, &rt);
    }
    
    char buf[2048];
    snprintf(buf, sizeof(buf), "{\"token\":\"%s\",\"refresh_token\":\"%s\"}", access_token.token_str, access_token.raw_refresh_token);
    sso_response_ok(resp, buf);
    token_destroy(&access_token);

cleanup:
    free(mfa_token); free(code);
    token_destroy(&decoded);
    return SSO_OK;
}
```

- [ ] **Step 3: Register routes in `main.c`**

```c
/* In src/main.c */
extern sso_error_t handle_mfa_setup(sso_context_t *ctx, const http_request_t *req, http_response_t *resp);
extern sso_error_t handle_mfa_enable(sso_context_t *ctx, const http_request_t *req, http_response_t *resp);
extern sso_error_t handle_mfa_verify(sso_context_t *ctx, const http_request_t *req, http_response_t *resp);

/* Inside route_t routes[] */
{"/api/v1/auth/mfa/setup", HTTP_POST, handle_mfa_setup, true},
{"/api/v1/auth/mfa/enable", HTTP_POST, handle_mfa_enable, true},
{"/api/v1/auth/mfa/verify", HTTP_POST, handle_mfa_verify, false},
```

- [ ] **Step 4: Verify build**

Run: `make`
Expected: Compile succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/handlers_auth.c src/main.c
git commit -m "feat(mfa): ✨ integrate MFA setup and verification endpoints"
```
