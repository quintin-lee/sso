# OAuth2 Multi-Client Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enhance the SSO system to support multiple OAuth2 clients stored in SQLite, alongside the single config-based client, using argon2id for secret hashing.

**Architecture:** We will first add the `oauth_clients` schema to `src/storage_sqlite.c`. Then, we extend `include/storage.h` with the `oauth_client_t` struct and CRUD function pointers. Next, we implement these functions in `storage_sqlite.c` and `storage_memory.c`. Finally, we update `handle_oauth_authorize` and `handle_oauth_token` in `src/oauth.c` to fallback to the DB if the requested `client_id` doesn't match the global config.

**Tech Stack:** C11, SQLite3, libsodium (for random generation and hashing).

---

### Task 1: Update Storage Interface

**Files:**
- Modify: `include/storage.h`

- [ ] **Step 1: Add `oauth_client_t` struct and function pointers to `storage.h`**

```c
/* In include/storage.h, after oauth_auth_code_t definition */

typedef struct {
    sso_id_t id;
    char client_id[64];
    char client_secret_hash[128];
    char redirect_uris[512];
    char app_name[128];
    char app_description[256];
    char app_logo_url[256];
    char allowed_scopes[256];
    char allowed_grant_types[128];
    long token_ttl_ms;
    int status;
    sso_timestamp_t created_at;
    sso_timestamp_t updated_at;
} oauth_client_t;

typedef sso_error_t (*storage_oauth_client_create_fn)(storage_backend_t *self, oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_get_fn)(storage_backend_t *self, const char *client_id, oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_update_fn)(storage_backend_t *self, const oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_delete_fn)(storage_backend_t *self, const char *client_id);
typedef sso_error_t (*storage_oauth_client_list_fn)(storage_backend_t *self, int offset, int limit, oauth_client_t *clients, size_t *count, size_t max);

/* Inside struct storage_backend, after oauth_code_cleanup */
    storage_oauth_client_create_fn    oauth_client_create;
    storage_oauth_client_get_fn       oauth_client_get;
    storage_oauth_client_update_fn    oauth_client_update;
    storage_oauth_client_delete_fn    oauth_client_delete;
    storage_oauth_client_list_fn      oauth_client_list;
```

- [ ] **Step 2: Compile to ensure no syntax errors in header**

Run: `make`
Expected: Successful compilation of the project.

- [ ] **Step 3: Commit**

```bash
git add include/storage.h
git commit -m "feat(storage): ✨ add oauth_client_t to storage interface"
```

---

### Task 2: Implement SQLite Backend Schema & CRUD

**Files:**
- Modify: `src/storage_sqlite.c`

- [ ] **Step 1: Add table creation schema to `sqlite_open`**

```c
/* In src/storage_sqlite.c, inside sqlite_open, add the table creation query */
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
```

- [ ] **Step 2: Implement binding/reading helpers and CRUD functions in `src/storage_sqlite.c`**

```c
/* Add these static helper functions and CRUD implementations */
static void bind_oauth_client(sqlite3_stmt *stmt, const oauth_client_t *c) {
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

static void read_oauth_client(sqlite3_stmt *stmt, oauth_client_t *c) {
    memset(c, 0, sizeof(*c));
    c->id = (sso_id_t)sqlite3_column_int64(stmt, 0);
    const char *client_id = (const char *)sqlite3_column_text(stmt, 1);
    if(client_id) strncpy(c->client_id, client_id, sizeof(c->client_id)-1);
    const char *hash = (const char *)sqlite3_column_text(stmt, 2);
    if(hash) strncpy(c->client_secret_hash, hash, sizeof(c->client_secret_hash)-1);
    const char *uris = (const char *)sqlite3_column_text(stmt, 3);
    if(uris) strncpy(c->redirect_uris, uris, sizeof(c->redirect_uris)-1);
    const char *name = (const char *)sqlite3_column_text(stmt, 4);
    if(name) strncpy(c->app_name, name, sizeof(c->app_name)-1);
    const char *desc = (const char *)sqlite3_column_text(stmt, 5);
    if(desc) strncpy(c->app_description, desc, sizeof(c->app_description)-1);
    const char *logo = (const char *)sqlite3_column_text(stmt, 6);
    if(logo) strncpy(c->app_logo_url, logo, sizeof(c->app_logo_url)-1);
    const char *scopes = (const char *)sqlite3_column_text(stmt, 7);
    if(scopes) strncpy(c->allowed_scopes, scopes, sizeof(c->allowed_scopes)-1);
    const char *grants = (const char *)sqlite3_column_text(stmt, 8);
    if(grants) strncpy(c->allowed_grant_types, grants, sizeof(c->allowed_grant_types)-1);
    c->token_ttl_ms = (long)sqlite3_column_int64(stmt, 9);
    c->status = sqlite3_column_int(stmt, 10);
    c->created_at = (sso_timestamp_t)sqlite3_column_int64(stmt, 11);
    c->updated_at = (sso_timestamp_t)sqlite3_column_int64(stmt, 12);
}

static sso_error_t sqlite_oauth_client_create(storage_backend_t *self, oauth_client_t *c) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris, app_name, app_description, app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    if (c->created_at == 0) c->created_at = sso_timestamp_now();
    if (c->updated_at == 0) c->updated_at = c->created_at;
    bind_oauth_client(stmt, c);
    if (sqlite3_step(stmt) != SQLITE_DONE) { sqlite3_finalize(stmt); return SSO_ERR_STORAGE; }
    c->id = (sso_id_t)sqlite3_last_insert_rowid(priv->db);
    sqlite3_finalize(stmt);
    return SSO_OK;
}

static sso_error_t sqlite_oauth_client_get(storage_backend_t *self, const char *client_id, oauth_client_t *c) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(priv->db, "SELECT id, client_id, client_secret_hash, redirect_uris, app_name, app_description, app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, updated_at FROM oauth_clients WHERE client_id = ?", -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        read_oauth_client(stmt, c);
        sqlite3_finalize(stmt);
        return SSO_OK;
    }
    sqlite3_finalize(stmt);
    return SSO_ERR_NOT_FOUND;
}

static sso_error_t sqlite_oauth_client_update(storage_backend_t *self, const oauth_client_t *c) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    const char *sql = "UPDATE oauth_clients SET client_id=?, client_secret_hash=?, redirect_uris=?, app_name=?, app_description=?, app_logo_url=?, allowed_scopes=?, allowed_grant_types=?, token_ttl_ms=?, status=?, created_at=?, updated_at=? WHERE id=?";
    if (sqlite3_prepare_v2(priv->db, sql, -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    bind_oauth_client(stmt, c);
    sqlite3_bind_int64(stmt, 13, (sqlite3_int64)c->id);
    sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
    sqlite3_finalize(stmt);
    return err;
}

static sso_error_t sqlite_oauth_client_delete(storage_backend_t *self, const char *client_id) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(priv->db, "DELETE FROM oauth_clients WHERE client_id=?", -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    sqlite3_bind_text(stmt, 1, client_id, -1, SQLITE_STATIC);
    sso_error_t err = (sqlite3_step(stmt) == SQLITE_DONE) ? SSO_OK : SSO_ERR_STORAGE;
    sqlite3_finalize(stmt);
    return err;
}

static sso_error_t sqlite_oauth_client_list(storage_backend_t *self, int offset, int limit, oauth_client_t *clients, size_t *count, size_t max) {
    sqlite_priv_t *priv = (sqlite_priv_t *)self->handle;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(priv->db, "SELECT id, client_id, client_secret_hash, redirect_uris, app_name, app_description, app_logo_url, allowed_scopes, allowed_grant_types, token_ttl_ms, status, created_at, updated_at FROM oauth_clients LIMIT ? OFFSET ?", -1, &stmt, NULL) != SQLITE_OK) return SSO_ERR_STORAGE;
    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);
    size_t c = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && c < max) {
        read_oauth_client(stmt, &clients[c]);
        c++;
    }
    sqlite3_finalize(stmt);
    if(count) *count = c;
    return SSO_OK;
}
```

- [ ] **Step 3: Assign function pointers in `storage_sqlite_create`**

```c
/* In storage_sqlite_create, map the pointers */
    b->oauth_client_create    = sqlite_oauth_client_create;
    b->oauth_client_get       = sqlite_oauth_client_get;
    b->oauth_client_update    = sqlite_oauth_client_update;
    b->oauth_client_delete    = sqlite_oauth_client_delete;
    b->oauth_client_list      = sqlite_oauth_client_list;
```

- [ ] **Step 4: Update Memory Backend (Stubs)**

Since memory backend is primarily for testing, stub the functions in `src/storage_memory.c` returning `SSO_ERR_NOT_FOUND` to satisfy the linker.

```c
static sso_error_t mem_oauth_client_create(storage_backend_t *self, oauth_client_t *c) { (void)self; (void)c; return SSO_ERR_STORAGE; }
static sso_error_t mem_oauth_client_get(storage_backend_t *self, const char *client_id, oauth_client_t *c) { (void)self; (void)client_id; (void)c; return SSO_ERR_NOT_FOUND; }
static sso_error_t mem_oauth_client_update(storage_backend_t *self, const oauth_client_t *c) { (void)self; (void)c; return SSO_ERR_STORAGE; }
static sso_error_t mem_oauth_client_delete(storage_backend_t *self, const char *client_id) { (void)self; (void)client_id; return SSO_ERR_STORAGE; }
static sso_error_t mem_oauth_client_list(storage_backend_t *self, int offset, int limit, oauth_client_t *clients, size_t *count, size_t max) { (void)self; (void)offset; (void)limit; (void)clients; (void)max; if(count) *count=0; return SSO_OK; }

/* Map them in storage_memory_create */
    b->oauth_client_create    = mem_oauth_client_create;
    b->oauth_client_get       = mem_oauth_client_get;
    b->oauth_client_update    = mem_oauth_client_update;
    b->oauth_client_delete    = mem_oauth_client_delete;
    b->oauth_client_list      = mem_oauth_client_list;
```

- [ ] **Step 5: Verify build**

Run: `make`
Expected: Code compiles.

- [ ] **Step 6: Commit**

```bash
git add src/storage_sqlite.c src/storage_memory.c
git commit -m "feat(storage): ✨ implement SQLite storage for oauth_clients"
```

---

### Task 3: Adjust `handle_oauth_authorize` for DB fallback

**Files:**
- Modify: `src/oauth.c`

- [ ] **Step 1: Write helper function to validate redirect URI against comma-separated list**

```c
/* Add above handle_oauth_authorize */
static bool is_redirect_uri_allowed(const char *allowed_uris, const char *redirect_uri) {
    if (!allowed_uris || !allowed_uris[0]) return false;
    char uris_copy[512];
    strncpy(uris_copy, allowed_uris, sizeof(uris_copy) - 1);
    uris_copy[sizeof(uris_copy) - 1] = '\0';
    
    char *tok = strtok(uris_copy, ",");
    while (tok) {
        while (*tok == ' ') tok++; /* Trim leading spaces */
        if (strcmp(tok, redirect_uri) == 0) return true;
        tok = strtok(NULL, ",");
    }
    return false;
}
```

- [ ] **Step 2: Update `handle_oauth_authorize` to lookup DB client**

```c
/* In src/oauth.c:handle_oauth_authorize, replace the config client_id check: */
    
    // Check config first
    bool is_config_client = false;
    oauth_client_t db_client;
    memset(&db_client, 0, sizeof(db_client));
    
    if (cfg && cfg->oauth_client_id[0] && strcmp(client_id, cfg->oauth_client_id) == 0) {
        is_config_client = true;
    } else {
        // Fallback to database
        storage_backend_t *sb = get_storage(ctx);
        if (sb && sb->oauth_client_get) {
            if (sb->oauth_client_get(sb, client_id, &db_client) != SSO_OK || db_client.status != 1) {
                json_error_response(resp, 400, "unauthorized_client");
                return SSO_OK;
            }
        } else {
            json_error_response(resp, 400, "unauthorized_client");
            return SSO_OK;
        }
    }

    /* Check redirect_uri against allowed URIs */
    if (is_config_client) {
        if (!is_redirect_uri_allowed(cfg->oauth_redirect_uris, redirect_uri)) {
            json_error_response(resp, 400, "invalid_redirect_uri");
            return SSO_OK;
        }
    } else {
        if (!is_redirect_uri_allowed(db_client.redirect_uris, redirect_uri)) {
            json_error_response(resp, 400, "invalid_redirect_uri");
            return SSO_OK;
        }
    }
    
    /* Store requested scope. We can skip deep scope validation for now or check against DB later */
```

- [ ] **Step 3: Compile and Test**

Run: `make`
Expected: Code compiles.

- [ ] **Step 4: Commit**

```bash
git add src/oauth.c
git commit -m "feat(oauth): ✨ support DB client lookup in authorize endpoint"
```

---

### Task 4: Adjust `handle_oauth_token` for DB fallback & Argon2id Hashing

**Files:**
- Modify: `src/oauth.c`

- [ ] **Step 1: Write helper function to verify client secret**

```c
/* Add above handle_oauth_token */
static bool verify_client_secret(const char *input_secret, const char *stored_hash) {
    if (!input_secret || !stored_hash) return false;
    return crypto_pwhash_str_verify(stored_hash, input_secret, strlen(input_secret)) == 0;
}
```

- [ ] **Step 2: Update `grant_type=authorization_code` handling**
(The authorize endpoint checks client_id, but the token endpoint doesn't currently mandate checking the client_id/secret for code exchange based on the provided logic. However, client credentials grant does.)

- [ ] **Step 3: Update `grant_type=client_credentials` handling**

```c
/* In src/oauth.c:handle_oauth_token, inside the client_credentials block */
    bool is_config_client = false;
    oauth_client_t db_client;
    memset(&db_client, 0, sizeof(db_client));

    if (cfg && cfg->oauth_client_id[0] && strcmp(client_id, cfg->oauth_client_id) == 0) {
        is_config_client = true;
        if (strcmp(client_secret, cfg->oauth_client_secret) != 0) {
            json_error_response(resp, 401, "invalid_client");
            goto cleanup;
        }
    } else {
        if (sb && sb->oauth_client_get) {
            if (sb->oauth_client_get(sb, client_id, &db_client) != SSO_OK || db_client.status != 1) {
                json_error_response(resp, 401, "invalid_client");
                goto cleanup;
            }
            if (!verify_client_secret(client_secret, db_client.client_secret_hash)) {
                json_error_response(resp, 401, "invalid_client");
                goto cleanup;
            }
            // Check allowed grant types
            if (db_client.allowed_grant_types[0] != '\0' && !strstr(db_client.allowed_grant_types, "client_credentials")) {
                json_error_response(resp, 400, "unauthorized_client");
                goto cleanup;
            }
        } else {
            json_error_response(resp, 401, "invalid_client");
            goto cleanup;
        }
    }

    /* ... Issue token ... */
    long ttl = 3600000;
    if (!is_config_client && db_client.token_ttl_ms > 0) {
        ttl = db_client.token_ttl_ms;
    }

    sso_error_t terr = token_issue(tmgr, &client_user, NULL, 0, NULL, 0, ttl, &access_token);
```

- [ ] **Step 4: Update `grant_type=authorization_code` to apply custom TTLs**

```c
/* In src/oauth.c:handle_oauth_token, inside the authorization_code block, after getting the code */
    long ttl = 3600000;
    // Check if the client belongs to DB and has a custom TTL
    if (!cfg || strcmp(ac.client_id, cfg->oauth_client_id) != 0) {
        oauth_client_t ac_client;
        if (sb && sb->oauth_client_get && sb->oauth_client_get(sb, ac.client_id, &ac_client) == SSO_OK) {
            if (ac_client.token_ttl_ms > 0) {
                ttl = ac_client.token_ttl_ms;
            }
        }
    }
    
    sso_error_t terr = token_issue(tmgr, &user, roles, rc, groups, gc, ttl, &access_token);
```

- [ ] **Step 5: Compile and Run tests**

Run: `make && make test`
Expected: Compile succeeds and existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/oauth.c
git commit -m "feat(oauth): ✨ authenticate DB clients and apply custom TTLs in token endpoint"
```

---

### Task 5: Add a Test for SQLite Multi-Client Backend

**Files:**
- Modify: `tests/test_storage.c`

- [ ] **Step 1: Write a test for `oauth_clients` CRUD**

```c
/* In tests/test_storage.c, add a new test function */
static char *test_oauth_clients() {
    storage_backend_t *sb = NULL;
    mu_assert("storage_sqlite_create failed", storage_sqlite_create(&sb) == SSO_OK);
    mu_assert("storage_open failed", sb->open(sb, "file::memory:?cache=shared") == SSO_OK);

    oauth_client_t client;
    memset(&client, 0, sizeof(client));
    strcpy(client.client_id, "test_client_1");
    strcpy(client.client_secret_hash, "$argon2id$v=19$m=65536,t=2,p=1$abc$def");
    strcpy(client.redirect_uris, "http://localhost/callback");
    client.status = 1;

    mu_assert("oauth_client_create failed", sb->oauth_client_create(sb, &client) == SSO_OK);
    mu_assert("ID assigned", client.id > 0);

    oauth_client_t fetched;
    mu_assert("oauth_client_get failed", sb->oauth_client_get(sb, "test_client_1", &fetched) == SSO_OK);
    mu_assert("client_id mismatch", strcmp(fetched.client_id, "test_client_1") == 0);

    fetched.token_ttl_ms = 7200000;
    mu_assert("oauth_client_update failed", sb->oauth_client_update(sb, &fetched) == SSO_OK);

    oauth_client_t fetched2;
    mu_assert("oauth_client_get failed", sb->oauth_client_get(sb, "test_client_1", &fetched2) == SSO_OK);
    mu_assert("TTL mismatch", fetched2.token_ttl_ms == 7200000);

    mu_assert("oauth_client_delete failed", sb->oauth_client_delete(sb, "test_client_1") == SSO_OK);
    mu_assert("oauth_client_get should fail", sb->oauth_client_get(sb, "test_client_1", &fetched) == SSO_ERR_NOT_FOUND);

    sb->close(sb);
    free(sb);
    return NULL;
}

/* Add to all_tests() in tests/test_storage.c */
mu_run_test(test_oauth_clients);
```

- [ ] **Step 2: Run the test**

Run: `make test`
Expected: `test_oauth_clients` PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_storage.c
git commit -m "test(storage): ✅ add CRUD tests for oauth_clients"
```
