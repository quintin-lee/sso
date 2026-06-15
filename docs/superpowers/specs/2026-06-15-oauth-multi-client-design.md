# OAuth2 Multi-Client Support Design

## Objective
Enhance the existing SSO system to support multiple OAuth2 clients dynamically managed via the SQLite database, while maintaining backward compatibility with the single hardcoded client defined in `sso.toml`. This will allow different applications to integrate with the SSO using dedicated client credentials, custom TTLs, scopes, and metadata.

## 1. Architecture & Data Flow
Currently, `handle_oauth_authorize` and `handle_oauth_token` rely entirely on `get_cfg(ctx)` to validate the `client_id`, `client_secret`, and `redirect_uri`. 
The new design will introduce a "Mixed (Config + DB)" approach:
- When validating a client, the system will first check if the requested `client_id` matches the global one in `sso_config_t`.
- If it does not match, the system will query the new `oauth_clients` table via the `storage_backend_t` interface.
- This ensures zero breakage for existing setups while opening the door for dynamic clients.

## 2. Database Schema
A new table `oauth_clients` will be added to `src/storage_sqlite.c` in the initialization phase.

```sql
CREATE TABLE IF NOT EXISTS oauth_clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT UNIQUE NOT NULL,
  client_secret_hash TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,          -- comma-separated
  app_name TEXT DEFAULT '',
  app_description TEXT DEFAULT '',
  app_logo_url TEXT DEFAULT '',
  allowed_scopes TEXT DEFAULT '',       -- comma-separated, empty means any
  allowed_grant_types TEXT DEFAULT '',  -- comma-separated e.g. "authorization_code,client_credentials"
  token_ttl_ms INTEGER DEFAULT 0,       -- 0 means use global default
  status INTEGER DEFAULT 1,             -- 1 = active, 0 = disabled
  created_at INTEGER DEFAULT 0,
  updated_at INTEGER DEFAULT 0
);
```

## 3. Storage Interface Extensions
`include/storage.h` will be extended with CRUD operations for the new `oauth_client_t` entity:

```c
typedef struct {
    sso_id_t id;
    char client_id[64];
    char client_secret_hash[128]; // Hashed using argon2id for security
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

// Function pointers to add to storage_backend_t
typedef sso_error_t (*storage_oauth_client_create_fn)(storage_backend_t *self, oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_get_fn)(storage_backend_t *self, const char *client_id, oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_update_fn)(storage_backend_t *self, const oauth_client_t *client);
typedef sso_error_t (*storage_oauth_client_delete_fn)(storage_backend_t *self, const char *client_id);
typedef sso_error_t (*storage_oauth_client_list_fn)(storage_backend_t *self, int offset, int limit, oauth_client_t **clients, size_t *count, size_t *total_count);
```

## 4. OAuth Logic Adjustments (`src/oauth.c`)
- **`handle_oauth_authorize`**: 
  - Extract `client_id` and query the DB if it doesn't match the config.
  - If a DB client is found, validate `redirect_uri` against the DB record's `redirect_uris`.
  - Validate requested scopes against the client's `allowed_scopes` (if not empty).
  
- **`handle_oauth_token`**:
  - For `authorization_code` and `client_credentials` grants, perform the same Config vs DB lookup.
  - For DB clients, verify the `client_secret` by hashing the incoming plaintext secret using Argon2id and comparing it with `client_secret_hash` from the DB.
  - Validate the requested `grant_type` against the client's `allowed_grant_types`.
  - If the client defines a custom `token_ttl_ms > 0`, use it instead of the global config when issuing the token.

## 5. Security Considerations
- The global client secret in `sso.toml` currently relies on plaintext comparison (noted in source as a limitation).
- The new database-backed clients **MUST** store their secrets as Argon2id hashes, utilizing the existing crypto utilities in the project to prevent plaintext secret exposure in the database.

## 6. Future Extensibility
While this phase focuses on the backend logic and storage, it paves the way for adding REST API endpoints (`/api/v1/oauth/clients`) and a UI section in the admin panel to manage these clients graphically.