# SSO System — Lightweight Single Sign-On Service in C

A lightweight, embeddable Single Sign-On (SSO) service written in C, providing unified authentication and authorization for microservices. Features seven permission strategies (functional, API endpoint, data scope, RBAC, Location, LBAC, ABAC) with a DENY-overrides permission engine, HMAC-based stateless tokens, and an embedded HTTP API server.

## Features

- **Unified Authentication** — register, login, token verify/refresh/logout, self-info query
- **Role-Based Access Control (RBAC)** — hierarchical roles with ancestry inheritance
- **Group Management** — hierarchical groups with membership
- **Seven Permission Strategies** (pluggable via strategy pattern):
  - **Functional** — feature/button-level permissions (`report:view`, `admin:*`)
  - **API Endpoint** — HTTP method + path matching with wildcards (`GET /api/v1/users/*`)
  - **Data Scope** — resource-scoped access with field-level filtering
  - **RBAC** — role membership check against policy-defined role names
  - **Location** — location-based access control via IP CIDR matching
  - **LBAC** — label-based access control (security labels/MLS)
  - **ABAC** — attribute-based access control with multi-condition evaluation
- **DENY-Overrides Engine** — explicit deny takes precedence; default-deny (fail closed)
- **Stateless Tokens** — HMAC-SHA256 signed JWT-like tokens (no server-side session storage)
- **Embedded HTTP Server** — POSIX socket-based, no external web server required
- **SQLite Persistence** — reliable, zero-config storage
- **Bootstrap Mode** — creates admin user and default roles/policies on first start

## Architecture

```
┌────────────────────────────────────────────┐
│          Management API (HTTP/8080)         │
├──────────┬──────────┬──────────┬────────────┤
│  User    │  Role    │  Group   │  Policy    │
│  Manager │  Manager │  Manager │  Engine    │
├──────────┴──────────┴──────────┴────────────┤
│        Permission Strategy Layer             │
│ [Functional][API][Data][RBAC][Location]      │
│ [LBAC]                [ABAC]                 │
├──────────────────────────────────────────────┤
│           Token / Session Manager            │
├──────────────────────────────────────────────┤
│         Storage Backend (SQLite)             │
└──────────────────────────────────────────────┘
```

## Requirements

- **C compiler** (GCC recommended)
- **SQLite3** — `libsqlite3-dev`
- **OpenSSL** — `libssl-dev` (for SHA-256 and HMAC)

### Install Dependencies

```bash
# Debian / Ubuntu
sudo apt-get install build-essential libsqlite3-dev libssl-dev

# Fedora / RHEL
sudo dnf install gcc sqlite-devel openssl-devel

# macOS (Homebrew)
brew install sqlite3 openssl
```

## Build

```bash
git clone <repo> && cd sso
make              # release build (O2)
make debug        # debug build (O0, -g)
```

Output: `./sso_system`

## Usage

Three run modes:

| Command | Mode | Description |
|---------|------|-------------|
| `./sso_system` | Demo | Comprehensive walkthrough of all features, then exits |
| `./sso_system --interactive` | Interactive | Guided menu-driven configuration shell for all 6 strategies |
| `./sso_system --server` | Server | Starts HTTP management API on port 8080 |

### Demo Mode

Runs a comprehensive walkthrough of all features and exits:

```bash
./sso_system
```

The demo demonstrates:
1. System initialization with SQLite
2. User, role, group CRUD
3. Policy creation for all seven strategy types
4. Role/group hierarchy and inheritance
5. Permission checks (functional, API, data, RBAC, Location, LBAC, ABAC)
6. Token-based authentication

### Interactive Configuration Mode

Guided step-by-step shell for creating all seven policy types interactively:

```bash
./sso_system --interactive
```

Presents a numbered menu with options for each strategy type plus actions:
- **Strategy creation** (1-6): step-by-step prompts with defaults — no raw JSON needed
- **Assign policies** (7): link a policy to a role by ID
- **Test checks** (8): verify a user's permission against any strategy type
- **List policies** (9): show all existing policies with rules
- **Exit** (0): saves configuration to `sso_config.db` for reuse

All prompts include inline help, examples, and sensible defaults. The database persists between sessions — re-run `--interactive` to continue where you left off, or delete `sso_config.db` for a fresh start.

### Server Mode

Starts the HTTP management API on port 8080:

```bash
./sso_system --server
```

**First start** — bootstraps default admin user, roles, groups, and 6 policy types:
- Admin user: `admin` / `admin123`
- Admin role, Editor role (child of Admin), Viewer role (child of Editor)
- All policy types (functional, API, data, RBAC, LBAC, ABAC) with demo rules
- All policies assigned to admin role → admin user inherits full access

```bash
# Quick test
curl --noproxy '*' http://localhost:8080/api/v1/health
```

> Note: If your environment has an HTTP proxy set, use `--noproxy '*'` to bypass it for localhost requests.

## API Reference

All endpoints return JSON. Authentication-required endpoints need a `Bearer` token in the `Authorization` header.

### Public Endpoints

#### `GET /api/v1/health`
Health check.

```json
{"status":"ok","service":"sso","version":"1.0.0"}
```

#### `POST /api/v1/auth/login`
Authenticate and receive a token.

**Request:**
```json
{"username":"admin","password":"admin123"}
```

**Response:**
```json
{
  "token":"eyJqdGkiOiIuLi4iLCJzdWIiOjEs...",
  "user_id":1,
  "username":"admin",
  "display_name":"Admin"
}
```

#### `POST /api/v1/auth/register`
Create a new user account.

**Request:**
```json
{"username":"alice","password":"alice123","display_name":"Alice"}
```

**Response:**
```json
{"user_id":2,"username":"alice","created":true}
```

### Authenticated Endpoints

All endpoints below require header: `Authorization: Bearer <token>`

#### `POST /api/v1/auth/verify`
Validate a token.

**Response:**
```json
{"valid":true,"user_id":1,"username":"admin","display_name":"Admin","expires_at":1781238528988}
```

#### `POST /api/v1/auth/refresh`
Refresh (renew) a token.

**Response:**
```json
{"token":"eyJ...","expires_at":1781238626358}
```

#### `POST /api/v1/auth/logout`
Revoke a token (blocks subsequent verify/refresh).

**Response:**
```json
{"logged_out":true}
```

#### `GET /api/v1/auth/me`
Get current user info from token.

```json
{"user_id":1,"username":"admin","email":"admin@example.com","display_name":"Admin","token_jti":"..."}
```

### Permission Check Endpoints

#### `POST /api/v1/check/functional`
Check if a user has a functional permission.

**Request:**
```json
{"function_code":"admin:reports","user_id":1}
```

**Response:**
```json
{"allowed":true,"user_id":1,"function":"admin:reports"}
```

#### `POST /api/v1/check/api`
Check if a user can access an API endpoint.

**Request:**
```json
{"method":"GET","path":"/api/v1/users","user_id":1}
```

**Response:**
```json
{"allowed":true,"user_id":1}
```

#### `POST /api/v1/check/data`
Check if a user can access a data resource with field-level filtering.

**Request:**
```json
{"resource_type":"report","resource_id":"123","action":"view","user_id":1}
```

**Response:**
```json
{"allowed":false,"user_id":1}
```

When allowed, the response may include a `fields` array for column-level filtering:
```json
{"allowed":true,"user_id":1,"fields":["id","title","status"]}
```

#### `POST /api/v1/check/rbac`
Check if a user has a specific role (RBAC).

**Request:**
```json
{"role_name":"admin","user_id":1}
```

**Response:**
```json
{"allowed":true,"user_id":1,"role":"admin"}
```

#### `POST /api/v1/check/location`
Check if a user's request originates from an allowed location.

**Request:**
```json
{"source_ip":"127.0.0.1","user_id":1}
```

**Response:**
```json
{"allowed":true,"user_id":1,"source_ip":"127.0.0.1"}
```

#### `POST /api/v1/check/lbac`
Check if a user has the required security labels (LBAC).

**Request:**
```json
{"user_labels":"PUBLIC,CONFIDENTIAL","resource_label":"CONFIDENTIAL","user_id":1}
```

**Response:**
```json
{"allowed":true,"user_id":1}
```

#### `POST /api/v1/check/abac`
Check if a user satisfies attribute-based conditions (ABAC).

**Request:**
```json
{"subject_attrs":"{\"department\":\"engineering\"}","user_id":1}
```

**Response:**
```json
{"allowed":true,"user_id":1}
```

### Management Endpoints

#### `POST /api/v1/users`
Create a user (admin endpoint).

**Request:**
```json
{"username":"bob","password":"bob123","email":"bob@example.com","display_name":"Bob"}
```

#### `POST /api/v1/roles`
Create a role.

**Request:**
```json
{"name":"reporter","description":"Report viewer","parent_id":0}
```

#### `POST /api/v1/roles/:id/assign`
Assign a role to a user or group.

**Request:**
```json
{"user_id":2}
```

or

```json
{"group_id":1}
```

## Permission System

### Strategy Pattern

Seven strategies are registered in the engine. Each policy declares its strategy type, and the engine dispatches evaluation to the correct strategy implementation.

| Strategy | Type | Purpose | Rule Format |
|----------|------|---------|-------------|
| Functional | `PERM_STRATEGY_FUNCTIONAL` | Feature/menu/button permissions | `{"functions":[{"code":"report:view","effect":"allow"}]}` |
| API | `PERM_STRATEGY_API` | HTTP method + path access control | `{"endpoints":[{"method":"GET","path":"/api/v1/*","effect":"allow"}]}` |
| Data | `PERM_STRATEGY_DATA` | Resource-scoped field-level access | `{"resources":[{"type":"report","scope":"all","fields":["id","title"],"conditions":[...]}]}` |
| RBAC | `PERM_STRATEGY_RBAC` | Role membership check | `{"roles":[{"name":"admin","effect":"allow"}]}` |
| Location | `PERM_STRATEGY_LOCATION` | IP/location-based access control | `{"locations":[{"type":"ip_cidr","value":"127.0.0.0/8","effect":"allow"}]}` |
| LBAC | `PERM_STRATEGY_LBAC` | Label-based access control (MLS) | `{"labels":[{"name":"CONFIDENTIAL","effect":"allow"}]}` |
| ABAC | `PERM_STRATEGY_ABAC` | Attribute-based access control | `{"conditions":[{"source":"subject","attr":"department","op":"eq","value":"engineering"}],"logic":"and","effect":"allow"}` |

### Evaluation Logic

1. **Resolve** all policies applicable to the user (via role/group ancestry)
2. **Evaluate** each policy in priority order
3. **DENY overrides** — any policy that explicitly denies access → result is DENY
4. **Default deny** — if no policy matches → result is DENY

### Permission Resolution

Policies are inherited through role and group hierarchies:
- User → direct policies → direct roles → parent roles → (ancestor chain)
- User → direct policies → direct groups → parent groups → (ancestor chain)
- All policies collected, deduplicated, sorted by priority (highest first)

## Token Format

Self-contained stateless tokens:

```
base64(json_header).hex(HMAC-SHA256(signing_key, base64(json_header)))
```

**Header payload:**
```json
{
  "jti": "19eb9df...",     /* unique token ID */
  "sub": 1,                 /* user ID */
  "iat": 1781234922486,     /* issued at (epoch ms) */
  "exp": 1781238522486,     /* expires at (epoch ms) */
  "roles": [1],             /* role IDs */
  "groups": []              /* group IDs */
}
```

## Configuration

### Makefile Targets

| Command | Description |
|---------|-------------|
| `make` | Build release binary |
| `make debug` | Build with debug symbols |
| `make run` | Build and run demo |
| `make server` | Build and start HTTP server |
| `make clean` | Remove build artifacts |
| `make size` | Show binary segment sizes |

### Server Defaults

| Setting | Value |
|---------|-------|
| Host | `0.0.0.0` |
| Port | `8080` |
| Database | `sso_server.db` (demo: `sso_demo.db`) |

## Project Structure

```
.
├── Makefile                 # Build system
├── include/                 # Public headers
│   ├── sso.h                # Core types, error codes, strategy interface
│   ├── user.h               # User manager
│   ├── role.h               # Role manager
│   ├── group.h              # Group manager
│   ├── policy.h             # Policy manager
│   ├── permission.h         # Permission engine (strategy registry + evaluate)
│   ├── token.h              # Token manager (issue/verify/refresh/revoke)
│   ├── storage.h            # Storage abstraction (vtable)
│   └── server.h             # HTTP server types and route system
├── src/                     # Implementation
│   ├── sso.c                # Context lifecycle
│   ├── permission.c         # Permission engine (DENY-overrides)
│   ├── user.c               # User CRUD, SHA-256+salt auth
│   ├── role.c               # Role CRUD, hierarchy
│   ├── group.c              # Group CRUD, hierarchy
│   ├── policy.c             # Policy CRUD, assignment, resolution
│   ├── token.c              # HMAC token generation/verification
│   ├── storage_sqlite.c     # SQLite backend
│   ├── server.c             # HTTP server, routing, auth middleware
│   └── main.c               # Entry point, demo, route handlers, bootstrap
└── strategies/              # Strategy implementations
    ├── func_perm.c          # Functional permission strategy
    ├── api_perm.c           # API endpoint permission strategy
    ├── data_perm.c          # Data scope permission strategy
    ├── rbac_perm.c          # RBAC (role membership) strategy
    ├── lbac_perm.c          # LBAC (location-based) strategy
    └── abac_perm.c          # ABAC (attribute-based) strategy
```

## Developer Notes

### Adding a New Strategy

1. Create `strategies/<name>.c` implementing `permission_strategy_t`
2. Register it in `permission.c` — `perm_engine_create()`
3. Add `eval_context` union member for new strategy's parameters
4. Add rule validation in the strategy's `validate_rules` callback

### Error Codes

| Code | Value | Meaning |
|------|-------|---------|
| `SSO_OK` | 0 | Success |
| `SSO_ERR_NOT_FOUND` | -2 | Resource not found |
| `SSO_ERR_ALREADY_EXISTS` | -3 | Duplicate entry |
| `SSO_ERR_INVALID_PARAM` | -4 | Invalid parameters |
| `SSO_ERR_NO_PERMISSION` | -5 | Access denied |
| `SSO_ERR_AUTH_FAILED` | -6 | Authentication failure |
| `SSO_ERR_TOKEN_EXPIRED` | -7 | Token has expired |
| `SSO_ERR_TOKEN_INVALID` | -8 | Token validation failed |
| `SSO_ERR_STORAGE` | -9 | Storage backend error |
| `SSO_ERR_OUT_OF_MEMORY` | -13 | Memory allocation failure |
