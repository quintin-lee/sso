# SSO System — High-Performance Single Sign-On Service in C

A lightweight, enterprise-ready Single Sign-On (SSO) service written in C11, providing unified authentication and fine-grained authorization with sub-millisecond latency. Designed for high-concurrency microservice architectures.

[![C11](https://img.shields.io/badge/C-11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/quintin-lee/sso/actions/workflows/ci.yml/badge.svg)](https://github.com/quintin-lee/sso/actions/workflows/ci.yml)

## Table of Contents

- [Project Status](#project-status)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Dependencies](#dependencies)
- [Running Modes](#running-modes)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Environment Variables](#environment-variables)
- [Docker Deployment](#docker-deployment)
- [CI/CD](#cicd)
- [Commit Convention](#commit-convention)
- [Developer Notes](#developer-notes)

---

## Project Status

The core authentication and authorization engine is stable and feature-complete with all 7 permission strategies implemented. The HTTP API server, Docker deployment, and CI pipeline are operational.

**Current**: `v1.1.0` — OAuth 2.0 / OIDC, libmicrohttpd backend, TOML config, Prometheus `/metrics` public, hardened C codebase.

---

## Key Features

### Authentication

- **Password Authentication**: Argon2id hashing via libsodium
- **SMS OTP Login**: Mobile verification code with auto-registration, served via libcurl to SMS gateway
- **JWT-style Tokens**: HMAC-SHA256 signed tokens with roles, groups embdded in claims
- **Token Revocation**: O(log N) binary search on revocaton lists for instant invalidation
- **Token Refresh and Rotation**: Long-lived sessions with refresh token rotation
- **OAuth 2.0 / OpenID Connect**: Authorization code flow, token introspection (RFC 7662), token revocation (RFC 7009), OIDC discovery, JWKS (RFC 7517), `/userinfo` endpoint

### Authorization — 7 Permission Strategies

| # | Strategy | Enum | Purpose |
|---|----------|------|---------|
| 1 | **Functional** | `PERM_STRATEGY_FUNCTIONAL` | Menu / button / feature flag access (supports wildcards) |
| 2 | **API Endpoint** | `PERM_STRATEGY_API` | HTTP method + path matching (`*`, `**`, `:param`) |
| 3 | **Data Scope** | `PERM_STRATEGY_DATA` | Row-level (conditions) and field-level (whitelist) filtering |
| 4 | **RBAC** | `PERM_STRATEGY_RBAC` | Role membership with recursive hierarchy (ancestor inheritance) |
| 5 | **Location** | `PERM_STRATEGY_LOCATION` | IP / geo-based access control |
| 6 | **ABAC** | `PERM_STRATEGY_ABAC` | Attribute-based: subject, resource, and environment attributes with operators |
| 7 | **LBAC** | `PERM_STRATEGY_LBAC` | Label-based (clearance levels) for MLS-style security |

All strategies follow a **vtable pattern** with `compile_rules`, `evaluate`, `validate_rules`, and `free_compiled_rules` function pointers — rules are pre-compiled into memory structures so runtime evaluation never touches JSON.

### Performance

- **35K+ QPS on Single Core**: The core permission engine evaluates over 35,000 multi-strategy permission checks per second (RBAC + API Path + Location IP checking) with a sub-30μs latency.
- **Lock-Free Concurrency**: Leverages C11 `<stdatomic.h>` (`atomic_fetch_add`) for non-blocking counters and ultra-fast trace ID generation.
- **Pre-compiled Rule Engine**: 100% of rules compiled to in-memory ASTs at policy creation time
- **L1 Resolution Cache**: Caches user-to-policy mappings (60s TTL)
- **L2 Decision Cache**: Caches evaluation results (50 s avg. latency, 30s TTL)
- **DENY-override Model**: Stops on first DENY — fail-closed security
- **Thread-safe**: Pthread read/write locks on all caches; mutex-guarded rate limiter
- **Zero-overhead Metrics**: Atomic counters for hit rates, eval counts, and duration

### Observability

- **Thread-Local Request Tracing**: Every HTTP request receives a unique `request_id` injected into the `X-Request-Id` response header and tracked across threads using C11 `_Thread_local` storage.
- **Structured JSON Logging**: Logs can be formatted as plain text or ELK-compatible JSON, with automatic trace ID injection across all `LOG_*` macros without altering function signatures.
- **Prometheus Metrics**: `/metrics` endpoint exposing cache hit rates, evaluation times, and decision counts
- **Audit Logging**: Every permission decision recorded in structured JSON to `audit.log`
- **Health Check**: `/api/v1/health` endpoint for basic liveness probe

### Administration

- **Embedded Admin UI**: HTML-based management page served at `/admin`
- **Full CRUD API**: Users, roles, groups, policies — all manageable via REST

---

## Project Structure

```
sso/
├── include/                    # Header files
│   ├── sso.h                  # Core types, error codes, strategy vtable, eval_context
│   ├── cJSON.h                # Third-party JSON parser
│   ├── config.h               # Configuration (TOML load + env overrides)
│   ├── group.h                # Group management API
│   ├── oauth.h                # OAuth 2.0 / OIDC handler declarations
│   ├── permission.h           # Permission engine API
│   ├── policy.h               # Policy management API
│   ├── ratelimit.h            # Rate limiter API
│   ├── role.h                 # Role management API (with hierarchy)
│   ├── server.h               # Embedded HTTP server API (unified interface)
│   ├── storage.h              # Storage abstraction layer (pluggable backend)
│   ├── token.h                # Token / session management API
│   ├── toml.h                 # Third-party TOML parser
│   └── user.h                 # User management API
├── src/                        # Source files
│   ├── main.c                 # Entry point: demo / server / interactive modes
│   ├── sso.c                  # Core lifecycle: sso_init(), sso_destroy()
│   ├── server.c               # POSIX socket HTTP server + thread pool (legacy backend)
│   ├── server_mhd.c           # libmicrohttpd HTTP server (primary backend)
│   ├── config.c               # TOML parser + environment variable loader
│   ├── oauth.c                # OAuth 2.0 / OIDC endpoint implementations
│   ├── user.c                 # User manager (Argon2id hashing)
│   ├── role.c                 # Role manager (hierarchy support)
│   ├── group.c                # Group manager (hierarchy support)
│   ├── policy.c               # Policy manager (resolution across user/role/group)
│   ├── token.c                # Token manager (HMAC-SHA256, binary-search revocation)
│   ├── permission.c           # Permission engine (L1/L2 caches, strategy router, audit)
│   ├── ratelimit.c            # Sliding-window rate limiter (DJB2 hash table)
│   ├── storage_sqlite.c       # SQLite storage backend (WAL mode, recursive CTE)
│   ├── cJSON.c                # Third-party JSON parser
│   ├── logger.c               # Logger with level-based filtering
│   ├── login_page.h           # Embedded login HTML page
│   ├── admin_page.h           # Embedded admin HTML page
│   ├── toml.c                 # Third-party TOML parser
├── strategies/                 # 7 pluggable permission strategies
│   ├── func_perm.c            # Functional permission
│   ├── api_perm.c             # API endpoint permission
│   ├── data_perm.c            # Data scope permission
│   ├── rbac_perm.c            # Role-based access control
│   ├── loc_perm.c             # Location/IP permission
│   ├── abac_perm.c            # Attribute-based access control
│   └── lbac_perm.c            # Label-based access control
├── tests/                      # Unit and integration tests
│   ├── minunit.h              # Minimal unit test framework (header-only)
│   ├── test_config.c          # Configuration tests
│   ├── test_group.c           # Group manager tests
│   ├── test_http_api.c        # HTTP API integration tests
│   ├── test_policy.c          # Policy manager tests
│   ├── test_ratelimit.c       # Rate limiter tests
│   ├── test_role.c            # Role manager tests
│   ├── test_server.c          # Server route/handler tests
│   ├── test_storage.c         # Storage backend tests
│   ├── test_token.c           # Token manager tests
│   └── test_user.c            # User manager tests
├── Makefile                   # Build system
├── Dockerfile                 # Multi-stage Docker build
├── docker-compose.yml         # Docker Compose configuration
├── sso.toml                   # Default TOML configuration
└── login.html                 # Standalone login UI
```

---

## Quick Start

### 1. Install Dependencies

**Debian / Ubuntu:**
```bash
sudo apt-get install libsqlite3-dev libssl-dev libsodium-dev libcurl4-openssl-dev libmicrohttpd-dev
```

**Alpine:**
```bash
apk add sqlite-dev openssl-dev libsodium-dev curl-dev libmicrohttpd-dev gcc musl-dev make
```

**macOS (Homebrew):**
```bash
brew install sqlite openssl libsodium curl libmicrohttpd
```

### 2. Build

```bash
make          # Release build (O2)
make debug    # Debug build (O0, -g, -DDEBUG)
```

### 3. Run

```bash
# Demo mode: creates sample data and runs all permission checks
./sso_system

# Server mode: starts HTTP API server on 0.0.0.0:8080
export SSO_TOKEN_SECRET=your_long_secure_secret
./sso_system --server

# Interactive mode: text-based policy creation console
./sso_system --interactive

# Quick reference
./sso_system --help
./sso_system --version
```

### 4. Other Make Targets

| Target | Description |
|--------|-------------|
| `make` | Release build |
| `make debug` | Debug build with symbols |
| `make run` | Build and run demo |
| `make server` | Build and run HTTP server |
| `make test` | Build and run unit tests |
| `make integration-test` | Build and run integration tests |
| `make check` | Run all: demo + unit tests + integration tests |
| `make asan` | Build with AddressSanitizer + UndefinedBehaviorSanitizer |
| `make docker` | Build production Docker image |
| `make clean` | Remove `build/`, binary, and `*.db` files |
| `make size` | Show binary size stats |

---

## Dependencies

| Library | Purpose |
|---------|---------|
| **libsodium** | Argon2id password hashing, secure memory locking (`mlock`/`memzero`) |
| **OpenSSL** | HMAC-SHA256 token signatures |
| **SQLite3** | Persistent storage (WAL mode, recursive CTE for hierarchy) |
| **libcurl** | SMS gateway HTTP calls |
| **libmicrohttpd** | Embedded HTTP server (optional; falls back to POSIX sockets) |
| **pthread** | Thread pool, mutex/rwlock synchronization |
| **cJSON** | Vendored JSON parser (included in source) |
| **toml.c** | Vendored TOML parser (included in source) |

---

## Running Modes

### Demo Mode (default)

Creates 3 users (admin, alice, bob), 3 roles (admin -> editor -> viewer hierarchy), 2 groups (engineering, finance), assigns policies across all 7 strategies, then runs comprehensive permission checks and a 1000-iteration cache stress test.

### Server Mode (`--server`)

Starts an embedded HTTP server backed by either **libmicrohttpd** (preferred, multi-threaded) or **POSIX sockets** (fallback), serving REST APIs on `0.0.0.0:8080`. On first start, bootstraps an admin account and default policies.

Features:
- CORS support with preflight handling
- Security headers (CSP, X-Frame-Options, HSTS)
- TLS/HTTPS support
- Request body size limits
- Configurable thread pool

### Interactive Mode (`--interactive`)

Text-based console for creating and managing policies interactively across all 7 strategy types.

### Options

| Flag | Description |
|------|-------------|
| `-c, --config FILE` | Load TOML configuration file (default: `sso.toml`) |
| `-h, --help` | Show usage help and exit |
| `-v, --version` | Show version and exit |

---

## API Reference

### Public Pages

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Login page (embedded HTML) |
| `GET` | `/login` | Login page (alias) |
| `GET` | `/admin` | Admin management page (embedded HTML; JS handles auth guard) |

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/auth/register` | No | Register new user |
| `POST` | `/api/v1/auth/login` | No | Password-based login (rate-limited: 5/min/IP) |
| `POST` | `/api/v1/auth/send_sms` | No | Send SMS OTP code (rate-limited: 1/min/IP) |
| `POST` | `/api/v1/auth/login_by_sms` | No | SMS code login with auto-registration |
| `GET/POST` | `/api/v1/auth/verify` | No | Validate token |
| `POST` | `/api/v1/auth/refresh` | Yes | Refresh token |
| `POST` | `/api/v1/auth/logout` | Yes | Revoke single token |
| `POST` | `/api/v1/auth/logout_all` | Yes | Revoke all user tokens |
| `POST` | `/api/v1/auth/password` | Yes | Change password |
| `GET` | `/api/v1/auth/me` | Yes | Get current user info |
| `GET` | `/api/v1/auth/userinfo` | Yes | OIDC /userinfo (standard claims) |
| `GET` | `/api/v1/auth/certs` | No | RSA public keys (PEM) for token verification |
| `GET` | `/api/v1/auth/jwks` | No | JWKS key set (RFC 7517) |

### Permission Checks

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/check` | Yes | Unified check (any strategy) |
| `POST` | `/api/v1/check/functional` | Yes | Check functional permission |
| `POST` | `/api/v1/check/api` | Yes | Check API endpoint access |
| `POST` | `/api/v1/check/data` | Yes | Check data scope access |
| `POST` | `/api/v1/check/rbac` | Yes | Check role membership |
| `POST` | `/api/v1/check/location` | Yes | Check IP-based access |
| `POST` | `/api/v1/check/lbac` | Yes | Check label-based access |
| `POST` | `/api/v1/check/abac` | Yes | Check attribute-based access |

### Administration (require auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/v1/users` | List / create users |
| `GET/PUT/DELETE` | `/api/v1/users/{id}` | Get / update / delete user |
| `GET/POST` | `/api/v1/roles` | List / create roles |
| `GET/PUT/DELETE` | `/api/v1/roles/{id}` | Get / update / delete role |
| `POST` | `/api/v1/roles/{id}/assign` | Assign role to user |
| `POST` | `/api/v1/roles/{id}/unassign` | Unassign role from user |
| `GET/POST` | `/api/v1/groups` | List / create groups |
| `GET/PUT/DELETE` | `/api/v1/groups/{id}` | Get / update / delete group |
| `POST` | `/api/v1/groups/{id}/members` | Add member to group |
| `DELETE` | `/api/v1/groups/{id}/members/{user_id}` | Remove member from group |
| `GET/POST` | `/api/v1/policies` | List / create policies |
| `GET/PUT/DELETE` | `/api/v1/policies/{id}` | Get / update / delete policy |
| `POST` | `/api/v1/policies/{id}/assign` | Assign policy |
| `POST` | `/api/v1/policies/{id}/unassign` | Unassign policy |
| `GET` | `/api/v1/audit/logs` | List audit log entries |
| `GET` | `/api/v1/admin/status` | System admin status |

### OAuth 2.0 / OpenID Connect

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | No | OIDC discovery document |
| `GET` | `/api/v1/oauth/authorize` | Yes | Authorization endpoint (auth code flow) |
| `POST` | `/api/v1/oauth/token` | No | Token endpoint (exchange code for tokens) |
| `POST` | `/api/v1/oauth/introspect` | Yes | Token introspection (RFC 7662) |
| `POST` | `/api/v1/oauth/revoke` | Yes | Token revocation (RFC 7009) |

### Monitoring (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/health` | Health check (liveness probe) |
| `GET` | `/metrics` | Prometheus metrics (cache hit rates, eval duration, counters) |

---

## Architecture

```
[ Clients ] ───▶ [ Nginx / API Gateway ]
                     │
                     ▼ (auth_request / OAuth Bearer)
              [ sso_system (C11) ] ◀───▶ [ SQLite (WAL) ]
                ├─ libmicrohttpd / POSIX sockets (dual backend)
                ├─ L1 Resolution Cache (60s TTL)
                ├─ L2 Decision Cache (30s TTL)
                ├─ Pre-compiled Rule ASTs
                ├─ 7 Strategy Registry
                ├─ OAuth 2.0 / OIDC Provider
                └─ Audit Logger (audit.log)
```

### Permission Evaluation Flow

```
Client Request
     │
     ▼
perm_engine_evaluate()
     │
     ├─ 1. Check L2 Decision Cache ────▶ Hit → return cached result
     │
     ├─ 2. Check L1 Resolution Cache ──▶ Hit → skip policy resolution
     │                    │
     │                    ▼ Miss
     │   policy_resolve_for_user()
     │     ├─ Direct user policies
     │     ├─ Role policies (with ancestor inheritance)
     │     └─ Group policies (with ancestor inheritance)
     │
     ├─ 3. For each policy (sorted by priority):
     │     ├─ Skip disabled policies
     │     ├─ Lookup strategy by type
     │     ├─ Use compiled rule (compile if missing)
     │     └─ strategy->evaluate(compiled_rule, eval_context)
     │
     ├─ 4. DENY-override: any DENY → result DENY (fail-closed)
     │
     ├─ 5. Cache result in L2
     │
     └─ 6. Write audit entry
```

---

## Environment Variables

All configuration can be set via environment, TOML config file (`sso.toml`), or both — env vars override file values.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `SSO_HOST` | `0.0.0.0` | Bind address |
| `SSO_PORT` | `8080` | HTTP port |
| `SSO_TLS_ENABLED` | `false` | Enable HTTPS (`true`/`false`) |
| `SSO_TLS_CERT_FILE` | — | Path to TLS certificate PEM file |
| `SSO_TLS_KEY_FILE` | — | Path to TLS private key PEM file |
| `SSO_REQUEST_TIMEOUT_MS` | `30000` | Request timeout in milliseconds |
| `SSO_MAX_BODY_SIZE` | `1048576` | Maximum request body size (bytes) |

### Authentication

| Variable | Required | Description |
|----------|----------|-------------|
| `SSO_TOKEN_SECRET` | Yes (HS256) | 32-byte HMAC secret for token signing |
| `SSO_PRIVATE_KEY` | Yes (RS256) | RSA Private Key (PEM) for asymmetric signing |
| `SSO_PUBLIC_KEY` | No (RS256) | RSA Public Key (PEM); derived from private key if unset |
| `SSO_ADMIN_PASSWORD` | Recommended | Initial admin password; random generated if unset |
| `SSO_PASSWORD_OPSLIMIT` | `3` | Argon2id ops limit (libsodium constant, default = `crypto_pwhash_OPSLIMIT_MODERATE`) |
| `SSO_PASSWORD_MEMLIMIT` | `268435456` | Argon2id memory limit in bytes (default = `crypto_pwhash_MEMLIMIT_MODERATE`, 256 MB) |

### OAuth 2.0 / OIDC

| Variable | Default | Description |
|----------|---------|-------------|
| `SSO_OAUTH_CLIENT_ID` | `sso-cli` | OAuth client ID |
| `SSO_OAUTH_CLIENT_SECRET` | — | OAuth client secret |
| `SSO_OAUTH_REDIRECT_URIS` | — | Comma-separated redirect URIs |
| `SSO_OAUTH_ISSUER` | `http://localhost:8080` | OIDC issuer URL |
| `SSO_OAUTH_AUTH_CODE_TTL_MS` | `300000` | Authorization code TTL (5 min) |

### SMS

| Variable | Default | Description |
|----------|---------|-------------|
| `SSO_SMS_GATEWAY_URL` | — | SMS gateway endpoint URL; unset = mock mode |
| `SSO_SMS_API_KEY` | — | SMS gateway API key |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `SSO_LOG_LEVEL` | `1` | Log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR) |

### Signature Key Setup

**HS256 (symmetric, default):**
```bash
export SSO_TOKEN_SECRET=$(openssl rand -hex 32)
```

**RS256 (asymmetric, preferred for production):**
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
export SSO_PRIVATE_KEY=$(cat private.pem)
export SSO_PUBLIC_KEY=$(cat public.pem)
```

The system auto-detects RS256 when `SSO_PRIVATE_KEY` is set. Public keys are exported at `/api/v1/auth/certs` and JWKS at `/api/v1/auth/jwks`.

---

## Docker Deployment

### Build & Run with Docker Compose

```bash
docker-compose up -d
```

This will:
- Build the multi-stage Docker image
- Start the container on port 8080
- Persist data to a Docker volume
- Mount the audit log to `./audit.log`

### Build Standalone

```bash
# Build image
docker build -t sso-system .

# Run container
docker run -d \
  -p 8080:8080 \
  -e SSO_TOKEN_SECRET=your_super_secret_key \
  -v $(pwd)/audit.log:/app/audit.log \
  sso-system
```

The Docker image runs as the `nobody` user, includes a **HEALTHCHECK** against `/api/v1/health`, and exposes port 8080.

---

## CI/CD

This project uses **GitHub Actions** for continuous integration.

### Workflow: `build-and-test` (push/PR on master/main)

| Step | Description |
|------|-------------|
| **Install dependencies** | `build-essential`, `libsqlite3-dev`, `libsodium-dev`, `libssl-dev`, `libcurl4-openssl-dev`, `libmicrohttpd-dev` |
| **Build** | `make` (release build with `-Wall -Wextra -Wpedantic`) |
| **Run demo** | Executes `./sso_system` which runs comprehensive permission checks and cache stress tests |
| **Unit tests** | `make test` — runs all unit tests |
| **Performance Benchmark** | `make bench` — validates permission engine performance and stability at high throughput |
| **AddressSanitizer** | `make asan` — memory safety + undefined behavior checks |
| **Integration tests** | `make integration-test` — runs all HTTP API integration tests |

### Workflow: `static-analysis`
Runs `cppcheck` and `clang-tidy` against a `bear` generated compilation database to enforce ultra-strict memory and syntax rules, filtering out 3rd-party code.

### Workflow: `frontend-build`
Seamlessly integrated Node.js 20 environment to install dependencies and run `npm run build` on the modern Vue/Vite frontend SPA.

### Workflow: `docker-build` (on build-and-test success)

| Step | Description |
|------|-------------|
| **Docker Buildx** | Sets up multi-stage Docker build |
| **Build image** | Builds the production Docker image without pushing |

The CI config lives at [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Commit Convention

This project follows a strict **Conventional Commits + Gitmoji** convention:

```
[type]([scope]): [emoji] [subject]
```

| Type | Emoji | Description |
|------|-------|-------------|
| `feat` | ✨ | New feature |
| `fix` | 🐛 | Bug fix |
| `docs` | 📝 | Documentation changes |
| `style` | 🎨 | Formatting, missing semi-colons, etc. (no code changes) |
| `refactor` | ♻️ | Code change that neither fixes a bug nor adds a feature |
| `perf` | ⚡️ | Code change that improves performance |
| `test` | ✅ | Adding missing tests or correcting existing tests |
| `build` | 📦 | Changes that affect the build system or external dependencies |
| `ci` | 👷 | Changes to CI configuration files and scripts |
| `chore` | 🚀 | Other changes that don't modify src or test files |
| `revert` | ⏪️ | Reverts a previous commit |

### Examples

```
feat(auth): ✨ implement JWT-based login
fix(ci): 📦 switch to Portable ZIP format to resolve link errors
docs(readme): 📝 update installation instructions
refactor(core): ♻️ extract validation logic to helper
```

---

## Developer Notes

### Adding a New Permission Strategy

1. Create `strategies/your_perm.c` with handler functions:
   - `your_compile()` — parse rules JSON into a compiled struct
   - `your_evaluate()` — check against `eval_context_t`, set `*result`
   - `your_validate()` — validate rules JSON syntax
   - `your_free_compiled()` — free compiled rule memory
2. Populate a `permission_strategy_t` struct with your function pointers
3. Register in `src/permission.c` alongside existing strategies
4. Add a convenience checker like `perm_check_your()` if appropriate

### Running Tests

```bash
# Unit tests (minunit + C11)
make test && ./sso_test

# Integration tests (full HTTP API round-trips)
make integration-test && ./sso_test_integration

# Run everything: demo + unit + integration
make check

# Memory/UB sanitizers
make asan && ./sso_test

# Static analysis
cppcheck --enable=all --suppress=missingIncludeSystem .
```

### Code Style

- C11 standard (`-std=c11`), compiled with `-Wall -Wextra -Wpedantic`
- BSD-style indentation (tabs for indent, 4-column widths)
- Function names: `snake_case` prefixed by module (`perm_engine_`, `policy_`, `sso_`)
- Error handling: return `sso_error_t` enum values, never silently discard errors
- All allocations checked: `malloc`/`calloc` return values verified before use
- String safety: `SSO_STRNCPY_DST` macro guarantees null-termination after copy

### Performance Telemetry

Monitor the `audit.log` or `/metrics` endpoint to observe sub-millisecond performance. Cache hit rates and evaluation duration are tracked using atomic counters for zero-runtime-overhead monitoring.

### Security Considerations

- `SSO_TOKEN_SECRET` is locked in RAM via `sodium_mlock()` and zeroed on `sso_destroy()`
- All password hashing uses Argon2id with moderate parameters
- Token revocation uses binary search for O(log N) lookup
- DENY-override evaluation model ensures fail-closed behavior
- Server runs as non-root in Docker by default (HEALTHCHECK enabled)
- Rate limiting prevents brute-force on login and SMS endpoints
- Security headers (CSP, X-Frame-Options, X-Content-Type-Options) sent on all responses
- TLS support with certificate and key file loading
- CORS allows origin-specific configuration with `Access-Control-Allow-Credentials`
- Request body size limited to `SSO_MAX_BODY_SIZE` (default 1 MiB)
