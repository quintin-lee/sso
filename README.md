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

This project is in active development. The core authentication and authorization engine is stable and feature-complete with all 7 permission strategies implemented. The HTTP API server, Docker deployment, and CI pipeline are operational.

**Current**: `v1.0.0` — core SSO engine, all 7 strategies, embedded HTTP server, Docker support.

---

## Key Features

### Authentication

- **Password Authentication**: Argon2id hashing via libsodium
- **SMS OTP Login**: Mobile verification code with auto-registration, served via libcurl to SMS gateway
- **JWT-style Tokens**: HMAC-SHA256 signed tokens with roles, groups embdded in claims
- **Token Revocation**: O(log N) binary search on revocaton lists for instant invalidation

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

- **Pre-compiled Rule Engine**: 100% of rules compiled to in-memory ASTs at policy creation time
- **L1 Resolution Cache**: Caches user-to-policy mappings (60s TTL)
- **L2 Decision Cache**: Caches evaluation results (50 s avg. latency, 30s TTL)
- **DENY-override Model**: Stops on first DENY — fail-closed security
- **Thread-safe**: Pthread read/write locks on all caches; mutex-guarded rate limiter
- **Zero-overhead Metrics**: Atomic counters for hit rates, eval counts, and duration

### Observability

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
│   ├── group.h                # Group management API
│   ├── permission.h           # Permission engine API
│   ├── policy.h               # Policy management API
│   ├── ratelimit.h            # Rate limiter API
│   ├── role.h                 # Role management API (with hierarchy)
│   ├── server.h               # Embedded HTTP server API
│   ├── storage.h              # Storage abstraction layer (pluggable backend)
│   ├── token.h                # Token / session management API
│   └── user.h                 # User management API
├── src/                        # Source files
│   ├── main.c                 # Entry point: demo / server / interactive modes
│   ├── sso.c                  # Core lifecycle: sso_init(), sso_destroy()
│   ├── server.c               # POSIX socket HTTP server + thread pool
│   ├── user.c                 # User manager (Argon2id hashing)
│   ├── role.c                 # Role manager (hierarchy support)
│   ├── group.c                # Group manager (hierarchy support)
│   ├── policy.c               # Policy manager (resolution across user/role/group)
│   ├── token.c                # Token manager (HMAC-SHA256, binary-search revocation)
│   ├── permission.c           # Permission engine (L1/L2 caches, strategy router, audit)
│   ├── ratelimit.c            # Sliding-window rate limiter (DJB2 hash table)
│   ├── storage_sqlite.c       # SQLite storage backend (WAL mode, recursive CTE)
│   ├── cJSON.c                # Third-party JSON parser
│   ├── login_page.h           # Embedded login HTML page
│   └── admin_page.h           # Embedded admin HTML page
├── strategies/                 # 7 pluggable permission strategies
│   ├── func_perm.c            # Functional permission
│   ├── api_perm.c             # API endpoint permission
│   ├── data_perm.c            # Data scope permission
│   ├── rbac_perm.c            # Role-based access control
│   ├── loc_perm.c             # Location/IP permission
│   ├── abac_perm.c            # Attribute-based access control
│   └── lbac_perm.c            # Label-based access control
├── Makefile                   # Build system
├── Dockerfile                 # Multi-stage Docker build
├── docker-compose.yml         # Docker Compose configuration
└── login.html                 # Standalone login UI
```

---

## Quick Start

### 1. Install Dependencies

**Debian / Ubuntu:**
```bash
sudo apt-get install libsqlite3-dev libssl-dev libsodium-dev libcurl4-openssl-dev
```

**Alpine:**
```bash
apk add sqlite-dev openssl-dev libsodium-dev curl-dev gcc musl-dev make
```

**macOS (Homebrew):**
```bash
brew install sqlite openssl libsodium curl
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
```

### 4. Other Make Targets

| Target | Description |
|--------|-------------|
| `make` | Release build |
| `make debug` | Debug build with symbols |
| `make run` | Build and run demo |
| `make server` | Build and run HTTP server |
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
| **pthread** | Thread pool, mutex/rwlock synchronization |
| **cJSON** | Vendored JSON parser (included in source) |

---

## Running Modes

### Demo Mode (default)

Creates 3 users (admin, alice, bob), 3 roles (admin -> editor -> viewer hierarchy), 2 groups (engineering, finance), assigns policies across all 7 strategies, then runs comprehensive permission checks and a 1000-iteration cache stress test.

### Server Mode (`--server`)

Starts an embedded HTTP server backed by an 8-worker thread pool (queue depth 1024), serving REST APIs on `0.0.0.0:8080`. On first start, bootstraps an admin account and default policies.

### Interactive Mode (`--interactive`)

Text-based console for creating and managing policies interactively across all 7 strategy types.

---

## API Reference

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/` | No | Login page (HTML) |
| `GET` | `/admin` | No | Admin management page |
| `POST` | `/api/v1/auth/register` | No | Register new user |
| `POST` | `/api/v1/auth/login` | No | Password-based login (rate-limited: 5/min/IP) |
| `POST` | `/api/v1/auth/send_sms` | No | Send SMS OTP code (rate-limited: 1/min/IP) |
| `POST` | `/api/v1/auth/login_by_sms` | No | SMS code login with auto-registration |
| `POST` | `/api/v1/auth/verify` | No | Validate token |
| `POST` | `/api/v1/auth/refresh` | Yes | Refresh token |
| `POST` | `/api/v1/auth/logout` | Yes | Revoke token |
| `GET` | `/api/v1/auth/me` | Yes | Get current user info |

### Permission Checks

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/check` | No | Unified check (any strategy) |
| `POST` | `/api/v1/check/functional` | No | Check functional permission |
| `POST` | `/api/v1/check/api` | No | Check API endpoint access |
| `POST` | `/api/v1/check/data` | No | Check data scope access |
| `POST` | `/api/v1/check/rbac` | No | Check role membership |
| `POST` | `/api/v1/check/location` | No | Check IP-based access |
| `POST` | `/api/v1/check/lbac` | No | Check label-based access |
| `POST` | `/api/v1/check/abac` | No | Check attribute-based access |

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
| `GET/POST` | `/api/v1/policies` | List / create policies |
| `GET/PUT/DELETE` | `/api/v1/policies/{id}` | Get / update / delete policy |
| `POST` | `/api/v1/policies/{id}/assign` | Assign policy |
| `POST` | `/api/v1/policies/{id}/unassign` | Unassign policy |

### Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

---

## Architecture

```
[ Clients ] ───▶ [ Nginx / API Gateway ]
                     │
                     ▼ (auth_request)
              [ sso_system (C11) ] ◀───▶ [ SQLite (WAL) ]
                ├─ Thread Pool (8 workers)
                ├─ L1 Resolution Cache (60s TTL)
                ├─ L2 Decision Cache (30s TTL)
                ├─ Pre-compiled Rule ASTs
                ├─ 7 Strategy Registry
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

| Variable | Required | Description |
|----------|----------|-------------|
| `SSO_TOKEN_SECRET` | Yes (server mode) | 32-byte HMAC secret for token signing. If not set, falls back to `/dev/urandom` |
| `SSO_ADMIN_PASSWORD` | Recommended | Admin user password. If not set, defaults to `admin123` |

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

The Docker image runs as the `nobody` user and exposes port 8080.

---

## CI/CD

This project uses **GitHub Actions** for continuous integration.

### Workflow: `build-and-test` (push/PR on master/main)

| Step | Description |
|------|-------------|
| **Install dependencies** | `build-essential`, `libsqlite3-dev`, `libsodium-dev`, `libssl-dev`, `libcurl4-openssl-dev` |
| **Build** | `make` (release build with `-Wall -Wextra -Wpedantic`) |
| **Run demo** | Executes `./sso_system` which runs comprehensive permission checks and cache stress tests |

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

### Performance Telemetry

Monitor the `audit.log` or `/metrics` endpoint to observe sub-millisecond performance. Cache hit rates and evaluation duration are tracked using atomic counters for zero-runtime-overhead monitoring.

### Security Considerations

- `SSO_TOKEN_SECRET` is locked in RAM via `sodium_mlock()` and zeroed on `sso_destroy()`
- All password hashing uses Argon2id with moderate parameters
- Token revocation uses binary search for O(log N) lookup
- DENY-override evaluation model ensures fail-closed behavior
- Server runs as non-root in Docker by default
- Rate limiting prevents brute-force on login and SMS endpoints
