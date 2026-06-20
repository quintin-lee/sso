# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- `.clang-format` — code style configuration matching project conventions
- `.clang-tidy` — static analysis configuration
- `.githooks/pre-commit` — automated format + whitespace + secret scan checks
- `CHANGELOG.md` — this file
- `docs/openapi.yaml` — OpenAPI 3.1 specification
- Top-level `CMakeLists.txt` — CMake build system as alternative to Makefile

### Changed
- All large stack buffers (>2 KB) converted to heap allocation across 11 source files
- Audit log switches from per-call `fopen`/`fclose` to persistent `FILE*` with 64 KB buffer
- Rate limiter eviction consolidated from 3-pass scan to single-pass `find_or_evict()`

### Fixed
- 233 `strncpy` call sites replaced with null-termination-safe `sso_strlcpy()`
- cJSON global `InitHooks` removed — eliminates cross-thread alloc/free UB (thread safety)
- Token HMAC payload encoding fixed (exact-length `memcpy` preserving original semantics)

### Security
- `sso_strlcpy()` ensures all string copies are null-terminated
- Pre-commit hook scans for accidental API keys/tokens/secrets in staged changes

---

## [1.3.0] — 2026-06-20

### Added
- DPoP (Demonstration of Proof-of-Possession) token theft prevention
- Silent token rotation with idle timeout
- Session concurrency control (max 3 sessions per user)
- Zero-Trust multi-tenancy sandbox with siloed data isolation
- Adaptive risk engine for behavioral and IP anomaly detection
- Redis Pub/Sub broadcast + Bloom filter for zero-hop JTI revocation
- Redis Sentinel high-availability via `redis-sentinel://` DSN
- Database-backed structured audit logging (SQLite + Postgres)
- OIDC RP-Initiated Single Logout (SLO)
- SQLite thread-local read-only connection pool
- Thread-safe atomic config hot-reload via SIGHUP

### Performance
- Request-scoped arena memory pool allocator with `arena_reset`
- cJSON allocations redirected to arena pool
- Rate limiter LRU eviction when slot cache is full

### Fixed
- Data race in permission cache updates
- Memory leak in data scope strategy `field_filter` allocation
- K8s port alignment in deployment manifests

---

## [1.2.0] — 2026-06-18

### Added
- Vue.js 3 frontend SPA with Vite, Tailwind CSS, PrimeVue
- PostgreSQL storage backend (full feature parity with SQLite)
- Redis storage backend skeleton + hiredis integration
- OAuth client application management UI
- Application portal for unified single sign-on redirect
- K8s manifests (deployment, service, configmap)
- Policy simulator tool
- i18n localization support
- Admin CRUD audit logging

### Frontend
- Login and MFA UI with glassmorphic theme
- Admin dashboard with UserManagement, RoleManagement, GroupManagement, PolicyManagement
- AuditLogViewer component
- Policy MultiSelect and assignment UI
- Premium dark security theme with glow animations

### Fixed
- Memory leak in memory storage backend
- Docker container startup failures
- `created_at` timestamp parsing (ms vs seconds)
- Various GCC strncpy `-Wstringop-truncation` warnings

---

## [1.1.0] — 2026-06-16

### Added
- OAuth 2.0 / OpenID Connect provider
  - Authorization code flow, PKCE (S256 + plain)
  - RFC 7662 token introspection, RFC 7009 revocation
  - OIDC discovery, JWKS (RFC 7517), `/userinfo`
- libmicrohttpd HTTP server backend (conditional compilation)
- Prometheus `/metrics` endpoint
- Support for both HS256 (symmetric) and RS256 (asymmetric) token signing
- TOML configuration file support
- `--help` / `--version` CLI flags
- Full pagination, search, and status filtering across all admin modules
- Request timeouts, body size limits
- TLS/HTTPS support
- `make check` target (demo + unit tests + integration tests)

### Refactored
- Monolithic `main.c` split into `server.c`, `handlers_*.c`, `demo.c`, `interactive.c`
- Route table extracted; handlers organized by domain (auth, admin, check, pages)
- Common helper functions moved to `handlers_common.c`

### Testing
- Zero-dependency minunit test suite across 11 test files
- Integration tests with full HTTP API round-trips
- ASan/UBSan CI job
- cppcheck static analysis in CI

### Infrastructure
- Docker multi-stage build with healthcheck
- Docker Compose with volume management
- Nginx reverse proxy configuration
- Gogs integration
- GitHub Actions CI with build + test + ASan + Docker

---

## [1.0.0] — 2026-06-14

### Added
- Core SSO lifecycle (`sso_init` / `sso_destroy`)
- Password authentication with Argon2id (libsodium)
- SMS OTP login with automatic registration
- Token management (HS256 JWT, refresh, rotation, revocation)
- 7 permission strategies:
  - Functional (feature flags with wildcards)
  - API Endpoint (method + path matching with `*`, `**`, `:param`)
  - Data Scope (row-level conditions + field-level whitelist)
  - RBAC (role hierarchy with ancestor inheritance)
  - Location (IP/CIDR matching)
  - ABAC (attribute-based with operators)
  - LBAC (label-based with MLS-style clearance)
- Pre-compiled rule engine (rules compiled to in-memory ASTs)
- L1 resolution cache, L2 decision cache (DENY-override, fail-closed)
- Thread-safe RW-lock caches with atomic metrics counters
- Embedded POSIX socket HTTP server
- Embedded admin HTML page with full CRUD
- Embedded login page with glassmorphism UI
- Interactive policy configuration shell
- SQLite storage backend (WAL mode, recursive CTE for hierarchy)
- Memory storage backend
- In-memory rate limiter (sliding window)
- Structured logging with level-based filtering

### Infrastructure
- Makefile-based build system
- Dockerfile
- Basic GitHub Actions CI

---

[1.3.0]: https://github.com/quintin-lee/sso/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/quintin-lee/sso/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/quintin-lee/sso/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/quintin-lee/sso/releases/tag/v1.0.0
