# Decoupled Frontend and PostgreSQL Support Design

## Objective
Modernize the SSO system by separating the UI from the C backend and adding support for PostgreSQL as a high-availability database option. The system will transition to a container-first architecture using Nginx as a reverse proxy/static file server.

## 1. Frontend: Vue.js Single Page Application (SPA)

### Architecture
- **Location**: `/frontend` directory.
- **Stack**: Vue 3 + Vite + TypeScript + Tailwind CSS.
- **UI Library**: PrimeVue (for professional admin components).
- **Communication**: Axios or Fetch API calling the C backend via `/api/v1/*`.
- **Authentication**: JWT stored in `localStorage` or Secure Cookies.

### Key Components
- **LoginView**: Replaces `src/login_page.h`. Handles Password/MFA flows.
- **AdminDashboard**: Replaces `src/admin_page.h`. Interactive CRUD for Users, Roles, Groups, and Policies.
- **AuthModule**: Centralized logic for token management and MFA verification.

## 2. Storage: PostgreSQL Backend

### Interface Implementation
A new file `src/storage_postgres.c` will implement the `storage_backend_t` interface defined in `include/storage.h`.

- **Library**: `libpq` (official PostgreSQL C library).
- **Schema Mapping**:
  - `INTEGER PRIMARY KEY AUTOINCREMENT` (SQLite) -> `BIGSERIAL PRIMARY KEY` (PG).
  - `TEXT` -> `TEXT` or `VARCHAR`.
  - `INTEGER` (timestamps) -> `BIGINT`.
- **Connection Management**: Persistent connection with automatic reconnection logic.

### Configuration
`sso.toml` will be updated:
```toml
[database]
type = "postgres" # or "sqlite"
url = "postgres://user:pass@host:5432/sso"
```

## 3. Deployment: Docker & Nginx

### Multi-Stage Dockerfile
1. **Frontend Builder**: Uses `node:20-alpine` to build the Vue app into `/dist`.
2. **Backend Builder**: Uses `alpine:3.18` to compile the C binary with `libpq-dev`.
3. **Final Image**:
   - Contains the `sso_system` binary.
   - Contains Nginx to serve the `/dist` folder.
   - Nginx proxies `/api` and `/.well-known` to the local C process.

### Docker Compose
- **sso-service**: The combined Nginx/C container.
- **postgres-db**: Official `postgres:15-alpine` image.
- **gogs-service**: Existing Gogs integration.

## 4. Migration Plan
- Existing embedded HTML headers (`login_page.h`, `admin_page.h`) will be deprecated and eventually removed.
- `main.c` will be updated to detect the database type from config and load the appropriate storage driver.
- The default build will now require `libpq` installed on the system (handled via `pkg-config` in the Makefile).

## 5. Testing
- **Frontend**: Vitest for component testing.
- **Database**: The existing `tests/test_storage.c` will be extended to run its suite against a live PostgreSQL instance (if available in CI) to ensure feature parity with SQLite.
- **Integration**: Playwright or Cypress for end-to-end flow validation (Login -> Admin -> Gogs).
