# SSO System — High-Performance Single Sign-On Service in C

A lightweight, enterprise-ready Single Sign-On (SSO) service written in C, providing unified authentication and authorization with sub-millisecond latency. Designed for high-concurrency microservice architectures.

## Key Production-Grade Features

### 🚀 High Performance
- **Pre-compiled Permission Engine**: 100% of rules (RBAC, ABAC, etc.) are pre-compiled into memory structures, eliminating runtime JSON parsing in the critical path.
- **Multi-Level Caching**:
  - **L1 (Resolution Cache)**: Caches user-to-policy mappings.
  - **L2 (Decision Cache)**: Caches evaluation results for specific contexts (50μs avg. latency).
- **Fast Token Revocation**: O(log N) binary search on revocation lists for instant token invalidation.

### 🛡️ Enterprise Security
- **Robust JWT Handling**: Full standard-compliant JSON processing via `cJSON` for token issuance and verification.
- **IP-Based Rate Limiting**: Built-in sliding window rate limiter to prevent SMS bombing and brute-force attacks.
- **Audit Logging**: Every decision is recorded in a structured JSON audit log for traceability.
- **Argon2id Hashing**: Industry-standard password hashing via `libsodium`.

### 🌐 Scalability & Observability
- **Multithreaded Architecture**: POSIX Thread Pool handles hundreds of concurrent HTTP requests without blocking.
- **Prometheus Metrics**: Built-in `/metrics` endpoint for real-time monitoring of cache hit rates, evaluation times, and decision counts.
- **Cloud Native**: Multi-stage Docker builds and Docker Compose support for immediate deployment.
- **SQLite WAL Mode**: High-concurrency database access with Write-Ahead Logging.

## Quick Start

### Build
```bash
make
```

### Run (Server Mode)
```bash
# Set your production secret
export SSO_TOKEN_SECRET=your_long_secure_secret
export SSO_ADMIN_PASSWORD=your_admin_password
./sso_system --server
```

### Docker Deployment
```bash
docker-compose up -d
```

## API Reference

### Auth & Maintenance
- `POST /api/v1/auth/login`: Password-based login.
- `POST /api/v1/auth/send_sms`: Request mobile verification code (Rate-limited).
- `POST /api/v1/auth/login_by_sms`: Code-based login with auto-registration.
- `GET /metrics`: Prometheus-compatible performance data.
- `GET /api/v1/health`: Basic service health check.

### Permission Checks
- `POST /api/v1/check`: Unified check endpoint accepting any combination of strategies.
- `POST /api/v1/check/rbac`: Direct RBAC role membership check.
- `POST /api/v1/check/data`: Record-level and field-level visibility check.

## Architecture

```
[ Clients ] ───▶ [ Nginx / API Gateway ]
                     │
                     ▼ (auth_request)
              [ sso_system (C11) ] ◀───▶ [ SQLite (WAL) ]
                ├─ Thread Pool
                ├─ L1/L2 Caches
                └─ Pre-compiled AST
```

## Developer Notes

### Performance Telemetry
Monitor the `audit.log` or `/metrics` endpoint to observe the sub-millisecond performance. Cache hit rates and evaluation duration are tracked using atomic counters for zero-overhead monitoring.

### Deployment Security
In production, ensure `SSO_TOKEN_SECRET` and `SSO_ADMIN_PASSWORD` are set via environment variables. The service runs as a non-root user in Docker by default.
