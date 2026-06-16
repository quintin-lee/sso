# PostgreSQL Storage Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a new PostgreSQL storage backend using `libpq` that fulfills the existing `storage_backend_t` interface.

**Architecture:** We will create `src/storage_postgres.c` which implements all storage function pointers (User, Role, Group, Policy, Tokens). We'll update the config system to support PostgreSQL DSNs and modify the build system to link against `libpq`.

**Tech Stack:** C11, PostgreSQL `libpq`, SQLite3 (maintained as alternative).

---

### Task 1: Build System & Config Updates

**Files:**
- Modify: `Makefile`
- Modify: `include/config.h`
- Modify: `src/config.c`
- Modify: `src/main.c`

- [ ] **Step 1: Update Makefile to check for libpq**

```makefile
# In Makefile
CFLAGS += $(shell pkg-config --cflags libpq)
LDFLAGS += $(shell pkg-config --libs libpq)
```

- [ ] **Step 2: Update `sso_config_t` and defaults**

```c
/* In include/config.h, update sso_config_t */
    char database_type[16]; /* "sqlite" or "postgres" */
    char database_url[SSO_MAX_PATH];
```

```c
/* In src/config.c, sso_config_default */
    strncpy(cfg->database_type, "sqlite", sizeof(cfg->database_type)-1);
    strncpy(cfg->database_url, "sso_server.db", sizeof(cfg->database_url)-1);
```

- [ ] **Step 3: Update `main.c` to instantiate the correct backend**

```c
/* In src/main.c, inside run_server */
    storage_backend_t *storage = NULL;
    if (strcmp(cfg->database_type, "postgres") == 0) {
        err = storage_postgres_create(&storage);
    } else {
        err = storage_sqlite_create(&storage);
    }
```

- [ ] **Step 4: Commit**

```bash
git add Makefile include/config.h src/config.c src/main.c
git commit -m "feat(config): 📦 add postgres configuration support"
```

---

### Task 2: PostgreSQL Backend Implementation (Boilerplate)

**Files:**
- Create: `src/storage_postgres.c`
- Modify: `include/storage.h`

- [ ] **Step 1: Declare `storage_postgres_create` in `storage.h`**

```c
/* In include/storage.h */
sso_error_t storage_postgres_create(storage_backend_t **backend);
```

- [ ] **Step 2: Implement connection logic in `src/storage_postgres.c`**

```c
#include <libpq-fe.h>
/* Implement postgres_open using PQconnectdb */
```

- [ ] **Step 3: Commit**

```bash
git add include/storage.h src/storage_postgres.c
git commit -m "feat(storage): ✨ implement postgres connection boilerplate"
```

---

### Task 3: Implement User & Token CRUD for PostgreSQL

**Files:**
- Modify: `src/storage_postgres.c`

- [ ] **Step 1: Implement `postgres_user_create` and `postgres_user_get`**
- [ ] **Step 2: Implement `postgres_refresh_token_create` and `revoke`**
- [ ] **Step 3: Commit**

```bash
git add src/storage_postgres.c
git commit -m "feat(storage): ✨ implement user and token storage for postgres"
```

---

### Task 4: Complete Storage Implementation & Test

**Files:**
- Modify: `src/storage_postgres.c`
- Modify: `tests/test_storage.c`

- [ ] **Step 1: Implement remaining Role, Group, Policy CRUD for PostgreSQL**
- [ ] **Step 2: Update `tests/test_storage.c` to run against Postgres if `SSO_TEST_PG_URL` is set**
- [ ] **Step 3: Verify all tests pass**

Run: `SSO_TEST_PG_URL="postgres://..." make test`

- [ ] **Step 4: Commit**

```bash
git add src/storage_postgres.c tests/test_storage.c
git commit -m "feat(storage): ✨ complete postgres backend implementation"
```
