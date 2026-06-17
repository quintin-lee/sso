# PostgreSQL Backend Completion and Test Refactoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the PostgreSQL storage backend implementation and refactor the storage tests to be generic, supporting PostgreSQL tests when a URL is provided.

**Architecture:** 
1. Fix corrupted function signature in `src/storage_postgres.c`.
2. Refactor `tests/test_storage.c` to use generic test functions that accept `storage_backend_t*`.
3. Update `main` in `tests/test_storage.c` to handle `SSO_TEST_PG_URL` and run generic tests against all supported backends (Memory, SQLite, and optionally PostgreSQL).

**Tech Stack:** C, libpq (PostgreSQL client library), SQLite3, minunit (test framework).

---

### Task 1: Fix `src/storage_postgres.c`

**Files:**
- Modify: `src/storage_postgres.c`

- [ ] **Step 1: Fix corrupted `postgres_rt_create` signature**

Find the corrupted section:
```c
/* ========================================================================
 * Assignment helpers
    if (!self || !rt) return SSO_ERR_INVALID_PARAM;
```
And replace it with:
```c
static sso_error_t postgres_rt_create(storage_backend_t *self, const refresh_token_t *rt) {
    if (!self || !rt) return SSO_ERR_INVALID_PARAM;
```

- [ ] **Step 2: Clean up section comments**

Ensure section comments are accurate (e.g., move the `OAuth Storage` comment above the OAuth functions).

- [ ] **Step 3: Verify build**

Run: `make`
Expected: SUCCESS

### Task 2: Refactor `tests/test_storage.c` to be Generic

**Files:**
- Modify: `tests/test_storage.c`

- [ ] **Step 1: Create generic test functions**

Refactor existing tests into generic versions:
- `test_user_crud(storage_backend_t *s)`
- `test_role_crud(storage_backend_t *s)`
- `test_group_crud(storage_backend_t *s)`
- `test_assignments(storage_backend_t *s)`
- `test_not_found(storage_backend_t *s)`
- `test_duplicate(storage_backend_t *s)`
- `test_refresh_tokens(storage_backend_t *s)`
- `test_oauth_clients(storage_backend_t *s)`

- [ ] **Step 2: Implement `run_storage_suite(storage_backend_t *s, const char *dsn)`**

A helper that opens the backend, runs all generic tests, and closes it.

- [ ] **Step 3: Update `main` to handle `SSO_TEST_PG_URL`**

```c
int main(int argc, char **argv) {
    // Run Memory tests
    // Run SQLite tests
    // If SSO_TEST_PG_URL set, run PostgreSQL tests
}
```

- [ ] **Step 4: Verify build and run SQLite/Memory tests**

Run: `make && ./build/test_storage`
Expected: ALL TESTS PASSED (for SQLite and Memory)

### Task 3: Final Verification and Commit

- [ ] **Step 1: Run all tests**

Run: `make test`
Expected: SUCCESS (SQLite and Memory tests pass)

- [ ] **Step 2: Commit changes**

```bash
git add src/storage_postgres.c tests/test_storage.c
git commit -m "feat(storage): ✨ complete postgres backend implementation and update tests"
```
