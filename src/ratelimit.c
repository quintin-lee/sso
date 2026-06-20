/*
 * ratelimit.c — In-memory rate limiting implementation.
 *
 * Uses a fixed-size hash table with chaining or simple LRU replacement 
 * to track request counts per IP within a sliding window.
 */

#include "ratelimit.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define MAX_KEY_LEN 64

typedef struct {
    char     key[MAX_KEY_LEN];
    uint64_t window_start_ms;
    int      count;
    uint64_t last_access_ms;
} rl_entry_t;

struct rate_limiter {
    rl_entry_t     *entries;
    size_t          max_entries;
    pthread_mutex_t lock;
};

static uint64_t get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (ts.tv_nsec / 1000000);
}

/* Simple DJB2 hash */
static size_t hash_string(const char *str) {
    size_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

sso_error_t rate_limiter_create(rate_limiter_t **rl, size_t max_entries) {
    if (!rl || max_entries == 0) return SSO_ERR_INVALID_PARAM;

    *rl = (rate_limiter_t *)calloc(1, sizeof(rate_limiter_t));
    if (!*rl) return SSO_ERR_OUT_OF_MEMORY;

    (*rl)->max_entries = max_entries;
    (*rl)->entries = (rl_entry_t *)calloc(max_entries, sizeof(rl_entry_t));
    if (!(*rl)->entries) {
        free(*rl);
        *rl = NULL;
        return SSO_ERR_OUT_OF_MEMORY;
    }

    pthread_mutex_init(&(*rl)->lock, NULL);
    return SSO_OK;
}

void rate_limiter_destroy(rate_limiter_t *rl) {
    if (!rl) return;
    pthread_mutex_destroy(&rl->lock);
    free(rl->entries);
    free(rl);
}

/* Single-pass probe: find exact match, first empty, first expired, or LRU candidate.
 * Returns a valid index (< max) or max if the table is empty (shouldn't happen).
 * Only used internally by rate_limiter_check — the probe order ensures
 * we never scan the table more than once under the lock. */
static size_t find_or_evict(rl_entry_t *entries, size_t max,
                            const char *key, uint64_t now, uint64_t window_ms) {
    size_t idx = hash_string(key) % max;
    size_t candidate = max;
    bool candidate_expired = false;
    size_t lru_idx = 0;
    uint64_t min_access = (uint64_t)-1;

    for (size_t i = 0; i < max; i++) {
        size_t probe = (idx + i) % max;
        rl_entry_t *e = &entries[probe];

        if (e->key[0] == '\0') return probe;                         /* empty — immediate reuse */
        if (strcmp(e->key, key) == 0) return probe;                  /* exact match */

        /* Remember first expired entry for potential reuse */
        if (!candidate_expired && (now - e->window_start_ms) > window_ms) {
            candidate = probe;
            candidate_expired = true;
        }

        /* Track LRU (best effort — only valid among non-expired) */
        if (e->last_access_ms < min_access) {
            min_access = e->last_access_ms;
            lru_idx = probe;
        }
    }

    return candidate_expired ? candidate : lru_idx;
}

sso_error_t rate_limiter_check(rate_limiter_t *rl, const char *key,
                               uint64_t window_ms, int max_requests) {
    if (!rl || !key) return SSO_ERR_INVALID_PARAM;

    uint64_t now = get_time_ms();

    pthread_mutex_lock(&rl->lock);

    /* Single pass: find exact match, or a reusable slot (empty/expired/LRU) */
    size_t idx = find_or_evict(rl->entries, rl->max_entries, key, now, window_ms);

    rl_entry_t *entry = &rl->entries[idx];

    if (strcmp(entry->key, key) == 0) {
        /* Exact match — check window */
        entry->last_access_ms = now;
        if ((now - entry->window_start_ms) <= window_ms) {
            entry->count++;
            sso_error_t result = (entry->count > max_requests) ? SSO_ERR_RATE_LIMIT : SSO_OK;
            pthread_mutex_unlock(&rl->lock);
            return result;
        }
        /* Window expired — reset window */
        entry->window_start_ms = now;
        entry->count = 1;
        pthread_mutex_unlock(&rl->lock);
        return SSO_OK;
    }

    /* New or reused slot — initialize */
    sso_strlcpy(entry->key, key, MAX_KEY_LEN);
    entry->window_start_ms = now;
    entry->last_access_ms = now;
    entry->count = 1;
    pthread_mutex_unlock(&rl->lock);
    return SSO_OK;
}

void rate_limiter_reset(rate_limiter_t *rl, const char *key) {
    if (!rl || !key) return;

    pthread_mutex_lock(&rl->lock);

    /* Simple hash probe — not hot-path, so no need for combined find/evict */
    size_t idx = hash_string(key) % rl->max_entries;
    size_t probe = idx;
    size_t i = 0;
    while (i < rl->max_entries && rl->entries[probe].key[0] != '\0') {
        if (strcmp(rl->entries[probe].key, key) == 0) {
            rl->entries[probe].count = 0;
            rl->entries[probe].window_start_ms = 0;
            rl->entries[probe].last_access_ms = 0;
            break;
        }
        i++;
        probe = (idx + i) % rl->max_entries;
    }

    pthread_mutex_unlock(&rl->lock);
}