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

static size_t find_slot(rl_entry_t *entries, size_t max, const char *key) {
    size_t idx = hash_string(key) % max;
    for (size_t i = 0; i < max; i++) {
        size_t probe = (idx + i) % max;
        if (entries[probe].key[0] == '\0') return probe;
        if (strcmp(entries[probe].key, key) == 0) return probe;
    }
    return max;
}

static size_t find_empty_or_expired(rl_entry_t *entries, size_t max, const char *key, uint64_t now, uint64_t window_ms) {
    size_t idx = hash_string(key) % max;
    for (size_t i = 0; i < max; i++) {
        size_t probe = (idx + i) % max;
        rl_entry_t *e = &entries[probe];
        if (e->key[0] == '\0') return probe;
        if ((now - e->window_start_ms) > window_ms) { e->key[0] = '\0'; return probe; }
    }
    return max;
}

sso_error_t rate_limiter_check(rate_limiter_t *rl, const char *key,
                               uint64_t window_ms, int max_requests) {
    if (!rl || !key) return SSO_ERR_INVALID_PARAM;

    uint64_t now = get_time_ms();

    pthread_mutex_lock(&rl->lock);

    /* First: try to find exact slot for key */
    size_t idx = find_slot(rl->entries, rl->max_entries, key);
    if (idx < rl->max_entries) {
        rl_entry_t *entry = &rl->entries[idx];
        if (strcmp(entry->key, key) != 0) { idx = rl->max_entries; goto not_found; }
        /* Key found — check if window expired */
        if ((now - entry->window_start_ms) <= window_ms) {
            /* Within window, increment */
            entry->count++;
            sso_error_t result = (entry->count > max_requests) ? SSO_ERR_RATE_LIMIT : SSO_OK;
            pthread_mutex_unlock(&rl->lock);
            return result;
        }
        /* Window expired — treat as new entry */
        entry->window_start_ms = now;
        entry->count = 1;
        pthread_mutex_unlock(&rl->lock);
        return SSO_OK;
    }

not_found:
    /* Key not found — find empty or expired slot */
    idx = find_empty_or_expired(rl->entries, rl->max_entries, key, now, window_ms);
    if (idx >= rl->max_entries) {
        pthread_mutex_unlock(&rl->lock);
        return SSO_ERR_RATE_LIMIT;
    }

    rl_entry_t *entry = &rl->entries[idx];
    strncpy(entry->key, key, MAX_KEY_LEN - 1);
    entry->key[MAX_KEY_LEN - 1] = '\0';
    entry->window_start_ms = now;
    entry->count = 1;
    pthread_mutex_unlock(&rl->lock);
    return SSO_OK;
}

void rate_limiter_reset(rate_limiter_t *rl, const char *key) {
    if (!rl || !key) return;

    pthread_mutex_lock(&rl->lock);

    size_t idx = find_slot(rl->entries, rl->max_entries, key);
    if (idx < rl->max_entries && strcmp(rl->entries[idx].key, key) == 0) {
        rl->entries[idx].count = 0;
        rl->entries[idx].window_start_ms = 0;
    }

    pthread_mutex_unlock(&rl->lock);
}