/*
 * ratelimit.h — In-memory rate limiting for API endpoints.
 *
 * Protects sensitive endpoints (e.g. login, send_sms) from brute-force
 * and denial-of-service attacks.
 */

#ifndef SSO_RATELIMIT_H
#define SSO_RATELIMIT_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rate_limiter rate_limiter_t;

/* Create a rate limiter.
 * max_entries: Maximum number of IPs to track simultaneously.
 */
sso_error_t rate_limiter_create(rate_limiter_t **rl, size_t max_entries);

/* Destroy the rate limiter. */
void rate_limiter_destroy(rate_limiter_t *rl);

/* Check if an action is allowed for a given key (e.g., IP address).
 * window_ms: The sliding window duration in milliseconds.
 * max_requests: Maximum requests allowed within the window.
 * Returns SSO_OK if allowed, SSO_ERR_RATE_LIMIT if exceeded.
 */
sso_error_t rate_limiter_check(rate_limiter_t *rl, const char *key,
                               uint64_t window_ms, int max_requests);

/* Reset the rate limit for a given key (e.g., on successful login). */
void rate_limiter_reset(rate_limiter_t *rl, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* SSO_RATELIMIT_H */