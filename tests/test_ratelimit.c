/*
 * test_ratelimit.c — Unit tests for the sliding-window rate limiter.
 *
 * Tests rate limit creation, per-key counting, window expiry,
 * limit enforcement (allow/deny at threshold), and cleanup of
 * expired entries from the hash table.
 */

#include <stdio.h>
#include <unistd.h>
#include "minunit.h"
#include "ratelimit.h"
#include "sso.h"

int tests_run = 0;

static const char* test_ratelimit_basic() {
	printf("  Running test_ratelimit_basic...\n");
	rate_limiter_t* rl;
	sso_error_t		err = rate_limiter_create(&rl, 100);
	ASSERT_INT_EQUAL(err, SSO_OK);

	uint64_t window = 60000;
	int		 max	= 5;

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "1.2.3.4", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "1.2.3.4", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "1.2.3.4", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "1.2.3.4", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "1.2.3.4", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "1.2.3.4", window, max), SSO_ERR_RATE_LIMIT);

	rate_limiter_destroy(rl);
	return 0;
}

static const char* test_ratelimit_reset() {
	printf("  Running test_ratelimit_reset...\n");
	rate_limiter_t* rl;
	rate_limiter_create(&rl, 100);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "127.0.0.1", 500, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "127.0.0.1", 500, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "127.0.0.1", 500, 2), SSO_ERR_RATE_LIMIT);

	rate_limiter_reset(rl, "127.0.0.1");
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "127.0.0.1", 500, 2), SSO_OK);

	rate_limiter_destroy(rl);
	return 0;
}

static const char* test_ratelimit_multi_ip() {
	printf("  Running test_ratelimit_multi_ip...\n");
	rate_limiter_t* rl;
	rate_limiter_create(&rl, 100);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.1", 60000, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.1", 60000, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.1", 60000, 2), SSO_ERR_RATE_LIMIT);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.2", 60000, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.2", 60000, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.2", 60000, 2), SSO_ERR_RATE_LIMIT);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.3", 60000, 2), SSO_OK);

	rate_limiter_destroy(rl);
	return 0;
}

static const char* test_ratelimit_window_expiry() {
	printf("  Running test_ratelimit_window_expiry...\n");
	rate_limiter_t* rl;
	rate_limiter_create(&rl, 100);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.1", 100, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.1", 100, 2), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.1", 100, 2), SSO_ERR_RATE_LIMIT);

	usleep(150000);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "10.0.0.1", 100, 2), SSO_OK);

	rate_limiter_destroy(rl);
	return 0;
}

static const char* test_ratelimit_lru_eviction() {
	printf("  Running test_ratelimit_lru_eviction...\n");
	rate_limiter_t* rl;
	sso_error_t		err = rate_limiter_create(&rl, 3);
	ASSERT_INT_EQUAL(err, SSO_OK);

	uint64_t window = 60000;
	int		 max	= 5;

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.1", window, max), SSO_OK);
	usleep(1000);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.2", window, max), SSO_OK);
	usleep(1000);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.3", window, max), SSO_OK);

	usleep(1000);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.1", window, max), SSO_OK);
	usleep(1000);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.2", window, max), SSO_OK);

	usleep(1000);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.4", window, max), SSO_OK);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.1", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.1", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.1", window, max), SSO_OK);
	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.1", window, max), SSO_ERR_RATE_LIMIT);

	ASSERT_INT_EQUAL(rate_limiter_check(rl, "192.168.1.3", window, max), SSO_OK);

	rate_limiter_destroy(rl);
	return 0;
}

static const char* all_tests() {
	mu_run_test(test_ratelimit_basic);
	mu_run_test(test_ratelimit_reset);
	mu_run_test(test_ratelimit_multi_ip);
	mu_run_test(test_ratelimit_window_expiry);
	mu_run_test(test_ratelimit_lru_eviction);
	return 0;
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;
	const char* result = all_tests();
	if (result != 0)
		printf("FAILED\n");
	else
		printf("ALL TESTS PASSED\n");
	printf("Tests run: %d\n", tests_run);
	return result != 0;
}
