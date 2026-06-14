#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>

#include "ratelimit.h"
#include "sso.h"

static void test_ratelimit_basic(void **state) {
    (void)state;
    rate_limiter_t *rl;
    sso_error_t err = rate_limiter_create(&rl, 100);
    assert_int_equal(err, SSO_OK);

    /* Allow first few requests */
    assert_true(rate_limiter_check(rl, "1.2.3.4", 5, 60));
    assert_true(rate_limiter_check(rl, "1.2.3.4", 5, 60));
    assert_true(rate_limiter_check(rl, "1.2.3.4", 5, 60));
    assert_true(rate_limiter_check(rl, "1.2.3.4", 5, 60));
    assert_true(rate_limiter_check(rl, "1.2.3.4", 5, 60));

    /* 6th request should be denied */
    assert_false(rate_limiter_check(rl, "1.2.3.4", 5, 60));

    /* Different IP should be allowed */
    assert_true(rate_limiter_check(rl, "1.2.3.5", 5, 60));

    rate_limiter_destroy(rl);
}

static void test_ratelimit_window_reset(void **state) {
    (void)state;
    rate_limiter_t *rl;
    rate_limiter_create(&rl, 100);

    /* Limit to 2 requests per 1 second */
    assert_true(rate_limiter_check(rl, "127.0.0.1", 2, 1));
    assert_true(rate_limiter_check(rl, "127.0.0.1", 2, 1));
    assert_false(rate_limiter_check(rl, "127.0.0.1", 2, 1));

    /* Wait for window to expire */
    sleep(2);

    /* Should be allowed again */
    assert_true(rate_limiter_check(rl, "127.0.0.1", 2, 1));

    rate_limiter_destroy(rl);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ratelimit_basic),
        cmocka_unit_test(test_ratelimit_window_reset),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
