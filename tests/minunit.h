#ifndef MINUNIT_H
#define MINUNIT_H

#include <stdio.h>

#define mu_assert(message, test) do { if (!(test)) { printf("    [FAIL] %s\n", message); return message; } } while (0)
#define mu_run_test(test) do { const char *message = test(); tests_run++; \
                               if (message) return message; } while (0)

extern int tests_run;

#define ASSERT_INT_EQUAL(a, b) do { if ((a) != (b)) { printf("    [FAIL] %d != %d\n", (int)(a), (int)(b)); return "fail"; } } while(0)
#define ASSERT_STR_EQUAL(a, b) do { if (strcmp((a), (b)) != 0) { printf("    [FAIL] \"%s\" != \"%s\"\n", (a), (b)); return "fail"; } } while(0)
#define ASSERT_TRUE(a) do { if (!(a)) { printf("    [FAIL] expected true\n"); return "fail"; } } while(0)
#define ASSERT_NOT_NULL(a) do { if ((a) == NULL) { printf("    [FAIL] expected not null\n"); return "fail"; } } while(0)

#endif
