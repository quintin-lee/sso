# Makefile — SSO System
#
# Build:
#   make              — build the SSO system (release)
#   make debug        — build with debug symbols
#   make clean        — remove build artifacts
#   make run          — build and run the demo
#   make server       — build and run the HTTP server
#
# Dependencies:
#   - SQLite3 (libsqlite3-dev)
#   - OpenSSL (libssl-dev) — for SHA-256 and HMAC
#   - libsodium — for argon2id password hashing
#
# Install deps on Debian/Ubuntu:
#   sudo apt-get install libsqlite3-dev libssl-dev

CC       = gcc
CFLAGS   = -Wall -Wextra -Wpedantic -std=c11 -O2 -D_GNU_SOURCE -D_POSIX_C_SOURCE=199309L -Wno-overlength-strings -MD -MP $(MHD_CFLAGS) $(shell pkg-config --cflags libpq 2>/dev/null)
LDFLAGS  = -lsodium -lsqlite3 -lssl -lcrypto -lcurl $(MHD_LIBS) $(shell pkg-config --libs libpq 2>/dev/null)
INCLUDES = -Iinclude

SRCDIR   = src
STRATEGIES = strategies
TESTDIR  = tests
BUILDDIR = build

# Common sources (always compiled)
SRCS_BASE = $(SRCDIR)/logger.c        \
       $(SRCDIR)/sso.c           \
       $(SRCDIR)/permission.c    \
       $(SRCDIR)/user.c          \
       $(SRCDIR)/role.c          \
       $(SRCDIR)/group.c         \
       $(SRCDIR)/policy.c        \
       $(SRCDIR)/token.c         \
       $(SRCDIR)/storage_sqlite.c \
       $(SRCDIR)/storage_memory.c \
       $(SRCDIR)/storage_postgres.c \
       $(SRCDIR)/ratelimit.c     \
       $(SRCDIR)/cJSON.c         \
       $(SRCDIR)/toml.c          \
       $(SRCDIR)/config.c        \
       $(SRCDIR)/oauth.c         \
       $(SRCDIR)/mfa.c           \
       $(SRCDIR)/handlers_common.c \
       $(SRCDIR)/handlers_pages.c \
       $(SRCDIR)/handlers_auth.c \
       $(SRCDIR)/handlers_admin.c \
       $(SRCDIR)/handlers_check.c \
       $(SRCDIR)/demo.c          \
       $(SRCDIR)/interactive.c   \
       $(SRCDIR)/main.c

# Detect libmicrohttpd availability (prefer pkg-config, fallback to header check)
MHD_AVAIL := $(shell pkg-config --exists libmicrohttpd 2>/dev/null && echo yes)
ifneq ($(MHD_AVAIL),yes)
    MHD_AVAIL := $(shell test -f /usr/include/microhttpd.h && echo yes)
endif

ifeq ($(MHD_AVAIL),yes)
    MHD_LIBS   := $(shell pkg-config --libs libmicrohttpd 2>/dev/null || echo "-lmicrohttpd")
    MHD_CFLAGS := -DUSE_LIBMICROHTTPD
    SRCS       = $(SRCS_BASE) $(SRCDIR)/server_mhd.c
else
    MHD_LIBS   :=
    MHD_CFLAGS :=
    SRCS       = $(SRCS_BASE) $(SRCDIR)/server.c
endif

# Tests
TEST_SRCS = $(wildcard $(TESTDIR)/test_*.c)
TEST_BINS = $(TEST_SRCS:$(TESTDIR)/%.c=$(BUILDDIR)/$(TESTDIR)/%)

STRAT_SRCS = $(STRATEGIES)/func_perm.c \
             $(STRATEGIES)/api_perm.c  \
             $(STRATEGIES)/data_perm.c \
             $(STRATEGIES)/rbac_perm.c \
             $(STRATEGIES)/lbac_perm.c \
             $(STRATEGIES)/loc_perm.c \
             $(STRATEGIES)/abac_perm.c

ALL_SRCS = $(SRCS) $(STRAT_SRCS)
OBJS     = $(ALL_SRCS:%=$(BUILDDIR)/%.o)
TARGET   = sso_system

# Debug target
DEBUG_CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -g -O0 -DDEBUG -Wno-overlength-strings -MD -MP $(MHD_CFLAGS)

# ASan target
ASAN_CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -g -O1 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -D_GNU_SOURCE -D_POSIX_C_SOURCE=199309L -Wno-overlength-strings -MD -MP $(MHD_CFLAGS)
ASAN_LDFLAGS = -fsanitize=address -fsanitize=undefined -lsodium -lsqlite3 -lssl -lcrypto -lcurl $(MHD_LIBS)

.PHONY: all clean run server debug dirs test integration-test asan check size

all: dirs $(TARGET)

dirs:
	@mkdir -p $(BUILDDIR)/$(SRCDIR)
	@mkdir -p $(BUILDDIR)/$(STRATEGIES)
	@mkdir -p $(BUILDDIR)/$(TESTDIR)

# Compile rule: every .c file gets a .o in build/
$(BUILDDIR)/%.c.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo "Build complete: $(TARGET)"

# Test compilation rule (minimal unit mode)
$(BUILDDIR)/$(TESTDIR)/test_%: $(TESTDIR)/test_%.c $(filter-out $(BUILDDIR)/$(SRCDIR)/main.c.o, $(OBJS))
	$(CC) $(CFLAGS) $(INCLUDES) $< $(filter-out $(BUILDDIR)/$(SRCDIR)/main.c.o, $(OBJS)) $(LDFLAGS) -o $@

test: dirs $(TEST_BINS)
	@echo "Running minimal unit tests..."
	@for bin in $(TEST_BINS); do ./$$bin || exit 1; done

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: all

run: all
	./$(TARGET)

server: all
	./$(TARGET) --server

clean:
	rm -rf $(BUILDDIR) $(TARGET) *.db
	find . -name '*.d' -delete 2>/dev/null || true

integration-test: all
	@echo "Running HTTP API integration tests..."
	@SSO_TEST_PORT=18080 tests/test_integration.sh

# Run everything: demo + unit tests + integration tests
check: all $(TEST_BINS)
	@echo "=== Smoke test (demo) ===" && ./$(TARGET) < /dev/null 2>&1 | grep -E '^=== Demo complete' || (echo "FAIL: demo" && false)
	@echo "=== Unit tests ===" && for bin in $(TEST_BINS); do echo "  $$bin" && ./$$bin || exit 1; done
	@echo "=== Integration tests ===" && $(MAKE) integration-test

# ASan build (AddressSanitizer + UndefinedBehaviorSanitizer)
asan: CFLAGS = $(ASAN_CFLAGS)
asan: LDFLAGS = $(ASAN_LDFLAGS)
asan: clean all test

# Show program size
size: $(TARGET)
	@size $(TARGET)

# Auto-dependency files (generated by -MD -MP)
DEPS = $(OBJS:.o=.d)

-include $(DEPS)
