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
#
# Install deps on Debian/Ubuntu:
#   sudo apt-get install libsqlite3-dev libssl-dev

CC       = gcc
CFLAGS   = -Wall -Wextra -Wpedantic -std=c11 -O2 -D_GNU_SOURCE -D_POSIX_C_SOURCE=199309L
LDFLAGS  = -lsqlite3 -lssl -lcrypto
INCLUDES = -Iinclude

SRCDIR   = src
STRATEGIES = strategies
BUILDDIR = build

# Sources
SRCS = $(SRCDIR)/sso.c           \
       $(SRCDIR)/permission.c    \
       $(SRCDIR)/user.c          \
       $(SRCDIR)/role.c          \
       $(SRCDIR)/group.c         \
       $(SRCDIR)/policy.c        \
       $(SRCDIR)/token.c         \
       $(SRCDIR)/storage_sqlite.c \
       $(SRCDIR)/server.c        \
       $(SRCDIR)/main.c

STRAT_SRCS = $(STRATEGIES)/func_perm.c \
             $(STRATEGIES)/api_perm.c  \
             $(STRATEGIES)/data_perm.c

ALL_SRCS = $(SRCS) $(STRAT_SRCS)
OBJS     = $(ALL_SRCS:%=$(BUILDDIR)/%.o)
TARGET   = sso_system

# Debug target
DEBUG_CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -g -O0 -DDEBUG

.PHONY: all clean run server debug dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p $(BUILDDIR)/$(SRCDIR)
	@mkdir -p $(BUILDDIR)/$(STRATEGIES)

# Compile rule: every .c file gets a .o in build/
$(BUILDDIR)/%.c.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo "Build complete: $(TARGET)"

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: all

run: all
	./$(TARGET)

server: all
	./$(TARGET) --server

clean:
	rm -rf $(BUILDDIR) $(TARGET) *.db

# Show program size
size: $(TARGET)
	@size $(TARGET)

# Dependency generation (requires gcc)
depend:
	$(CC) $(INCLUDES) -MM $(ALL_SRCS) > .depend

-include .depend
