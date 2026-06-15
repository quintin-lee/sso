FROM alpine:3.18 AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    sqlite-dev \
    libsodium-dev \
    openssl-dev \
    curl-dev \
    libmicrohttpd-dev

WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN make clean && make

# ---------------------------------------------------------
# Production image
FROM alpine:3.18

# Install runtime dependencies only
RUN apk add --no-cache \
    sqlite-libs \
    libsodium \
    openssl \
    libcurl \
    libmicrohttpd

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/sso_system /usr/local/bin/sso_system

# Create directory for SQLite database
RUN mkdir -p /app/data && chown -R nobody:nobody /app

# Switch to non-root user for security
USER nobody

# Expose the API port
EXPOSE 8080

# Health check — verifies the HTTP API is responding
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/health || exit 1

# Configure volumes for persistent data
VOLUME /app/data

# Run the system in server mode on port 8080
CMD ["sso_system", "--server"]