FROM alpine:3.18 AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    sqlite-dev \
    libsodium-dev \
    openssl-dev \
    curl-dev

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
    libcurl

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/sso_system /usr/local/bin/sso_system

# Create directory for SQLite database
RUN mkdir -p /app/data && chown -R nobody:nobody /app

# Switch to non-root user for security
USER nobody

# Expose the API port
EXPOSE 8080

# Configure volumes for persistent data
VOLUME /app/data

# Run the system, passing a specific database file path via env var (if your app supports it, 
# otherwise it creates sso_demo.db in the CWD, which is /app)
CMD ["sso_system"]