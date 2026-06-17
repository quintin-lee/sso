# Stage 1: Build Vue app
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# Stage 2: Compile C backend
FROM alpine:3.18 AS backend-builder
RUN apk add --no-cache \
    gcc \
    musl-dev \
    make \
    sqlite-dev \
    libsodium-dev \
    openssl-dev \
    curl-dev \
    libmicrohttpd-dev \
    postgresql-dev \
    pkgconfig

WORKDIR /app
COPY . .
RUN make clean && make

# Stage 3: Final image
FROM alpine:3.18
RUN apk add --no-cache \
    nginx \
    sqlite-libs \
    libsodium \
    openssl \
    libcurl \
    libmicrohttpd \
    libpq \
    supervisor

# Copy Nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy frontend assets
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# Copy backend binary
COPY --from=backend-builder /app/sso_system /usr/local/bin/sso_system

# Copy supervisor config
RUN mkdir -p /etc/supervisor.d/
COPY sso.ini /etc/supervisor.d/sso.ini

# Setup directories and permissions
RUN mkdir -p /app/data && chown -R nobody:nobody /app /var/lib/nginx /var/log/nginx /run/nginx

# Expose HTTP port (Nginx)
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1/api/v1/health || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
