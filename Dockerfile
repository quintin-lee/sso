# Dockerfile — Multi-stage production image for the SSO System.
#
# Stage 1 (frontend-builder): Build the Vue.js admin SPA.
# Stage 2 (backend-builder):   Cross-compile the C11 SSO daemon.
# Stage 3 (runtime):          Minimal Alpine image with the binary + assets.

ARG DOCKER_REGISTRY=""

# Stage 1: Build Vue app
FROM ${DOCKER_REGISTRY}node:20-alpine AS frontend-builder
ARG USE_CHINA_MIRROR=0
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN if [ "$USE_CHINA_MIRROR" = "1" ]; then npm config set registry https://registry.npmmirror.com/; fi && npm install
COPY frontend/ .
RUN npm run build

# Stage 2: Compile C backend
FROM ${DOCKER_REGISTRY}alpine:3.18 AS backend-builder
ARG USE_CHINA_MIRROR=0
RUN if [ "$USE_CHINA_MIRROR" = "1" ]; then sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories; fi && \
    apk add --no-cache \
    gcc \
    musl-dev \
    make \
    sqlite-dev \
    libsodium-dev \
    openssl-dev \
    curl-dev \
    libmicrohttpd-dev \
    postgresql-dev \
    hiredis-dev \
    pkgconfig

WORKDIR /app
COPY . .
RUN make clean && make

# Stage 3: Final image
FROM ${DOCKER_REGISTRY}alpine:3.18
ARG USE_CHINA_MIRROR=0
RUN if [ "$USE_CHINA_MIRROR" = "1" ]; then sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories; fi && \
    apk add --no-cache \
    nginx \
    sqlite-libs \
    libsodium \
    openssl \
    libcurl \
    libmicrohttpd \
    libpq \
    hiredis \
    supervisor

# Copy Nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy frontend assets
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# Copy backend binary, config, and SQL files
COPY --from=backend-builder /app/sso_system /usr/local/bin/sso_system
COPY --from=backend-builder /app/sso.toml /app/sso.toml
COPY --from=backend-builder /app/sql /app/sql

# Copy supervisor configs
RUN mkdir -p /etc/supervisor.d/ /var/log/supervisor
COPY supervisord.conf /etc/supervisord.conf
COPY sso.ini /etc/supervisor.d/sso.ini

# Setup directories and permissions
RUN mkdir -p /app/data && chown -R nobody:nobody /app /var/lib/nginx /var/log/nginx /run/nginx

# Expose HTTP port (Nginx)
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://127.0.0.1/api/v1/health || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
