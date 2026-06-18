# Stage 1: Build Vue app
FROM docker.1ms.run/library/node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm config set registry https://registry.npmmirror.com/ && npm install
COPY frontend/ .
RUN npm run build

# Stage 2: Compile C backend
FROM docker.1ms.run/library/alpine:3.18 AS backend-builder
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
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
    pkgconfig

WORKDIR /app
COPY . .
RUN make clean && make

# Stage 3: Final image
FROM docker.1ms.run/library/alpine:3.18
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
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

# Copy backend binary and config
COPY --from=backend-builder /app/sso_system /usr/local/bin/sso_system
COPY --from=backend-builder /app/sso.toml /app/sso.toml

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
