/*
 * server.c — Simple embedded HTTP server for the SSO management API.
 *
 * Uses POSIX sockets (no external dependency).  Handles one connection
 * at a time (accept → parse → dispatch → respond → close).
 * In production, use libmicrohttpd or nginx as a reverse proxy.
 *
 * Route dispatching:
 *   The server matches incoming requests against registered routes.
 *   Route patterns support :param segments for path parameters.
 */

#include "sso.h"
#include "server.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "permission.h"
#include "token.h"
#include "storage.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>

/* Global so signal handler can stop the server */
static sso_server_t *g_server = NULL;

/* ========================================================================
 * Thread Pool for HTTP Server
 * ======================================================================== */
#define THREAD_POOL_SIZE 8
#define QUEUE_SIZE 1024

typedef struct {
    int  client_fd;
    char client_ip[64];
} task_t;

typedef struct {
    pthread_t threads[THREAD_POOL_SIZE];
    task_t queue[QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t notify;
    bool stop;
    sso_server_t *server;
} thread_pool_t;

static thread_pool_t g_pool;

static void handle_client(sso_server_t *server, int client_fd, const char *client_ip);

static void *worker_thread(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&g_pool.lock);
        while (g_pool.count == 0 && !g_pool.stop) {
            pthread_cond_wait(&g_pool.notify, &g_pool.lock);
        }
        if (g_pool.stop && g_pool.count == 0) {
            pthread_mutex_unlock(&g_pool.lock);
            break;
        }

        task_t task = g_pool.queue[g_pool.head];
        g_pool.head = (g_pool.head + 1) % QUEUE_SIZE;
        g_pool.count--;
        pthread_mutex_unlock(&g_pool.lock);

        /* Handle connection */
        handle_client(g_pool.server, task.client_fd, task.client_ip);
    }
    return NULL;
}

static void pool_init(sso_server_t *server) {
    g_pool.head = 0;
    g_pool.tail = 0;
    g_pool.count = 0;
    g_pool.stop = false;
    g_pool.server = server;
    pthread_mutex_init(&g_pool.lock, NULL);
    pthread_cond_init(&g_pool.notify, NULL);

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_create(&g_pool.threads[i], NULL, worker_thread, NULL);
    }
}

static void pool_submit(int client_fd, const char *client_ip) {
    pthread_mutex_lock(&g_pool.lock);
    if (g_pool.count < QUEUE_SIZE) {
        g_pool.queue[g_pool.tail].client_fd = client_fd;
        snprintf(g_pool.queue[g_pool.tail].client_ip, 
                 sizeof(g_pool.queue[g_pool.tail].client_ip), "%s", client_ip);
        g_pool.tail = (g_pool.tail + 1) % QUEUE_SIZE;
        g_pool.count++;
        pthread_cond_signal(&g_pool.notify);
    } else {
        /* Queue full, drop connection */
        close(client_fd);
    }
    pthread_mutex_unlock(&g_pool.lock);
}

static void pool_shutdown() {
    pthread_mutex_lock(&g_pool.lock);
    g_pool.stop = true;
    pthread_cond_broadcast(&g_pool.notify);
    pthread_mutex_unlock(&g_pool.lock);

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(g_pool.threads[i], NULL);
    }

    pthread_mutex_destroy(&g_pool.lock);
    pthread_cond_destroy(&g_pool.notify);
}

/* ========================================================================
 * Internal: HTTP request parser (minimal)
 * ======================================================================== */

/* Read a line from a socket (up to newline or max). */
static ssize_t read_line(int fd, char *buf, size_t max) {
    size_t i = 0;
    while (i < max - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) break;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (ssize_t)i;
}

static int parse_request(int client_fd, http_request_t *req) {
    memset(req, 0, sizeof(*req));

    char line[4096];
    if (read_line(client_fd, line, sizeof(line)) <= 0) return -1;

    /* Parse: METHOD /path HTTP/1.1 */
    char method[16], path[SSO_MAX_PATH], version[16];
    if (sscanf(line, "%15s %255s %15s", method, path, version) < 2) return -1;

    /* Convert method string to enum */
    if (strcmp(method, "GET") == 0)        req->method = HTTP_GET;
    else if (strcmp(method, "POST") == 0)  req->method = HTTP_POST;
    else if (strcmp(method, "PUT") == 0)   req->method = HTTP_PUT;
    else if (strcmp(method, "DELETE") == 0) req->method = HTTP_DELETE;
    else if (strcmp(method, "PATCH") == 0) req->method = HTTP_PATCH;
    else return -1;

    memcpy(req->path, path, SSO_MAX_PATH - 1);
    req->path[SSO_MAX_PATH - 1] = '\0';

    /* Parse headers — look for Content-Length and Authorization */
    int content_length = 0;
    while (1) {
        if (read_line(client_fd, line, sizeof(line)) <= 0) break;
        if (line[0] == '\0') break; /* end of headers */

        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            content_length = atoi(line + 15);
        }
        if (strncasecmp(line, "Authorization:", 14) == 0) {
            const char *token = line + 14;
            while (*token == ' ') token++;
            if (strncasecmp(token, "Bearer ", 7) == 0) {
                strncpy(req->auth_token, token + 7, SSO_MAX_TOKEN_STR - 1);
            }
        }
    }

    /* Read body if present */
    if (content_length > 0 && content_length < 65536) {
        req->body = (char *)malloc((size_t)content_length + 1);
        if (req->body) {
            size_t total = 0;
            while (total < (size_t)content_length) {
                ssize_t n = read(client_fd, req->body + total,
                                 (size_t)(content_length - total));
                if (n <= 0) break;
                total += (size_t)n;
            }
            req->body[total] = '\0';
            req->body_len = total;
        }
    }

    return 0;
}

/* ========================================================================
 * Response helpers
 * ======================================================================== */
void sso_response_ok(http_response_t *resp, const char *body_json) {
    resp->status_code = 200;
    resp->body = strdup(body_json);
    resp->body_len = strlen(body_json);
    strcpy(resp->content_type, "application/json");
}

void sso_response_error(http_response_t *resp, int status_code, const char *message) {
    resp->status_code = status_code;
    char buf[1024];
    snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", message);
    resp->body = strdup(buf);
    resp->body_len = strlen(buf);
    strcpy(resp->content_type, "application/json");
}

/* Send the HTTP response over the socket. */
static void send_response(int fd, const http_response_t *resp) {
    char header[4096];
    int n = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "Pragma: no-cache\r\n"
        "\r\n",
        resp->status_code,
        resp->status_code == 200 ? "OK" :
        resp->status_code == 201 ? "Created" :
        resp->status_code == 400 ? "Bad Request" :
        resp->status_code == 401 ? "Unauthorized" :
        resp->status_code == 403 ? "Forbidden" :
        resp->status_code == 404 ? "Not Found" : "Internal Server Error",
        resp->content_type,
        resp->body_len);

    write(fd, header, (size_t)n);
    if (resp->body && resp->body_len > 0) {
        write(fd, resp->body, resp->body_len);
    }
}

/* ========================================================================
 * Route matching
 * ======================================================================== */

/* Match a path pattern against a request path.  Supports :param segments.
 * Returns true if matched.  Extracts path params into query_params. */
static bool match_route(const char *pattern, const char *path, char **params) {
    if (!pattern || !path) return false;

    while (*pattern && *path) {
        if (*pattern == ':') {
            /* Skip pattern segment name */
            pattern++;
            while (*pattern && *pattern != '/') pattern++;
            /* Match corresponding path segment */
            while (*path && *path != '/') path++;
            if (params) {
                /* In production, store key=value */
            }
        } else if (*pattern == '*') {
            return true; /* wildcard */
        } else {
            if (*pattern != *path) return false;
            pattern++;
            path++;
        }
    }

    /* Allow trailing slash differences */
    if (*pattern == '/' && *path == '\0') pattern++;
    if (*path == '/' && *pattern == '\0') path++;

    return *pattern == '\0' && *path == '\0';
}

/* ========================================================================
 * Auth middleware
 * ======================================================================== */
static sso_error_t authenticate_request(sso_server_t *server, const http_request_t *req,
                                        user_t *user, token_t *tok) {
    if (!server || !req || !user || !tok) return SSO_ERR_INVALID_PARAM;

    if (req->auth_token[0] == '\0') return SSO_ERR_AUTH_FAILED;

    token_manager_t *tmgr = (token_manager_t *)server->sso_ctx->token_mgr;
    sso_error_t err = token_verify(tmgr, req->auth_token, tok);
    if (err != SSO_OK) return err;

    if (token_is_revoked(tmgr, tok->jti)) return SSO_ERR_TOKEN_INVALID;

    /* Load user */
    user_manager_t *umgr = (user_manager_t *)server->sso_ctx->user_mgr;
    return user_get_by_id(umgr, tok->user_id, user);
}

/* ========================================================================
 * Handle a single client connection
 * ======================================================================== */
static void handle_client(sso_server_t *server, int client_fd, const char *client_ip) {
    http_request_t req;
    http_response_t resp;

    if (parse_request(client_fd, &req) != 0) {
        close(client_fd);
        return;
    }
    strncpy(req.client_ip, client_ip, sizeof(req.client_ip) - 1);
    req.client_ip[sizeof(req.client_ip) - 1] = '\0';

    memset(&resp, 0, sizeof(resp));
    resp.body = NULL;
    resp.body_len = 0;
    strcpy(resp.content_type, "application/json");

    /* Find matching route */
    route_t *matched = NULL;
    for (size_t i = 0; i < server->route_count; i++) {
        if (server->routes[i].method == req.method &&
            match_route(server->routes[i].path_pattern, req.path, NULL)) {
            matched = &server->routes[i];
            break;
        }
    }

    if (!matched) {
        sso_response_error(&resp, 404, "Not found");
        send_response(client_fd, &resp);
        free(resp.body);
        free(req.body);
        close(client_fd);
        return;
    }

    /* Auth check — populate req->userdata with auth_context_t */
    req.userdata = NULL;
    if (matched->require_auth) {
        auth_context_t *auth = (auth_context_t *)malloc(sizeof(auth_context_t));
        if (!auth) {
            sso_response_error(&resp, 500, "Internal server error");
            send_response(client_fd, &resp);
            free(resp.body);
            free(req.body);
            close(client_fd);
            return;
        }
        sso_error_t aerr = authenticate_request(server, &req, &auth->user, &auth->token);
        if (aerr != SSO_OK) {
            const char *msg = "Authentication failed";
            if (aerr == SSO_ERR_TOKEN_EXPIRED) msg = "Token expired";
            sso_response_error(&resp, 401, msg);
            free(auth);
            send_response(client_fd, &resp);
            free(resp.body);
            free(req.body);
            close(client_fd);
            return;
        }
        req.userdata = auth;
    }

    /* Dispatch to handler */
    sso_error_t err = matched->handler(server->sso_ctx, &req, &resp);

    /* Free auth context if allocated */
    if (req.userdata) {
        free(req.userdata);
        req.userdata = NULL;
    }
    if (err != SSO_OK && resp.body == NULL) {
        sso_response_error(&resp, 500, sso_strerror(err));
    }

    send_response(client_fd, &resp);
    free(resp.body);
    free(req.body);
    close(client_fd);
}

/* ========================================================================
 * Signal handler for graceful shutdown
 * ======================================================================== */
static void sigint_handler(int sig) {
    (void)sig;
    if (g_server) {
        sso_server_stop(g_server);
    }
}

/* ========================================================================
 * Server lifecycle
 * ======================================================================== */
sso_error_t sso_server_init(sso_server_t *server, sso_context_t *ctx,
                            const char *host, int port,
                            const route_t *routes, size_t route_count) {
    if (!server || !ctx) return SSO_ERR_INVALID_PARAM;

    memset(server, 0, sizeof(*server));
    server->sso_ctx = ctx;
    strncpy(server->host, host ? host : "0.0.0.0", sizeof(server->host) - 1);
    server->port = port;
    server->routes = (route_t *)routes;
    server->route_count = route_count;
    server->server_data = NULL;

    return SSO_OK;
}

void sso_server_stop(sso_server_t *server) {
    if (!server) return;
    /* Signal the accept loop to stop — platform-specific */
    int *sock = (int *)&server->server_data;
    if (*sock > 0) {
        shutdown(*sock, SHUT_RDWR);
        close(*sock);
        *sock = 0;
    }
}

sso_error_t sso_server_start(sso_server_t *server) {
    if (!server) return SSO_ERR_INVALID_PARAM;

    g_server = server;
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return SSO_ERR_GENERAL; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)server->port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return SSO_ERR_GENERAL;
    }

    if (listen(server_fd, 128) < 0) {
        perror("listen");
        close(server_fd);
        return SSO_ERR_GENERAL;
    }

    server->server_data = (void *)(intptr_t)server_fd;
    printf("SSO management API listening on http://%s:%d\n",
           server->host, server->port);
           
    pool_init(server);

    /* Main accept loop */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd,
                               (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EBADF || errno == EINVAL) {
                /* Signal caught or socket closed — check if we should stop */
                int *sock = (int *)&server->server_data;
                if (*sock == 0) break;
                continue;
            }
            break;
        }

        /* Get client IP */
        char client_ip[64] = "unknown";
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        /* Submit connection to thread pool */
        pool_submit(client_fd, client_ip);
    }

    pool_shutdown();
    close(server_fd);
    server->server_data = NULL;
    printf("SSO management API stopped.\n");
    return SSO_OK;
}
