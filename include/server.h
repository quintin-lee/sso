/*
 * server.h — Embedded HTTP management server.
 *
 * Exposes a RESTful API for the SSO management platform.
 * Routes are registered at init time and map URL paths → handlers.
 *
 * Authentication:
 *   All management endpoints (except /api/v1/auth/login) require a valid
 *   Bearer token in the Authorization header.  The server middleware
 *   extracts and validates the token before routing to the handler.
 *
 * API conventions:
 *   POST   /api/v1/auth/login          — authenticate & receive token
 *   POST   /api/v1/auth/logout         — revoke token
 *
 *   CRUD   /api/v1/users               — user management
 *   CRUD   /api/v1/roles               — role management
 *   CRUD   /api/v1/groups              — group management
 *   CRUD   /api/v1/policies            — policy configuration
 *
 *   POST   /api/v1/roles/:id/assign    — assign role to user/group
 *   POST   /api/v1/groups/:id/members  — add user to group
 *   POST   /api/v1/policies/:id/attach — attach policy to target
 *
 *   POST   /api/v1/check/functional    — check functional permission
 *   POST   /api/v1/check/api           — check API permission
 *   POST   /api/v1/check/data          — check data permission
 */

#ifndef SSO_SERVER_H
#define SSO_SERVER_H

#include "sso.h"
#include "user.h"
#include "token.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Auth context — passed to handlers via req->userdata after authentication
 * ======================================================================== */
typedef struct {
    user_t        user;          /* authenticated user              */
    token_t       token;         /* decoded token                   */
} auth_context_t;

/* ========================================================================
 * HTTP method
 * ======================================================================== */
typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_PATCH,
} http_method_t;

/* ========================================================================
 * HTTP request / response (minimal)
 * ======================================================================== */
typedef struct {
    http_method_t    method;
    char             path[SSO_MAX_PATH];
    char             client_ip[64];     /* requester IP address */
    char             *body;
    size_t           body_len;
    char             **query_params;    /* "key=value" strings, NULL-terminated */
    char             auth_token[SSO_MAX_TOKEN_STR];
    void             *userdata;         /* connection-specific data */
} http_request_t;

typedef struct {
    int              status_code;       /* 200, 201, 400, 401, 403, 404, 500 … */
    char             *body;             /* response body (JSON)                 */
    size_t           body_len;
    char             content_type[64];  /* e.g. "application/json"              */
} http_response_t;

/* ========================================================================
 * Request handler — each route registers one of these.
 * ======================================================================== */
typedef sso_error_t (*route_handler_fn)(sso_context_t *ctx,
                                        const http_request_t *req,
                                        http_response_t *resp);

/* ========================================================================
 * Route registration
 * ======================================================================== */
typedef struct {
    const char      *path_pattern;      /* e.g. "/api/v1/users/:id"            */
    http_method_t    method;
    route_handler_fn handler;
    bool             require_auth;      /* if true, middleware checks token    */
} route_t;

/* ========================================================================
 * Server
 * ======================================================================== */
struct sso_server {
    char             host[64];
    int              port;
    route_t         *routes;
    size_t           route_count;
    sso_context_t   *sso_ctx;
    void            *server_data;       /* platform-specific (socket, ctx)     */
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/* Create and configure the server.  routes must remain valid for the
 * server's lifetime. */
sso_error_t sso_server_init(sso_server_t *server, sso_context_t *ctx,
                            const char *host, int port,
                            const route_t *routes, size_t route_count);

/* Start the server (blocking).  Returns on SIGINT / error. */
sso_error_t sso_server_start(sso_server_t *server);

/* Signal the server to stop (called from signal handler). */
void        sso_server_stop(sso_server_t *server);

/* -----------------------------------------------------------------------
 * Route matching (exposed for testing)
 * ----------------------------------------------------------------------- */
bool match_route(const char *pattern, const char *path, char **params);

/* -----------------------------------------------------------------------
 * Response helpers
 * ----------------------------------------------------------------------- */

/* Fill a JSON 200 response.  body_json must be a valid JSON string. */
void sso_response_ok(http_response_t *resp, const char *body_json);

/* Fill a JSON error response with the given status code and message. */
void sso_response_error(http_response_t *resp, int status_code, const char *message);

#ifdef __cplusplus
}
#endif

#endif /* SSO_SERVER_H */
