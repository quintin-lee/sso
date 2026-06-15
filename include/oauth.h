#ifndef SSO_OAUTH_H
#define SSO_OAUTH_H

#include "sso.h"
#include "server.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* All OAuth 2.0 / OIDC endpoint handlers.
 * These follow the route_handler_fn signature from server.h.
 * The sso_context_t->config must be castable to sso_config_t*. */

sso_error_t handle_oauth_authorize(sso_context_t *ctx,
                                   const http_request_t *req,
                                   http_response_t *resp);

sso_error_t handle_oauth_token(sso_context_t *ctx,
                               const http_request_t *req,
                               http_response_t *resp);

sso_error_t handle_oauth_introspect(sso_context_t *ctx,
                                    const http_request_t *req,
                                    http_response_t *resp);

sso_error_t handle_oauth_revoke(sso_context_t *ctx,
                                const http_request_t *req,
                                http_response_t *resp);

sso_error_t handle_well_known_openid_config(sso_context_t *ctx,
                                            const http_request_t *req,
                                            http_response_t *resp);

sso_error_t handle_jwks(sso_context_t *ctx,
                        const http_request_t *req,
                        http_response_t *resp);

sso_error_t handle_userinfo(sso_context_t *ctx,
                            const http_request_t *req,
                            http_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif /* SSO_OAUTH_H */