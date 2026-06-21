/*
 * oauth.h — OAuth 2.0 / OpenID Connect (OIDC) endpoint handlers.
 *
 * Implements the OAuth 2.0 authorization code flow with PKCE (S256 + plain),
 * token introspection (RFC 7662), token revocation (RFC 7009), OIDC discovery,
 * JWKS key distribution (RFC 7517), and /userinfo.
 *
 * All handlers follow the route_handler_fn signature from server.h and
 * are registered in main.c's routes[] array.
 */

#ifndef SSO_OAUTH_H
#define SSO_OAUTH_H

#include "sso.h"
#include "server.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default TTL for refresh tokens: 30 days in milliseconds. */
#define SSO_REFRESH_TOKEN_TTL 2592000000LL

/**
 * @brief OAuth Authorization endpoint (RFC 6749 §4.1.1).
 *
 * Expects query params: response_type=code, client_id, redirect_uri, scope.
 * Returns HTTP 302 with ?code=<auth_code> in the redirect Location header.
 * Supports PKCE via code_challenge and code_challenge_method params.
 */
sso_error_t handle_oauth_authorize(sso_context_t *ctx,
                                   const http_request_t *req,
                                   http_response_t *resp);

/**
 * @brief OAuth Token endpoint (RFC 6749 §4.1.3).
 *
 * Exchanges an authorization code for access_token, refresh_token, and id_token.
 * Supports grant_type=authorization_code with optional PKCE code_verifier.
 */
sso_error_t handle_oauth_token(sso_context_t *ctx,
                               const http_request_t *req,
                               http_response_t *resp);

/**
 * @brief Token Introspection endpoint (RFC 7662).
 *
 * Returns active=true/false and token metadata. Requires admin auth.
 */
sso_error_t handle_oauth_introspect(sso_context_t *ctx,
                                    const http_request_t *req,
                                    http_response_t *resp);

/**
 * @brief Token Revocation endpoint (RFC 7009).
 *
 * Revokes an access/refresh token, adding its JTI to the blocklist.
 * Always returns HTTP 200 per spec (indistinguishable from invalid token).
 */
sso_error_t handle_oauth_revoke(sso_context_t *ctx,
                                const http_request_t *req,
                                http_response_t *resp);

/**
 * @brief OIDC Session Logout endpoint (RP-initiated logout).
 *
 * Accepts id_token_hint + post_logout_redirect_uri + state.
 * Without params, simply clears the session and returns {"status":"logged_out"}.
 */
sso_error_t handle_oauth_end_session(sso_context_t *ctx,
                                     const http_request_t *req,
                                     http_response_t *resp);

/**
 * @brief OIDC Discovery document (/.well-known/openid-configuration).
 *
 * Returns the provider metadata JSON per OIDC Core §6.2.
 * Public endpoint (no auth required).
 */
sso_error_t handle_well_known_openid_config(sso_context_t *ctx,
                                            const http_request_t *req,
                                            http_response_t *resp);

/**
 * @brief JWKS endpoint (RFC 7517).
 *
 * Returns the public RSA key(s) in JWK format for token verification.
 * Public endpoint (no auth required). Returns a keys array.
 */
sso_error_t handle_jwks(sso_context_t *ctx,
                        const http_request_t *req,
                        http_response_t *resp);

/**
 * @brief OIDC UserInfo endpoint.
 *
 * Returns standard claims (sub, name, preferred_username, email)
 * for the authenticated user. Requires Bearer token.
 */
sso_error_t handle_userinfo(sso_context_t *ctx,
                            const http_request_t *req,
                            http_response_t *resp);

#ifdef __cplusplus
}
#endif

#endif /* SSO_OAUTH_H */