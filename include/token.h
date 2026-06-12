/*
 * token.h — Token / session management module.
 *
 * Issues tokens upon successful authentication, validates them on
 * subsequent requests, and manages expiry / revocation.
 *
 * Token format (v1):
 *   base64({
 *     "jti":    "<uuid>",
 *     "sub":    "<user_id>",
 *     "iat":    <issued_at_ms>,
 *     "exp":    <expires_at_ms>,
 *     "roles":  [<role_id>, ...],
 *     "groups": [<group_id>, ...]
 *   }) + "." + HMAC_SHA256(payload, server_secret)
 *
 * This is a self-contained (stateless) token — the server can verify it
 * without a database round-trip, though a blocklist is kept for revocation.
 */

#ifndef SSO_TOKEN_H
#define SSO_TOKEN_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Token structure (decoded payload)
 * ======================================================================== */
struct token {
    char              token_str[SSO_MAX_TOKEN_STR]; /* raw token string   */
    char              jti[64];                      /* unique token ID    */
    sso_id_t          user_id;
    sso_timestamp_t   issued_at;
    sso_timestamp_t   expires_at;
    sso_id_t         *role_ids;                     /* cached on issue    */
    size_t            role_count;
    sso_id_t         *group_ids;                    /* cached on issue    */
    size_t            group_count;
    char              claims[SSO_MAX_CLAIMS_JSON];  /* extra claims JSON  */
};

/* ========================================================================
 * Token manager (opaque)
 * ======================================================================== */
struct token_manager {
    unsigned char     secret[32];           /* HMAC key                    */
    sso_timestamp_t   default_ttl_ms;       /* default token lifetime (ms)*/
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/* Initialise the token manager with a secret key and default TTL. */
sso_error_t token_manager_init(token_manager_t *mgr, const unsigned char *secret,
                               size_t secret_len, sso_timestamp_t default_ttl_ms);

/* Destroy the token manager and securely wipe sensitive data. */
void        token_manager_destroy(token_manager_t *mgr);

/* -----------------------------------------------------------------------
 * Token operations
 * ----------------------------------------------------------------------- */

/* Free dynamically allocated fields inside a token (role_ids, group_ids).
 * Does NOT free the token struct itself. */
void token_destroy(token_t *token);

/* Issue a new token for the given user, embedding their roles & groups. */
sso_error_t token_issue(token_manager_t *mgr, const user_t *user,
                        const sso_id_t *role_ids, size_t role_count,
                        const sso_id_t *group_ids, size_t group_count,
                        sso_timestamp_t ttl_ms, token_t *out);

/* Verify and decode a token string.  Returns SSO_OK on success,
 * SSO_ERR_TOKEN_INVALID for bad signature / malformed,
 * SSO_ERR_TOKEN_EXPIRED if expired. */
sso_error_t token_verify(token_manager_t *mgr, const char *token_str, token_t *out);

/* Refresh a token (issue a new one with extended TTL). */
sso_error_t token_refresh(token_manager_t *mgr, const token_t *old_token,
                          sso_timestamp_t ttl_ms, token_t *out);

/* Revoke a token (add its jti to the blocklist). */
sso_error_t token_revoke(token_manager_t *mgr, const char *jti);

/* Check whether a token has been revoked. */
bool token_is_revoked(token_manager_t *mgr, const char *jti);

#ifdef __cplusplus
}
#endif

#endif /* SSO_TOKEN_H */
