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
#include <pthread.h>

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
    uint64_t          nonce;                        /* user token version */
    char              oauth_nonce[128];              /* OIDC nonce (per-request) */
    char              scope[256];                    /* OAuth scope string       */
    char              claims[SSO_MAX_CLAIMS_JSON];  /* extra claims JSON  */
    char              raw_refresh_token[128];       /* Generated opaque string */
};

/* ========================================================================
 * Token manager (opaque)
 * ======================================================================== */
typedef enum {
    SSO_TOKEN_MODE_HS256,   /* Symmetric (shared secret) */
    SSO_TOKEN_MODE_RS256    /* Asymmetric (RSA private/public pair) */
} sso_token_mode_t;

typedef struct { sso_id_t uid; uint64_t nonce; } nonce_pair_t;

#define TOKEN_REVOCATION_STR_LEN 64

struct token_manager {
    sso_token_mode_t  mode;
    union {
        unsigned char secret[32];
        struct {
            void *priv_key;
            void *pub_key;
        } rsa;
    } keys;
    sso_timestamp_t   default_ttl_ms;
    nonce_pair_t     *nonces;
    size_t            nonce_count;
    size_t            nonce_cap;
    pthread_mutex_t   nonce_lock;

    /* Per-instance revocation blocklist (was process-global) */
    char    (*jtis)[TOKEN_REVOCATION_STR_LEN]; /* dynamic array of JTI strings */
    size_t   rev_count;
    size_t   rev_capacity;
    bool     rev_sorted;
    pthread_mutex_t rev_lock;
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/* Initialise the token manager with a secret key (HS256). */
sso_error_t token_manager_init(token_manager_t *mgr, const unsigned char *secret,
                               size_t secret_len, sso_timestamp_t default_ttl_ms);

/* Initialise the token manager with an RSA key pair (RS256).
 * keys are PEM-encoded strings. */
sso_error_t token_manager_init_rs256(token_manager_t *mgr, 
                                     const char *priv_key_pem,
                                     const char *pub_key_pem,
                                     sso_timestamp_t default_ttl_ms);

/* Destroy the token manager and securely wipe sensitive data. */
void        token_manager_destroy(token_manager_t *mgr);

/* -----------------------------------------------------------------------
 * Token operations
 * ----------------------------------------------------------------------- */

/* Get the current public key in PEM format (only for RS256 mode).
 * Caller must free the returned string. */
char *token_manager_get_public_key_pem(token_manager_t *mgr);

/* Free dynamically allocated fields inside a token (role_ids, group_ids).
 * Does NOT free the token struct itself. */
void token_destroy(token_t *token);

/* Issue a new token for the given user, embedding their roles & groups. */
sso_error_t token_issue(token_manager_t *mgr, const user_t *user,
                        const sso_id_t *role_ids, size_t role_count,
                        const sso_id_t *group_ids, size_t group_count,
                        const char *scope,
                        sso_timestamp_t ttl_ms, token_t *out);

/* Verify and decode a token string.  Returns SSO_OK on success,
 * SSO_ERR_TOKEN_INVALID for bad signature / malformed,
 * SSO_ERR_TOKEN_EXPIRED if expired. */
sso_error_t token_verify(token_manager_t *mgr, const char *token_str, token_t *out);

/* Set the token nonce for a user.  Tokens issued with an older nonce
 * will fail the nonce check.  Used to implement "logout all sessions". */
sso_error_t token_set_nonce(token_manager_t *mgr, sso_id_t user_id, uint64_t nonce);

/* Get the current token nonce for a user (default 0). */
uint64_t token_get_nonce(token_manager_t *mgr, sso_id_t user_id);

/* Bump (increment) the token nonce for a user, invalidating all existing
 * sessions. */
sso_error_t token_bump_nonce(token_manager_t *mgr, sso_id_t user_id);

/* Refresh a token (issue a new one with extended TTL). */
sso_error_t token_refresh(token_manager_t *mgr, const token_t *old_token,
                          sso_timestamp_t ttl_ms, token_t *out);

/* -----------------------------------------------------------------------
 * Base64url encoding (RFC 4648 §5 — URL-safe, no padding)
 * ----------------------------------------------------------------------- */

/* Encode binary data to base64url (no padding). Returns length written. */
size_t base64url_encode(const unsigned char *input, size_t len,
                        char *output, size_t output_len);

/* Decode a base64url string (handles missing padding, tolerates +/ vs -_). */
size_t base64url_decode(const char *input, unsigned char *output,
                        size_t output_len);

/* Revoke a token (add its jti to the blocklist). */
sso_error_t token_revoke(token_manager_t *mgr, const char *jti);

/* Check whether a token has been revoked. */
bool token_is_revoked(token_manager_t *mgr, const char *jti);

#ifdef __cplusplus
}
#endif

#endif /* SSO_TOKEN_H */
