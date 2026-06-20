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

/**
 * @struct token
 * @brief Decoded payload and metadata of a session token.
 */
struct token {
    char              token_str[SSO_MAX_TOKEN_STR]; /**< Raw JWT string */
    char              jti[64];                      /**< Unique token identifier / UUID */
    sso_id_t          user_id;                      /**< Subject (User ID) */
    sso_timestamp_t   issued_at;                    /**< Issued At timestamp (epoch ms) */
    sso_timestamp_t   expires_at;                   /**< Expiry timestamp (epoch ms) */
    sso_id_t         *role_ids;                     /**< Array of roles cached inside token */
    size_t            role_count;                   /**< Number of roles inside token */
    sso_id_t         *group_ids;                    /**< Array of groups cached inside token */
    size_t            group_count;                  /**< Number of groups inside token */
    uint64_t          nonce;                        /**< User token nonce version */
    char              oauth_nonce[128];             /**< Optional OIDC nonce string */
    char              scope[256];                   /**< Optional OAuth scope string */
    char              claims[SSO_MAX_CLAIMS_JSON];  /**< Additional JSON claims string */
    char              jkt[64];                      /**< DPoP JWK Thumbprint */
    char              raw_refresh_token[128];       /**< Generated opaque refresh token string */
};

/**
 * @brief Token signing mode (Symmetric or Asymmetric).
 */
typedef enum {
    SSO_TOKEN_MODE_HS256,   /**< Symmetric HS256 (shared secret) signing */
    SSO_TOKEN_MODE_RS256    /**< Asymmetric RS256 (RSA private/public pair) signing */
} sso_token_mode_t;

/**
 * @struct nonce_pair_t
 * @brief Nonce tracking for a user.
 */
typedef struct { sso_id_t uid; uint64_t nonce; } nonce_pair_t;

#define TOKEN_REVOCATION_STR_LEN 64

/**
 * @struct token_manager
 * @brief Handles token creation, verification, revocation lists, and nonces.
 */
struct token_manager {
    sso_token_mode_t  mode;                         /**< Signing mode (HS256 or RS256) */
    union {
        unsigned char secret[32];                   /**< HMAC-SHA256 secret key */
        struct {
            void *priv_key;                         /**< RSA private key object (EVP_PKEY) */
            void *pub_key;                          /**< RSA public key object (EVP_PKEY) */
        } rsa;
    } keys;
    sso_timestamp_t   default_ttl_ms;               /**< Default token duration */
    nonce_pair_t     *nonces;                       /**< Array of user nonces */
    size_t            nonce_count;                  /**< Active count of nonces */
    size_t            nonce_cap;                    /**< Capacity of nonces array */
    pthread_mutex_t   nonce_lock;                   /**< Mutex guarding nonces access */

    /* Per-instance revocation blocklist (was process-global) */
    char    (*jtis)[TOKEN_REVOCATION_STR_LEN];      /**< Dynamic array of revoked JTI strings */
    size_t   rev_count;                             /**< Active count of revoked JTIs */
    size_t   rev_capacity;                          /**< Capacity of revoked JTIs array */
    bool     rev_sorted;                            /**< True if array is sorted for binary search */
    pthread_mutex_t rev_lock;                       /**< Mutex guarding revocation blocklist */
    void    *storage;                               /**< Pointer to storage backend */
};

/* -----------------------------------------------------------------------
 * Lifecycle
 * ----------------------------------------------------------------------- */

/**
 * @brief Initializes the token manager in symmetric HS256 mode.
 * 
 * @param mgr Manager instance to initialize.
 * @param secret Shared secret key.
 * @param secret_len Length of secret key.
 * @param default_ttl_ms Default token time-to-live.
 */
sso_error_t token_manager_init(token_manager_t *mgr, const unsigned char *secret,
                               size_t secret_len, sso_timestamp_t default_ttl_ms);

/**
 * @brief Initializes the token manager in asymmetric RS256 mode.
 * 
 * @param mgr Manager instance.
 * @param priv_key_pem PEM-encoded RSA private key.
 * @param pub_key_pem PEM-encoded RSA public key.
 * @param default_ttl_ms Default token time-to-live.
 */
sso_error_t token_manager_init_rs256(token_manager_t *mgr, 
                                     const char *priv_key_pem,
                                     const char *pub_key_pem,
                                     sso_timestamp_t default_ttl_ms);

/**
 * @brief Destroys token manager, freeing nonces and revocation blocklist.
 * 
 * Securely wipes sensitive signing keys from memory.
 * 
 * @param mgr Manager instance to destroy.
 */
void        token_manager_destroy(token_manager_t *mgr);

/* -----------------------------------------------------------------------
 * Token operations
 * ----------------------------------------------------------------------- */

/**
 * @brief Retrieves the public key in PEM format (only for RS256 mode).
 * 
 * @param mgr Token manager.
 * @return Allocated PEM string, caller must free it.
 */
char *token_manager_get_public_key_pem(token_manager_t *mgr);

/**
 * @brief Frees dynamically allocated structures inside a token.
 * 
 * Reclaims memory allocated for role_ids and group_ids array. Does not free the token container itself.
 * 
 * @param token Token instance.
 */
void token_destroy(token_t *token);

/**
 * @brief Issues a new JWT token for a user.
 * 
 * Encodes user properties, active roles, and groups into the JWT claims and signs it.
 * 
 * @param mgr Token manager.
 * @param user User to issue the token for.
 * @param role_ids Array of roles.
 * @param role_count Size of role array.
 * @param group_ids Array of groups.
 * @param group_count Size of group array.
 * @param scope Scope access string.
 * @param ttl_ms Token duration (0 uses default TTL).
 * @param out Output token structure containing JWT string.
 */
sso_error_t token_issue(token_manager_t *mgr, const user_t *user,
                        const sso_id_t *role_ids, size_t role_count,
                        const sso_id_t *group_ids, size_t group_count,
                        const char *scope,
                        sso_timestamp_t ttl_ms, token_t *out);

/**
 * @brief Decodes, validates signature, and verifies the TTL of a raw JWT string.
 * 
 * @param mgr Token manager.
 * @param token_str Raw JWT string.
 * @param out Output token payload if validation passes.
 * @return SSO_OK, SSO_ERR_TOKEN_INVALID, or SSO_ERR_TOKEN_EXPIRED.
 */
sso_error_t token_verify(token_manager_t *mgr, const char *token_str, token_t *out);

/**
 * @brief Overrides or sets the nonce tracking value for a user.
 * 
 * @param mgr Token manager.
 * @param user_id User ID.
 * @param nonce Nonce version target.
 */
sso_error_t token_set_nonce(token_manager_t *mgr, sso_id_t user_id, uint64_t nonce);

/**
 * @brief Retrieves the current token nonce for a user.
 * 
 * @param mgr Token manager.
 * @param user_id User ID.
 * @return Current nonce value (default 0).
 */
uint64_t token_get_nonce(token_manager_t *mgr, sso_id_t user_id);

/**
 * @brief Increments the token nonce version for a user.
 * 
 * Used to immediately invalidate all currently active tokens (logout all sessions) of this user.
 * 
 * @param mgr Token manager.
 * @param user_id User ID.
 */
sso_error_t token_bump_nonce(token_manager_t *mgr, sso_id_t user_id);

/**
 * @brief Refreshes an old token, issuing a new token with a renewed TTL.
 * 
 * @param mgr Token manager.
 * @param old_token Previous valid token.
 * @param ttl_ms New TTL duration (0 uses default).
 * @param out Output token structure.
 */
sso_error_t token_refresh(token_manager_t *mgr, const token_t *old_token,
                          sso_timestamp_t ttl_ms, token_t *out);

/* -----------------------------------------------------------------------
 * Base64url encoding (RFC 4648 §5 — URL-safe, no padding)
 * ----------------------------------------------------------------------- */

/**
 * @brief Encodes binary data to base64url string (RFC 4648 §5).
 * 
 * @param input Binary buffer.
 * @param len Length of binary buffer.
 * @param output Output string buffer.
 * @param output_len Output buffer capacity.
 * @return Number of characters written.
 */
size_t base64url_encode(const unsigned char *input, size_t len,
                        char *output, size_t output_len);

/**
 * @brief Decodes base64url string back to binary.
 * 
 * Tolerates lack of padding, URL-safe variants, and basic whitespaces.
 * 
 * @param input Base64url encoded string.
 * @param output Output binary buffer.
 * @param output_len Output buffer capacity.
 * @return Number of bytes decoded.
 */
size_t base64url_decode(const char *input, unsigned char *output,
                        size_t output_len);

/**
 * @brief Revokes a token, adding its JTI UUID to the blocklist.
 * 
 * @param mgr Token manager.
 * @param jti JTI identifier string.
 * @param expires_at Token expiry timestamp (epoch ms).
 */
sso_error_t token_revoke(token_manager_t *mgr, const char *jti, sso_timestamp_t expires_at);

/**
 * @brief Checks if a token has been explicitly revoked.
 * 
 * @param mgr Token manager.
 * @param jti JTI identifier.
 * @return True if JTI is in the revocation blocklist.
 */
bool token_is_revoked(token_manager_t *mgr, const char *jti);

#ifdef __cplusplus
}
#endif

#endif /* SSO_TOKEN_H */
