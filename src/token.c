/*
 * token.c — Token manager implementation.
 *
 * Self-contained token format:
 *   base64(json_payload) "." hex(HMAC-SHA256(payload, secret))
 *
 * The token embeds user_id, role_ids, group_ids so subsequent requests
 * don't require database lookups for authorization context.
 */

#include "sso.h"
#include "token.h"
#include "user.h"
#include "cJSON.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sodium.h>
#include <pthread.h>

/* ========================================================================
 * Internal helpers
 * ======================================================================== */

static void to_hex(const unsigned char *bin, size_t len, char *hex, size_t hex_len) {
    char *p = hex;
    for (size_t i = 0; i < len && p < hex + hex_len - 3; i++) {
        p += snprintf(p, hex_len - (size_t)(p - hex), "%02x", bin[i]);
    }
    *p = '\0';
}

/* ---- Self-contained base64 (no OpenSSL BIO dependency) ---- */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const unsigned char *input, size_t len,
                           char *output, size_t output_len) {
    size_t i = 0, o = 0;
    while (i < len && o + 4 < output_len) {
        unsigned char a = input[i];
        unsigned char b = (i + 1 < len) ? input[i + 1] : 0;
        unsigned char c = (i + 2 < len) ? input[i + 2] : 0;

        output[o++] = b64_table[a >> 2];
        output[o++] = b64_table[((a & 0x03) << 4) | (b >> 4)];
        output[o++] = (i + 1 < len) ? b64_table[((b & 0x0f) << 2) | (c >> 6)] : '=';
        output[o++] = (i + 2 < len) ? b64_table[c & 0x3f] : '=';
        i += 3;
    }
    output[o] = '\0';
}

static int b64_rev(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char *input, unsigned char *output, size_t output_len) {
    size_t i = 0, o = 0;
    size_t len = strlen(input);
    while (i < len && o < output_len) {
        int a = b64_rev(input[i]);      if (a < 0) break;
        int b = b64_rev(input[i + 1]);  if (b < 0) break;
        int c = b64_rev(input[i + 2]);
        int d = b64_rev(input[i + 3]);

        output[o++] = (unsigned char)((a << 2) | (b >> 4));
        if (c >= 0 && o < output_len) {
            output[o++] = (unsigned char)(((b & 0x0f) << 4) | (c >> 2));
        }
        if (d >= 0 && o < output_len) {
            output[o++] = (unsigned char)(((c & 0x03) << 6) | d);
        }
        i += 4;
    }
    return o;
}

/* ---- Base64url (RFC 4648 §5): URL-safe, no padding ---- */
static const char b64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t base64url_encode(const unsigned char *input, size_t len,
                        char *output, size_t output_len) {
    size_t i = 0, o = 0;
    while (i < len && o + 4 < output_len) {
        unsigned char a = input[i];
        unsigned char b = (i + 1 < len) ? input[i + 1] : 0;
        unsigned char c = (i + 2 < len) ? input[i + 2] : 0;

        output[o++] = b64url_table[a >> 2];
        output[o++] = b64url_table[((a & 0x03) << 4) | (b >> 4)];
        if ((i + 1) < len)
            output[o++] = b64url_table[((b & 0x0f) << 2) | (c >> 6)];
        if ((i + 2) < len)
            output[o++] = b64url_table[c & 0x3f];
        i += 3;
    }
    output[o] = '\0';
    return o;
}

static int b64url_rev(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

size_t base64url_decode(const char *input, unsigned char *output, size_t output_len) {
    size_t i = 0, o = 0;
    size_t len = strlen(input);
    while (i < len && o < output_len) {
        int a = b64url_rev(input[i]);      if (a < 0) break;
        int b = b64url_rev(input[i + 1]);  if (b < 0) break;
        int c = (i + 2 < len) ? b64url_rev(input[i + 2]) : -1;
        int d = (i + 3 < len) ? b64url_rev(input[i + 3]) : -1;

        output[o++] = (unsigned char)((a << 2) | (b >> 4));
        if (c >= 0 && o < output_len)
            output[o++] = (unsigned char)(((b & 0x0f) << 4) | (c >> 2));
        if (d >= 0 && o < output_len)
            output[o++] = (unsigned char)(((c & 0x03) << 6) | d);
        i += 4;
    }
    return o;
}

/* Check if a string looks like hex (all [0-9a-fA-F]). */
static bool is_hex_str(const char *s) {
    if (!s || !*s) return false;
    while (*s) {
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')))
            return false;
        s++;
    }
    return true;
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */
sso_error_t token_manager_init(token_manager_t *mgr, const unsigned char *secret,
                               size_t secret_len, sso_timestamp_t default_ttl_ms) {
    if (!mgr || !secret || secret_len == 0) return SSO_ERR_INVALID_PARAM;
    
    memset(mgr, 0, sizeof(*mgr));
    mgr->mode = SSO_TOKEN_MODE_HS256;
    
    size_t copy_len = secret_len < sizeof(mgr->keys.secret) ? secret_len : sizeof(mgr->keys.secret);
    memcpy(mgr->keys.secret, secret, copy_len);
    if (sodium_mlock(mgr->keys.secret, sizeof(mgr->keys.secret)) != 0) {
    }
    mgr->default_ttl_ms = default_ttl_ms;
    pthread_mutex_init(&mgr->nonce_lock, NULL);
    return SSO_OK;
}

sso_error_t token_manager_init_rs256(token_manager_t *mgr, 
                                     const char *priv_key_pem,
                                     const char *pub_key_pem,
                                     sso_timestamp_t default_ttl_ms) {
    if (!mgr || !priv_key_pem) return SSO_ERR_INVALID_PARAM;

    memset(mgr, 0, sizeof(*mgr));
    mgr->mode = SSO_TOKEN_MODE_RS256;
    mgr->default_ttl_ms = default_ttl_ms;
    pthread_mutex_init(&mgr->nonce_lock, NULL);

    /* Load private key */
    BIO *priv_bio = BIO_new_mem_buf(priv_key_pem, -1);
    if (!priv_bio) { return SSO_ERR_INIT; }
    mgr->keys.rsa.priv_key = (void *)PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
    BIO_free(priv_bio);

    if (!mgr->keys.rsa.priv_key) {
        return SSO_ERR_INIT;
    }

    /* Load public key if provided, otherwise derive it from private */
    if (pub_key_pem) {
        BIO *pub_bio = BIO_new_mem_buf(pub_key_pem, -1);
        mgr->keys.rsa.pub_key = (void *)PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
        BIO_free(pub_bio);
    } else {
        /* Extract public key from private key */
        BIO *pub_bio = BIO_new(BIO_s_mem());
        if (PEM_write_bio_PUBKEY(pub_bio, (EVP_PKEY *)mgr->keys.rsa.priv_key)) {
            mgr->keys.rsa.pub_key = (void *)PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
        }
        BIO_free(pub_bio);
    }

    if (!mgr->keys.rsa.pub_key) {
        EVP_PKEY_free((EVP_PKEY *)mgr->keys.rsa.priv_key);
        mgr->keys.rsa.priv_key = NULL;
        return SSO_ERR_INIT;
    }

    return SSO_OK;
}

char *token_manager_get_public_key_pem(token_manager_t *mgr) {
    if (!mgr || mgr->mode != SSO_TOKEN_MODE_RS256 || !mgr->keys.rsa.pub_key) return NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, (EVP_PKEY *)mgr->keys.rsa.pub_key)) {
        BIO_free(bio);
        return NULL;
    }

    char *buf;
    long len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *)malloc((size_t)len + 1);
    if (ret) {
        memcpy(ret, buf, (size_t)len);
        ret[len] = '\0';
    }

    BIO_free(bio);
    return ret;
}

void token_manager_destroy(token_manager_t *mgr) {
    if (!mgr) return;
    
    if (mgr->mode == SSO_TOKEN_MODE_HS256) {
        /* Securely wipe the HMAC key before freeing. */
        sodium_memzero(mgr->keys.secret, sizeof(mgr->keys.secret));
        sodium_munlock(mgr->keys.secret, sizeof(mgr->keys.secret));
    } else {
        if (mgr->keys.rsa.priv_key) EVP_PKEY_free((EVP_PKEY *)mgr->keys.rsa.priv_key);
        if (mgr->keys.rsa.pub_key) EVP_PKEY_free((EVP_PKEY *)mgr->keys.rsa.pub_key);
    }

    free(mgr->nonces);
    mgr->nonces = NULL;
    pthread_mutex_destroy(&mgr->nonce_lock);

    free(mgr);
}

void token_destroy(token_t *token) {
    if (!token) return;
    free(token->role_ids);
    token->role_ids = NULL;
    token->role_count = 0;
    free(token->group_ids);
    token->group_ids = NULL;
    token->group_count = 0;
}

/* ========================================================================
 * Token operations
 * ======================================================================== */
sso_error_t token_issue(token_manager_t *mgr, const user_t *user,
                        const sso_id_t *role_ids, size_t role_count,
                        const sso_id_t *group_ids, size_t group_count,
                        const char *scope,
                        sso_timestamp_t ttl_ms, token_t *out) {
    if (!mgr || !user || !out) return SSO_ERR_INVALID_PARAM;

    memset(out, 0, sizeof(*out));
    out->user_id = user->id;
    out->issued_at = sso_timestamp_now();
    long long actual_ttl = (ttl_ms > 0) ? ttl_ms : (ttl_ms == 0 ? mgr->default_ttl_ms : ttl_ms);
    out->expires_at = out->issued_at + actual_ttl;
    out->role_count = role_count;
    out->group_count = group_count;
    out->nonce = token_get_nonce(mgr, user->id);

    if (scope) {
        strncpy(out->scope, scope, sizeof(out->scope) - 1);
    }

    unsigned char rand_bytes[8];
    randombytes_buf(rand_bytes, sizeof(rand_bytes));
    snprintf(out->jti, sizeof(out->jti), "%llx%02x%02x%02x%02x%02x%02x%02x%02x",
             (unsigned long long)out->issued_at,
             rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
             rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7]);

    if (role_ids && role_count > 0) {
        out->role_ids = (sso_id_t *)malloc(role_count * sizeof(sso_id_t));
        if (!out->role_ids) return SSO_ERR_OUT_OF_MEMORY;
        memcpy(out->role_ids, role_ids, role_count * sizeof(sso_id_t));
    }
    if (group_ids && group_count > 0) {
        out->group_ids = (sso_id_t *)malloc(group_count * sizeof(sso_id_t));
        if (!out->group_ids) {
            free(out->role_ids);
            out->role_ids = NULL;
            return SSO_ERR_OUT_OF_MEMORY;
        }
        memcpy(out->group_ids, group_ids, group_count * sizeof(sso_id_t));
    }

    /* JWT Header */
    cJSON *header = cJSON_CreateObject();
    cJSON_AddStringToObject(header, "alg", mgr->mode == SSO_TOKEN_MODE_RS256 ? "RS256" : "HS256");
    cJSON_AddStringToObject(header, "typ", "JWT");
    char *header_str = cJSON_PrintUnformatted(header);
    cJSON_Delete(header);
    char b64_header[128];
    base64_encode((unsigned char *)header_str, strlen(header_str), b64_header, sizeof(b64_header));
    free(header_str);

    /* JWT Payload */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "jti", out->jti);
    cJSON_AddNumberToObject(root, "sub", (double)out->user_id);
    cJSON_AddNumberToObject(root, "iat", (double)out->issued_at);
    cJSON_AddNumberToObject(root, "exp", (double)out->expires_at);
    cJSON_AddNumberToObject(root, "tnc", (double)out->nonce);
    cJSON_AddStringToObject(root, "iss", "sso-server");
    cJSON_AddStringToObject(root, "aud", "sso-api");

    if (out->scope[0])
        cJSON_AddStringToObject(root, "scope", out->scope);
    if (out->oauth_nonce[0])
        cJSON_AddStringToObject(root, "nonce", out->oauth_nonce);

    cJSON *roles_arr = cJSON_CreateArray();
    for (size_t i = 0; i < role_count; i++) {
        cJSON_AddItemToArray(roles_arr, cJSON_CreateNumber((double)role_ids[i]));
    }
    cJSON_AddItemToObject(root, "roles", roles_arr);

    cJSON *groups_arr = cJSON_CreateArray();
    for (size_t i = 0; i < group_count; i++) {
        cJSON_AddItemToArray(groups_arr, cJSON_CreateNumber((double)group_ids[i]));
    }
    cJSON_AddItemToObject(root, "groups", groups_arr);

    char *payload_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!payload_str) return SSO_ERR_OUT_OF_MEMORY;

    char b64_payload[2048];
    base64_encode((unsigned char *)payload_str, strlen(payload_str), b64_payload, sizeof(b64_payload));
    free(payload_str);

    /* signing_input = header.payload */
    char signing_input[2560];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", b64_header, b64_payload);

    /* Generate 32 bytes of random data for refresh token */
    unsigned char rt_bytes[32];
    randombytes_buf(rt_bytes, sizeof(rt_bytes));
    
    /* Base64url encode it */
    base64url_encode(rt_bytes, sizeof(rt_bytes), out->raw_refresh_token, sizeof(out->raw_refresh_token));

    if (mgr->mode == SSO_TOKEN_MODE_HS256) {
        unsigned char hmac_result[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;
        HMAC(EVP_sha256(), mgr->keys.secret, (int)sizeof(mgr->keys.secret),
             (unsigned char *)signing_input, strlen(signing_input),
             hmac_result, &hmac_len);

        char sig_b64[EVP_MAX_MD_SIZE * 2 + 1];
        base64url_encode(hmac_result, hmac_len, sig_b64, sizeof(sig_b64));
        snprintf(out->token_str, sizeof(out->token_str), "%s.%s", signing_input, sig_b64);
    } else {
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pk_ctx = NULL;
        size_t sig_len = 0;
        unsigned char *sig = NULL;

        if (EVP_DigestSignInit(md_ctx, &pk_ctx, EVP_sha256(), NULL, (EVP_PKEY *)mgr->keys.rsa.priv_key) <= 0) goto rs_fail;
        if (EVP_DigestSignUpdate(md_ctx, signing_input, strlen(signing_input)) <= 0) goto rs_fail;
        if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) goto rs_fail;
        
        sig = (unsigned char *)malloc(sig_len);
        if (!sig) { goto rs_fail; }
        if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) { free(sig); goto rs_fail; }

        char *sig_b64 = (char *)malloc(sig_len * 2 + 2);
        if (!sig_b64) { free(sig); goto rs_fail; }
        base64url_encode(sig, sig_len, sig_b64, sig_len * 2 + 2);
        snprintf(out->token_str, sizeof(out->token_str), "%s.%s", signing_input, sig_b64);
        
        free(sig);
        free(sig_b64);
        EVP_MD_CTX_free(md_ctx);
        return SSO_OK;

    rs_fail:
        if (md_ctx) EVP_MD_CTX_free(md_ctx);
        return SSO_ERR_INIT;
    }

    return SSO_OK;
}

sso_error_t token_verify(token_manager_t *mgr, const char *token_str, token_t *out) {
    if (!mgr || !token_str || !out) return SSO_ERR_INVALID_PARAM;

    memset(out, 0, sizeof(*out));
    strncpy(out->token_str, token_str, SSO_MAX_TOKEN_STR - 1);

    /* Split into header, payload, and signature */
    const char *dot1 = strchr(token_str, '.');
    if (!dot1) return SSO_ERR_TOKEN_INVALID;

    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return SSO_ERR_TOKEN_INVALID;

    size_t hdr_len = (size_t)(dot1 - token_str);
    size_t b64_len = (size_t)(dot2 - dot1 - 1);

    char b64_header[128];
    char b64_payload[2048];
    if (hdr_len >= sizeof(b64_header) || b64_len >= sizeof(b64_payload))
        return SSO_ERR_TOKEN_INVALID;

    strncpy(b64_header, token_str, hdr_len);
    b64_header[hdr_len] = '\0';

    strncpy(b64_payload, dot1 + 1, b64_len);
    b64_payload[b64_len] = '\0';

    const char *sig_part = dot2 + 1;

    /* signing_input = header.payload */
    char signing_input[2560];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", b64_header, b64_payload);

    /* Backward compat: detect hex-encoded signature (old format) */
    bool legacy_hex = is_hex_str(sig_part);

    /* Verify signature */
    if (mgr->mode == SSO_TOKEN_MODE_HS256) {
        unsigned char hmac_result[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;
        HMAC(EVP_sha256(), mgr->keys.secret, (int)sizeof(mgr->keys.secret),
             (unsigned char *)signing_input, strlen(signing_input),
             hmac_result, &hmac_len);

        if (legacy_hex) {
            char expected_hex[EVP_MAX_MD_SIZE * 2 + 1];
            to_hex(hmac_result, hmac_len, expected_hex, sizeof(expected_hex));
            if (strcmp(sig_part, expected_hex) != 0)
                return SSO_ERR_TOKEN_INVALID;
        } else {
            char expected_b64[EVP_MAX_MD_SIZE * 2 + 1];
            base64url_encode(hmac_result, hmac_len, expected_b64, sizeof(expected_b64));
            if (strcmp(sig_part, expected_b64) != 0)
                return SSO_ERR_TOKEN_INVALID;
        }
    } else {
        unsigned char *sig = NULL;
        size_t sig_len = 0;

        if (legacy_hex) {
            sig_len = strlen(sig_part) / 2;
            sig = (unsigned char *)malloc(sig_len);
            if (!sig) return SSO_ERR_TOKEN_INVALID; // Or an OOM error if you have one
            for (size_t i = 0; i < sig_len; i++) {
                unsigned int val;
                sscanf(sig_part + i*2, "%02x", &val);
                sig[i] = (unsigned char)val;
            }
        } else {
            sig_len = strlen(sig_part) / 4 * 3 + 4;
            sig = (unsigned char *)malloc(sig_len);
            if (!sig) return SSO_ERR_TOKEN_INVALID; // Or OOM error
            sig_len = base64url_decode(sig_part, sig, sig_len);
        }

        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX *pk_ctx = NULL;
        sso_error_t v_err = SSO_OK;

        if (EVP_DigestVerifyInit(md_ctx, &pk_ctx, EVP_sha256(), NULL, (EVP_PKEY *)mgr->keys.rsa.pub_key) <= 0) v_err = SSO_ERR_INIT;
        if (v_err == SSO_OK && EVP_DigestVerifyUpdate(md_ctx, signing_input, strlen(signing_input)) <= 0) v_err = SSO_ERR_INIT;
        if (v_err == SSO_OK && EVP_DigestVerifyFinal(md_ctx, sig, sig_len) <= 0) v_err = SSO_ERR_TOKEN_INVALID;

        free(sig);
        EVP_MD_CTX_free(md_ctx);
        if (v_err != SSO_OK) return v_err;
    }

    /* Decode payload (accept both base64 and base64url) */
    unsigned char decoded[4096];
    size_t decoded_len = base64_decode(b64_payload, decoded, sizeof(decoded) - 1);
    if (decoded_len == 0)
        decoded_len = base64url_decode(b64_payload, decoded, sizeof(decoded) - 1);
    if (decoded_len == 0) return SSO_ERR_TOKEN_INVALID;
    decoded[decoded_len] = '\0';

    cJSON *root = cJSON_Parse((const char *)decoded);
    if (!root) return SSO_ERR_TOKEN_INVALID;

    cJSON *jti_item = cJSON_GetObjectItem(root, "jti");
    if (cJSON_IsString(jti_item)) {
        strncpy(out->jti, jti_item->valuestring, sizeof(out->jti) - 1);
    }

    cJSON *sub_item = cJSON_GetObjectItem(root, "sub");
    if (cJSON_IsNumber(sub_item)) {
        out->user_id = (sso_id_t)sub_item->valuedouble;
    }

    cJSON *iat_item = cJSON_GetObjectItem(root, "iat");
    if (cJSON_IsNumber(iat_item)) {
        out->issued_at = (sso_timestamp_t)iat_item->valuedouble;
    }

    cJSON *exp_item = cJSON_GetObjectItem(root, "exp");
    if (cJSON_IsNumber(exp_item)) {
        out->expires_at = (sso_timestamp_t)exp_item->valuedouble;
    }

    cJSON *tnc_item = cJSON_GetObjectItem(root, "tnc");
    if (cJSON_IsNumber(tnc_item)) {
        out->nonce = (uint64_t)tnc_item->valuedouble;
    }

    cJSON *scope_item = cJSON_GetObjectItem(root, "scope");
    if (cJSON_IsString(scope_item)) {
        strncpy(out->scope, scope_item->valuestring, sizeof(out->scope) - 1);
    }

    cJSON *nonce_item = cJSON_GetObjectItem(root, "nonce");
    if (cJSON_IsString(nonce_item)) {
        strncpy(out->oauth_nonce, nonce_item->valuestring, sizeof(out->oauth_nonce) - 1);
    }

    cJSON *roles_arr = cJSON_GetObjectItem(root, "roles");
    if (cJSON_IsArray(roles_arr)) {
        out->role_count = (size_t)cJSON_GetArraySize(roles_arr);
        if (out->role_count > 0) {
            out->role_ids = (sso_id_t *)calloc(out->role_count, sizeof(sso_id_t));
            for (size_t i = 0; i < out->role_count; i++) {
                cJSON *r = cJSON_GetArrayItem(roles_arr, (int)i);
                if (cJSON_IsNumber(r)) out->role_ids[i] = (sso_id_t)r->valuedouble;
            }
        }
    }

    cJSON *groups_arr = cJSON_GetObjectItem(root, "groups");
    if (cJSON_IsArray(groups_arr)) {
        out->group_count = (size_t)cJSON_GetArraySize(groups_arr);
        if (out->group_count > 0) {
            out->group_ids = (sso_id_t *)calloc(out->group_count, sizeof(sso_id_t));
            for (size_t i = 0; i < out->group_count; i++) {
                cJSON *g = cJSON_GetArrayItem(groups_arr, (int)i);
                if (cJSON_IsNumber(g)) out->group_ids[i] = (sso_id_t)g->valuedouble;
            }
        }
    }

    cJSON_Delete(root);

    if (sso_timestamp_now() > out->expires_at) {
        token_destroy(out);
        return SSO_ERR_TOKEN_EXPIRED;
    }

    return SSO_OK;
}

sso_error_t token_refresh(token_manager_t *mgr, const token_t *old_token,
                          sso_timestamp_t ttl_ms, token_t *out) {
    if (!mgr || !old_token || !out) return SSO_ERR_INVALID_PARAM;

    /* Issue a new token for the same user, reusing roles/groups from the old token */
    user_t user;
    memset(&user, 0, sizeof(user));
    user.id = old_token->user_id;
    /* user data not fully available here — but token_issue only needs user->id */

    return token_issue(mgr, &user,
                       old_token->role_ids, old_token->role_count,
                       old_token->group_ids, old_token->group_count,
                       old_token->scope,
                       ttl_ms > 0 ? ttl_ms : mgr->default_ttl_ms,
                       out);
}

/* ========================================================================
 * Revocation (dynamic growing blocklist)
 * ======================================================================== */
#define REVOCATION_STR_LEN 64
#define REVOCATIONS_INIT_CAP 64

static struct {
    char (*jtis)[REVOCATION_STR_LEN];
    size_t count;
    size_t capacity;
    bool   sorted;
    pthread_mutex_t lock;
} revocations = {NULL, 0, 0, true, PTHREAD_MUTEX_INITIALIZER};

static int compare_jtis(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

sso_error_t token_revoke(token_manager_t *mgr, const char *jti) {
    (void)mgr;
    if (!jti) return SSO_ERR_INVALID_PARAM;

    pthread_mutex_lock(&revocations.lock);

    if (revocations.jtis == NULL) {
        revocations.jtis = (char (*)[REVOCATION_STR_LEN])calloc(
            REVOCATIONS_INIT_CAP, REVOCATION_STR_LEN);
        if (!revocations.jtis) {
            pthread_mutex_unlock(&revocations.lock);
            return SSO_ERR_OUT_OF_MEMORY;
        }
        revocations.capacity = REVOCATIONS_INIT_CAP;
    }

    if (revocations.count >= revocations.capacity) {
        size_t new_cap = revocations.capacity * 2;
        char (*new_jtis)[REVOCATION_STR_LEN] = (char (*)[REVOCATION_STR_LEN])realloc(
            revocations.jtis, new_cap * REVOCATION_STR_LEN);
        if (!new_jtis) {
            pthread_mutex_unlock(&revocations.lock);
            return SSO_ERR_OUT_OF_MEMORY;
        }
        revocations.jtis = new_jtis;
        revocations.capacity = new_cap;
    }

    strncpy(revocations.jtis[revocations.count], jti, REVOCATION_STR_LEN - 1);
    revocations.jtis[revocations.count][REVOCATION_STR_LEN - 1] = '\0';
    revocations.count++;
    revocations.sorted = false;

    pthread_mutex_unlock(&revocations.lock);
    return SSO_OK;
}

bool token_is_revoked(token_manager_t *mgr, const char *jti) {
    (void)mgr;
    if (!jti) return false;

    pthread_mutex_lock(&revocations.lock);

    if (!revocations.jtis || revocations.count == 0) {
        pthread_mutex_unlock(&revocations.lock);
        return false;
    }

    if (!revocations.sorted) {
        qsort(revocations.jtis, revocations.count, REVOCATION_STR_LEN, compare_jtis);
        revocations.sorted = true;
    }

    bool found = bsearch(jti, revocations.jtis, revocations.count, REVOCATION_STR_LEN, compare_jtis) != NULL;
    pthread_mutex_unlock(&revocations.lock);
    return found;
}

/* ========================================================================
 * User token nonces (for "logout all sessions")
 * ======================================================================== */
sso_error_t token_set_nonce(token_manager_t *mgr, sso_id_t user_id, uint64_t nonce) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    pthread_mutex_lock(&mgr->nonce_lock);
    for (size_t i = 0; i < mgr->nonce_count; i++) {
        if (mgr->nonces[i].uid == user_id) {
            mgr->nonces[i].nonce = nonce;
            pthread_mutex_unlock(&mgr->nonce_lock);
            return SSO_OK;
        }
    }
    size_t new_cap = mgr->nonce_cap ? mgr->nonce_cap * 2 : 16;
    nonce_pair_t *new_nonces = (nonce_pair_t *)realloc(mgr->nonces, new_cap * sizeof(nonce_pair_t));
    if (!new_nonces) { pthread_mutex_unlock(&mgr->nonce_lock); return SSO_ERR_OUT_OF_MEMORY; }
    mgr->nonces = new_nonces;
    mgr->nonce_cap = new_cap;
    mgr->nonces[mgr->nonce_count].uid = user_id;
    mgr->nonces[mgr->nonce_count].nonce = nonce;
    mgr->nonce_count++;
    pthread_mutex_unlock(&mgr->nonce_lock);
    return SSO_OK;
}

uint64_t token_get_nonce(token_manager_t *mgr, sso_id_t user_id) {
    if (!mgr) return 0;
    pthread_mutex_lock(&mgr->nonce_lock);
    for (size_t i = 0; i < mgr->nonce_count; i++) {
        if (mgr->nonces[i].uid == user_id) {
            uint64_t n = mgr->nonces[i].nonce;
            pthread_mutex_unlock(&mgr->nonce_lock);
            return n;
        }
    }
    pthread_mutex_unlock(&mgr->nonce_lock);
    return 0;
}

sso_error_t token_bump_nonce(token_manager_t *mgr, sso_id_t user_id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    uint64_t current = token_get_nonce(mgr, user_id);
    return token_set_nonce(mgr, user_id, current + 1);
}
