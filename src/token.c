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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sodium.h>

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

/* Minimal JSON payload builder.  In production, use cjson. */
static void build_token_payload(const token_t *token, char *payload, size_t payload_len) {
    /* Build JSON: {"jti":"...","sub":...,"iat":...,"exp":...,"roles":[...],"groups":[...]} */
    char roles_str[256] = "";
    if (token->role_count > 0) {
        strcat(roles_str, "[");
        for (size_t i = 0; i < token->role_count; i++) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%lu%s",
                     (unsigned long)token->role_ids[i],
                     i < token->role_count - 1 ? "," : "");
            strcat(roles_str, buf);
        }
        strcat(roles_str, "]");
    } else {
        strcat(roles_str, "[]");
    }

    char groups_str[256] = "";
    if (token->group_count > 0) {
        strcat(groups_str, "[");
        for (size_t i = 0; i < token->group_count; i++) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%lu%s",
                     (unsigned long)token->group_ids[i],
                     i < token->group_count - 1 ? "," : "");
            strcat(groups_str, buf);
        }
        strcat(groups_str, "]");
    } else {
        strcat(groups_str, "[]");
    }

    snprintf(payload, payload_len,
             "{\"jti\":\"%s\",\"sub\":%lu,\"iat\":%lld,\"exp\":%lld,"
             "\"roles\":%s,\"groups\":%s}",
             token->jti,
             (unsigned long)token->user_id,
             (long long)token->issued_at,
             (long long)token->expires_at,
             roles_str, groups_str);
}

/* Minimal JSON parser to extract values from token payload. */
static const char *json_get_value(const char *json, const char *key) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p && *p != ':' && *p != ',') p++;
    if (*p == ':') p++;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
    return p;
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */
sso_error_t token_manager_init(token_manager_t *mgr, const unsigned char *secret,
                               size_t secret_len, sso_timestamp_t default_ttl_ms) {
    if (!mgr || !secret || secret_len == 0) return SSO_ERR_INVALID_PARAM;
    memset(mgr->secret, 0, sizeof(mgr->secret));
    size_t copy_len = secret_len < sizeof(mgr->secret) ? secret_len : sizeof(mgr->secret);
    memcpy(mgr->secret, secret, copy_len);
    /* Lock the secret in memory to prevent it from being swapped to disk. */
    if (sodium_mlock(mgr->secret, sizeof(mgr->secret)) != 0) {
        /* Non-fatal: best-effort protection. */
    }
    mgr->default_ttl_ms = default_ttl_ms;
    return SSO_OK;
}

void token_manager_destroy(token_manager_t *mgr) {
    if (!mgr) return;
    /* Securely wipe the HMAC key before freeing. */
    sodium_memzero(mgr->secret, sizeof(mgr->secret));
    sodium_munlock(mgr->secret, sizeof(mgr->secret));
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
                        sso_timestamp_t ttl_ms, token_t *out) {
    if (!mgr || !user || !out) return SSO_ERR_INVALID_PARAM;

    memset(out, 0, sizeof(*out));
    out->user_id = user->id;
    out->issued_at = sso_timestamp_now();
    out->expires_at = out->issued_at + (ttl_ms > 0 ? ttl_ms : mgr->default_ttl_ms);
    out->role_count = role_count;
    out->group_count = group_count;

    /* Generate jti (simple: timestamp + random) */
    unsigned char rand_bytes[8];
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        fread(rand_bytes, 1, 8, f);
        fclose(f);
    } else {
        for (int i = 0; i < 8; i++) rand_bytes[i] = rand() & 0xFF;
    }
    snprintf(out->jti, sizeof(out->jti), "%llx%02x%02x",
             (unsigned long long)out->issued_at,
             rand_bytes[0], rand_bytes[1]);

    /* Copy role/group IDs */
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

    /* Build and sign the token */
    char payload[1024];
    build_token_payload(out, payload, sizeof(payload));

    /* Base64-encode the payload */
    char b64_payload[1536];
    base64_encode((unsigned char *)payload, strlen(payload), b64_payload, sizeof(b64_payload));

    /* HMAC-SHA256 */
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), mgr->secret, (int)sizeof(mgr->secret),
         (unsigned char *)b64_payload, strlen(b64_payload),
         hmac_result, &hmac_len);

    char hmac_hex[EVP_MAX_MD_SIZE * 2 + 1];
    to_hex(hmac_result, hmac_len, hmac_hex, sizeof(hmac_hex));

    /* Final token: payload.signature */
    snprintf(out->token_str, sizeof(out->token_str), "%s.%s", b64_payload, hmac_hex);

    return SSO_OK;
}

sso_error_t token_verify(token_manager_t *mgr, const char *token_str, token_t *out) {
    if (!mgr || !token_str || !out) return SSO_ERR_INVALID_PARAM;

    memset(out, 0, sizeof(*out));
    strncpy(out->token_str, token_str, SSO_MAX_TOKEN_STR - 1);

    /* Split into payload and signature */
    const char *dot = strchr(token_str, '.');
    if (!dot) return SSO_ERR_TOKEN_INVALID;

    size_t b64_len = (size_t)(dot - token_str);
    char b64_payload[1536];
    strncpy(b64_payload, token_str, b64_len);
    b64_payload[b64_len] = '\0';

    const char *sig_hex = dot + 1;

    /* Verify signature */
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), mgr->secret, (int)sizeof(mgr->secret),
         (unsigned char *)b64_payload, strlen(b64_payload),
         hmac_result, &hmac_len);

    char expected_sig[EVP_MAX_MD_SIZE * 2 + 1];
    to_hex(hmac_result, hmac_len, expected_sig, sizeof(expected_sig));

    if (strcmp(sig_hex, expected_sig) != 0) {
        return SSO_ERR_TOKEN_INVALID;
    }

    /* Decode payload */
    unsigned char decoded[2048];
    size_t decoded_len = base64_decode(b64_payload, decoded, sizeof(decoded) - 1);
    if (decoded_len == 0) return SSO_ERR_TOKEN_INVALID;
    decoded[decoded_len] = '\0';

    const char *payload = (const char *)decoded;

    /* Extract fields (minimal JSON parsing) */
    const char *v;

    v = json_get_value(payload, "jti");
    if (v && *v == '"') {
        v++;
        const char *end = strchr(v, '"');
        if (end) {
            size_t len = (size_t)(end - v);
            if (len >= sizeof(out->jti)) len = sizeof(out->jti) - 1;
            strncpy(out->jti, v, len);
            out->jti[len] = '\0';
        }
    }

    v = json_get_value(payload, "sub");
    if (v) out->user_id = strtoull(v, NULL, 10);

    v = json_get_value(payload, "iat");
    if (v) out->issued_at = strtoll(v, NULL, 10);

    v = json_get_value(payload, "exp");
    if (v) out->expires_at = strtoll(v, NULL, 10);

    /* Check expiry */
    sso_timestamp_t now = sso_timestamp_now();
    if (now > out->expires_at) {
        return SSO_ERR_TOKEN_EXPIRED;
    }

    /* Extract roles array */
    v = json_get_value(payload, "roles");
    if (v) {
        if (*v == '[') {
            v++;
            sso_id_t roles[64];
            size_t rc = 0;
            while (*v && *v != ']' && rc < 64) {
                if (*v >= '0' && *v <= '9') {
                    roles[rc++] = strtoull(v, (char **)&v, 10);
                } else {
                    v++;
                }
            }
            if (rc > 0) {
                out->role_ids = (sso_id_t *)malloc(rc * sizeof(sso_id_t));
                if (out->role_ids) {
                    memcpy(out->role_ids, roles, rc * sizeof(sso_id_t));
                    out->role_count = rc;
                }
            }
        }
    }

    /* Extract groups array */
    v = json_get_value(payload, "groups");
    if (v) {
        if (*v == '[') {
            v++;
            sso_id_t groups[64];
            size_t gc = 0;
            while (*v && *v != ']' && gc < 64) {
                if (*v >= '0' && *v <= '9') {
                    groups[gc++] = strtoull(v, (char **)&v, 10);
                } else {
                    v++;
                }
            }
            if (gc > 0) {
                out->group_ids = (sso_id_t *)malloc(gc * sizeof(sso_id_t));
                if (out->group_ids) {
                    memcpy(out->group_ids, groups, gc * sizeof(sso_id_t));
                    out->group_count = gc;
                }
            }
        }
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
} revocations = {NULL, 0, 0, true};

static int compare_jtis(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

sso_error_t token_revoke(token_manager_t *mgr, const char *jti) {
    (void)mgr;
    if (!jti) return SSO_ERR_INVALID_PARAM;

    /* Lazily initialise the array */
    if (revocations.jtis == NULL) {
        revocations.jtis = (char (*)[REVOCATION_STR_LEN])calloc(
            REVOCATIONS_INIT_CAP, REVOCATION_STR_LEN);
        if (!revocations.jtis) return SSO_ERR_OUT_OF_MEMORY;
        revocations.capacity = REVOCATIONS_INIT_CAP;
    }

    /* Grow if full */
    if (revocations.count >= revocations.capacity) {
        size_t new_cap = revocations.capacity * 2;
        char (*new_jtis)[REVOCATION_STR_LEN] = (char (*)[REVOCATION_STR_LEN])realloc(
            revocations.jtis, new_cap * REVOCATION_STR_LEN);
        if (!new_jtis) return SSO_ERR_OUT_OF_MEMORY;
        revocations.jtis = new_jtis;
        revocations.capacity = new_cap;
    }

    strncpy(revocations.jtis[revocations.count], jti, REVOCATION_STR_LEN - 1);
    revocations.jtis[revocations.count][REVOCATION_STR_LEN - 1] = '\0';
    revocations.count++;
    revocations.sorted = false;
    return SSO_OK;
}

bool token_is_revoked(token_manager_t *mgr, const char *jti) {
    (void)mgr;
    if (!jti || !revocations.jtis || revocations.count == 0) return false;

    if (!revocations.sorted) {
        qsort(revocations.jtis, revocations.count, REVOCATION_STR_LEN, compare_jtis);
        revocations.sorted = true;
    }

    return bsearch(jti, revocations.jtis, revocations.count, REVOCATION_STR_LEN, compare_jtis) != NULL;
}
