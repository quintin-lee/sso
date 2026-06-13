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

    /* Build the token payload using cJSON */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "jti", out->jti);
    cJSON_AddNumberToObject(root, "sub", (double)out->user_id);
    cJSON_AddNumberToObject(root, "iat", (double)out->issued_at);
    cJSON_AddNumberToObject(root, "exp", (double)out->expires_at);

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

    /* Base64-encode the payload */
    char b64_payload[2048];
    base64_encode((unsigned char *)payload_str, strlen(payload_str), b64_payload, sizeof(b64_payload));
    free(payload_str);

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
    char b64_payload[2048];
    if (b64_len >= sizeof(b64_payload)) return SSO_ERR_TOKEN_INVALID;
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
    unsigned char decoded[4096];
    size_t decoded_len = base64_decode(b64_payload, decoded, sizeof(decoded) - 1);
    if (decoded_len == 0) return SSO_ERR_TOKEN_INVALID;
    decoded[decoded_len] = '\0';

    /* Extract fields using cJSON */
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

    /* Roles */
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

    /* Groups */
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
