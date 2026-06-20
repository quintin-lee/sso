#include "dpop.h"
#include "cJSON.h"
#include "logger.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

/* These functions are in token.c */
extern size_t base64url_decode(const char *input, unsigned char *output, size_t output_len);
extern size_t base64url_encode(const unsigned char *input, size_t len, char *output, size_t output_len);

static int str_case_equals(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower(*a) != tolower(*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

sso_error_t dpop_verify_proof(const char *dpop_proof, const char *method, const char *url, 
                              const char *expected_jkt, char *out_jkt) {
    if (!dpop_proof || !method || !url || !out_jkt) return SSO_ERR_INVALID_PARAM;
    out_jkt[0] = '\0';

    char *proof = strdup(dpop_proof);
    if (!proof) return SSO_ERR_OUT_OF_MEMORY;

    char *dot1 = strchr(proof, '.');
    if (!dot1) { free(proof); return SSO_ERR_TOKEN_INVALID; }
    *dot1 = '\0';
    
    char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) { free(proof); return SSO_ERR_TOKEN_INVALID; }
    *dot2 = '\0';

    const char *hdr_b64 = proof;
    const char *pld_b64 = dot1 + 1;
    const char *sig_b64 = dot2 + 1;

    size_t hdr_len = strlen(hdr_b64);
    unsigned char *hdr_bin = malloc(hdr_len);
    size_t hdr_bin_len = base64url_decode(hdr_b64, hdr_bin, hdr_len);
    hdr_bin[hdr_bin_len] = '\0';

    size_t pld_len = strlen(pld_b64);
    unsigned char *pld_bin = malloc(pld_len);
    size_t pld_bin_len = base64url_decode(pld_b64, pld_bin, pld_len);
    pld_bin[pld_bin_len] = '\0';

    cJSON *hdr_json = cJSON_Parse((const char *)hdr_bin);
    cJSON *pld_json = cJSON_Parse((const char *)pld_bin);

    sso_error_t result = SSO_ERR_TOKEN_INVALID;
    EVP_PKEY *pkey = NULL;
    char *sign_input = NULL;

    if (!hdr_json || !pld_json) goto cleanup;

    /* 1. Verify Header */
    cJSON *typ = cJSON_GetObjectItem(hdr_json, "typ");
    if (!typ || !cJSON_IsString(typ) || !str_case_equals(typ->valuestring, "dpop+jwt")) {
        LOG_WARN("[dpop] Invalid typ");
        goto cleanup;
    }

    cJSON *alg = cJSON_GetObjectItem(hdr_json, "alg");
    if (!alg || !cJSON_IsString(alg) || strcmp(alg->valuestring, "RS256") != 0) {
        LOG_WARN("[dpop] Only RS256 is supported currently");
        goto cleanup;
    }

    cJSON *jwk = cJSON_GetObjectItem(hdr_json, "jwk");
    if (!jwk || !cJSON_IsObject(jwk)) goto cleanup;

    cJSON *kty = cJSON_GetObjectItem(jwk, "kty");
    cJSON *n_val = cJSON_GetObjectItem(jwk, "n");
    cJSON *e_val = cJSON_GetObjectItem(jwk, "e");
    if (!kty || !cJSON_IsString(kty) || strcmp(kty->valuestring, "RSA") != 0 ||
        !n_val || !cJSON_IsString(n_val) || !e_val || !cJSON_IsString(e_val)) {
        goto cleanup;
    }

    /* 2. Compute JWK Thumbprint (jkt) */
    char canonical_jwk[2048];
    snprintf(canonical_jwk, sizeof(canonical_jwk), "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}", e_val->valuestring, n_val->valuestring);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)canonical_jwk, strlen(canonical_jwk), hash);
    base64url_encode(hash, SHA256_DIGEST_LENGTH, out_jkt, 64);

    if (expected_jkt && strcmp(expected_jkt, out_jkt) != 0) {
        LOG_WARN("[dpop] Expected jkt %s does not match computed %s", expected_jkt, out_jkt);
        goto cleanup;
    }

    /* 3. Verify Payload */
    cJSON *htm = cJSON_GetObjectItem(pld_json, "htm");
    cJSON *htu = cJSON_GetObjectItem(pld_json, "htu");
    cJSON *iat = cJSON_GetObjectItem(pld_json, "iat");

    if (!htm || !cJSON_IsString(htm) || !str_case_equals(htm->valuestring, method)) {
        LOG_WARN("[dpop] Method mismatch");
        goto cleanup;
    }
    
    if (!htu || !cJSON_IsString(htu)) goto cleanup;
    /* Basic URL matching (should ideally strip query parameters if needed) */
    if (strncmp(htu->valuestring, url, strlen(url)) != 0) {
        LOG_WARN("[dpop] URL mismatch");
        goto cleanup;
    }

    if (!iat || !cJSON_IsNumber(iat)) goto cleanup;
    sso_timestamp_t now = sso_timestamp_now();
    sso_timestamp_t iat_ms = (sso_timestamp_t)(iat->valuedouble * 1000.0);
    if (iat_ms > now + 300000 || iat_ms < now - 300000) {
        LOG_WARN("[dpop] Token expired or generated in the future");
        goto cleanup;
    }

    /* 4. Signature Verification */
    size_t n_len = strlen(n_val->valuestring);
    unsigned char *n_bin = malloc(n_len);
    size_t n_bin_len = base64url_decode(n_val->valuestring, n_bin, n_len);
    
    size_t e_len = strlen(e_val->valuestring);
    unsigned char *e_bin = malloc(e_len);
    size_t e_bin_len = base64url_decode(e_val->valuestring, e_bin, e_len);

    BIGNUM *bn_n = BN_bin2bn(n_bin, n_bin_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e_bin, e_bin_len, NULL);
    free(n_bin); free(e_bin);

    RSA *rsa = RSA_new();
    if (!rsa || !bn_n || !bn_e) {
        if (bn_n) BN_free(bn_n);
        if (bn_e) BN_free(bn_e);
        if (rsa) RSA_free(rsa);
        goto cleanup;
    }
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = bn_n;
    rsa->e = bn_e;
#else
    RSA_set0_key(rsa, bn_n, bn_e, NULL);
#endif

    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    size_t sig_len = strlen(sig_b64);
    unsigned char *sig_bin = malloc(sig_len);
    size_t sig_bin_len = base64url_decode(sig_b64, sig_bin, sig_len);

    sign_input = (char *)malloc(8192);
    if (!sign_input) { free(sig_bin); goto cleanup; }
    snprintf(sign_input, 8192, "%s.%s", hdr_b64, pld_b64);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(md_ctx); free(sig_bin); goto cleanup;
    }
    EVP_DigestVerifyUpdate(md_ctx, sign_input, strlen(sign_input));
    int v_ret = EVP_DigestVerifyFinal(md_ctx, sig_bin, sig_bin_len);
    EVP_MD_CTX_free(md_ctx);
    free(sig_bin);

    if (v_ret == 1) {
        result = SSO_OK;
    } else {
        LOG_WARN("[dpop] Invalid signature");
    }

cleanup:
    if (hdr_json) cJSON_Delete(hdr_json);
    if (pld_json) cJSON_Delete(pld_json);
    if (pkey) EVP_PKEY_free(pkey);
    free(hdr_bin);
    free(pld_bin);
    free(proof);
    free(sign_input);
    return result;
}
