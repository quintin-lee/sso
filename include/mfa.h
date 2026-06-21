/*
 * mfa.h — Multi-Factor Authentication (TOTP) support.
 *
 * Implements RFC 6238 TOTP (Time-Based One-Time Password) using HMAC-SHA1.
 * The server generates a base32-encoded TOTP secret, the user scans it in
 * an authenticator app (Google / Microsoft / Authy), and subsequently sends
 * the 6-digit code as a second factor during login.
 *
 * The base32 encode/decode and TOTP primitives are exposed for testing.
 */

#ifndef SSO_MFA_H
#define SSO_MFA_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a random TOTP secret and encode it as base32.
 * @param base32_out  Buffer to hold the base32-encoded secret.
 * @param out_len     Capacity of output buffer (should be >= 64).
 */
void mfa_generate_secret(char *base32_out, size_t out_len);

/**
 * @brief Verify a 6-digit TOTP code against the stored base32 secret.
 * @param base32_secret  The base32-encoded TOTP secret.
 * @param code           The 6-digit code provided by the user.
 * @return true if the code is valid.
 */
bool mfa_verify_totp(const char *base32_secret, const char *code);

/* ── Primitives exposed for unit testing ── */

/** Encode raw bytes as base32 (RFC 4648). */
bool base32_encode(const uint8_t *data, size_t length, char *result, size_t max_len);
/** Decode a base32 string back to raw bytes. */
size_t base32_decode(const char *encoded, uint8_t *result, size_t max_len);
/** Generate the TOTP value for a given key at a UNIX time step. */
uint32_t generate_totp(const uint8_t *key, size_t key_len, uint64_t time_step);

#ifdef __cplusplus
}
#endif
#endif
