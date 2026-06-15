#ifndef SSO_MFA_H
#define SSO_MFA_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mfa_generate_secret(char *base32_out, size_t out_len);
bool mfa_verify_totp(const char *base32_secret, const char *code);

// Exposed for testing
bool base32_encode(const uint8_t *data, size_t length, char *result, size_t max_len);
size_t base32_decode(const char *encoded, uint8_t *result, size_t max_len);
uint32_t generate_totp(const uint8_t *key, size_t key_len, uint64_t time_step);

#ifdef __cplusplus
}
#endif
#endif
