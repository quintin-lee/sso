#include "mfa.h"
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sodium.h>

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

bool base32_encode(const uint8_t *data, size_t length, char *result, size_t max_len) {
    uint32_t buffer = 0;
    int bits_left = 0;
    size_t out_pos = 0;
    
    for (size_t i = 0; i < length; i++) {
        buffer = (buffer << 8) | data[i];
        bits_left += 8;
        while (bits_left >= 5) {
            if (out_pos + 1 >= max_len) return false;
            result[out_pos++] = base32_chars[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
        buffer &= (1 << bits_left) - 1;
    }
    
    if (bits_left > 0) {
        if (out_pos + 1 >= max_len) return false;
        result[out_pos++] = base32_chars[(buffer << (5 - bits_left)) & 0x1F];
    }
    
    result[out_pos] = '\0';
    return true;
}

size_t base32_decode(const char *encoded, uint8_t *result, size_t max_len) {
    uint32_t buffer = 0;
    int bits_left = 0;
    size_t length = 0;
    
    while (*encoded) {
        char c = *encoded++;
        uint8_t val = 0;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            val = (c >= 'A' && c <= 'Z') ? (c - 'A') : (c - 'a');
        } else if (c >= '2' && c <= '7') {
            val = c - '2' + 26;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-') {
            continue;
        } else {
            continue;
        }
        
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if (bits_left >= 8) {
            if (length >= max_len) return 0;
            result[length++] = (buffer >> (bits_left - 8)) & 0xFF;
            bits_left -= 8;
        }
        buffer &= (1 << bits_left) - 1;
    }
    
    return length;
}

void mfa_generate_secret(char *base32_out, size_t out_len) {
    uint8_t raw[20];
    randombytes_buf(raw, sizeof(raw));
    if (!base32_encode(raw, sizeof(raw), base32_out, out_len)) {
        if (out_len > 0) base32_out[0] = '\0';
    }
}

uint32_t generate_totp(const uint8_t *key, size_t key_len, uint64_t time_step) {
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) {
        msg[i] = (uint8_t)(time_step & 0xFF);
        time_step >>= 8;
    }
    
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (HMAC(EVP_sha1(), key, key_len, msg, sizeof(msg), hash, &hash_len) == NULL) {
        return 0;
    }
    
    int offset = hash[19] & 0x0F;
    uint32_t binary = ((hash[offset] & 0x7F) << 24) |
                      ((hash[offset + 1] & 0xFF) << 16) |
                      ((hash[offset + 2] & 0xFF) << 8) |
                      (hash[offset + 3] & 0xFF);
    return binary % 1000000;
}

bool mfa_verify_totp(const char *base32_secret, const char *code) {
    if (!base32_secret || !code || strlen(code) != 6) return false;
    uint8_t key[64];
    size_t key_len = base32_decode(base32_secret, key, sizeof(key));
    if (key_len == 0) return false;
    
    uint64_t current_step = (uint64_t)time(NULL) / 30;
    
    for (int i = -1; i <= 1; i++) {
        uint32_t expected = generate_totp(key, key_len, current_step + i);
        char expected_str[8];
        snprintf(expected_str, sizeof(expected_str), "%06u", expected);
        
        if (sodium_memcmp(expected_str, code, 6) == 0) {
            return true;
        }
    }
    
    return false;
}
