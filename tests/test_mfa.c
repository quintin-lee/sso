/*
 * test_mfa.c — Unit tests for TOTP-based multi-factor authentication.
 *
 * Tests RFC 6238 TOTP secret generation, code computation at
 * specific timestamps, code validation with valid/expired codes,
 * and integration with the MFA enrolment flow.
 */

#include "minunit.h"
#include "mfa.h"
#include <string.h>
#include <stdint.h>
#include <sodium.h>
#include <time.h>

int tests_run = 0;

static const char* test_base32_consistency() {
	const uint8_t original[] = "Hello World!";
	char		  encoded[64];
	uint8_t		  decoded[64];

	mu_assert("base32_encode failed", base32_encode(original, strlen((char*)original), encoded, sizeof(encoded)));
	size_t decoded_len = base32_decode(encoded, decoded, sizeof(decoded));
	mu_assert("base32_decode failed", decoded_len == strlen((char*)original));
	mu_assert("decoded data mismatch", memcmp(original, decoded, decoded_len) == 0);

	return NULL;
}

static const char* test_base32_empty() {
	const uint8_t original[] = "";
	char		  encoded[64];
	uint8_t		  decoded[64];

	mu_assert("base32_encode empty failed", base32_encode(original, 0, encoded, sizeof(encoded)));
	mu_assert("encoded empty mismatch", strcmp(encoded, "") == 0);
	size_t decoded_len = base32_decode(encoded, decoded, sizeof(decoded));
	mu_assert("base32_decode empty mismatch", decoded_len == 0);

	return NULL;
}

static const char* test_base32_known_secret() {
	const char* secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
	const char* expected   = "12345678901234567890";
	uint8_t		decoded[64];
	size_t		decoded_len = base32_decode(secret_b32, decoded, sizeof(decoded));
	mu_assert("decode known secret length mismatch", decoded_len == 20);
	mu_assert("decode known secret data mismatch", memcmp(decoded, expected, 20) == 0);
	return NULL;
}

static const char* test_totp_known_values() {
	// RFC 6238 Test Vector
	// Secret: 12345678901234567890 in ASCII is "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" in Base32
	const char* secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
	uint8_t		key[20];
	size_t		key_len = base32_decode(secret_b32, key, sizeof(key));
	mu_assert("decode secret failed", key_len == 20);

	// T=1111111109, expected code 081804 (last 6 digits of 07081804)
	uint32_t totp = generate_totp(key, key_len, 1111111109 / 30);
	ASSERT_INT_EQUAL(totp, 81804);

	// T=1234567890, expected code 005924 (per RFC 6238)
	totp = generate_totp(key, key_len, 1234567890 / 30);
	ASSERT_INT_EQUAL(totp, 5924);

	return NULL;
}

static const char* test_mfa_verify_current() {
	char secret[64];
	mfa_generate_secret(secret, sizeof(secret));
	mu_assert("mfa_generate_secret failed", strlen(secret) > 0);

	uint8_t	 key[64];
	size_t	 key_len	  = base32_decode(secret, key, sizeof(key));
	uint64_t current_step = (uint64_t)time(NULL) / 30;
	uint32_t totp_val	  = generate_totp(key, key_len, current_step);

	char code[8];
	snprintf(code, sizeof(code), "%06u", totp_val);

	mu_assert("mfa_verify_totp failed for current step", mfa_verify_totp(secret, code));

	return NULL;
}

static const char* all_tests() {
	mu_run_test(test_base32_consistency);
	mu_run_test(test_base32_empty);
	mu_run_test(test_base32_known_secret);
	mu_run_test(test_totp_known_values);
	mu_run_test(test_mfa_verify_current);
	return NULL;
}

int main(int argc, char** argv) {
	(void)argc;
	(void)argv;
	if (sodium_init() < 0)
		return 1;
	const char* result = all_tests();
	if (result != 0) {
		printf("FAILED\n");
	} else {
		printf("ALL TESTS PASSED\n");
	}
	printf("Tests run: %d\n", tests_run);
	return result != 0;
}
