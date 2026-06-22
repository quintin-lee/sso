/*
 * webauthn.c — WebAuthn / FIDO2 credential verification implementation.
 *
 * Provides the low-level cryptographic verification routines for
 * WebAuthn authenticator assertions: challenge generation, attestation
 * object parsing, signature verification over the clientDataJSON and
 * authenticatorData using ECDSA (P-256) public keys, and Base64URL
 * encoding/decoding helpers used throughout the WebAuthn flow.
 */

#include "webauthn.h"
#include "logger.h"
#include "intern.h"
#include "yyjson.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <string.h>

/* Base64URL encode/decode helpers */
static size_t b64u_encode(const unsigned char* in, size_t in_len, char* out) {
	static const char basis64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t			  out_len	= 0;
	for (size_t i = 0; i < in_len; i += 3) {
		unsigned char b1 = in[i];
		unsigned char b2 = (i + 1 < in_len) ? in[i + 1] : 0;
		unsigned char b3 = (i + 2 < in_len) ? in[i + 2] : 0;
		out[out_len++]	 = basis64[b1 >> 2];
		out[out_len++]	 = basis64[((b1 & 0x03) << 4) | (b2 >> 4)];
		if (i + 1 < in_len)
			out[out_len++] = basis64[((b2 & 0x0f) << 2) | (b3 >> 6)];
		if (i + 2 < in_len)
			out[out_len++] = basis64[b3 & 0x3f];
	}
	out[out_len] = '\0';
	return out_len;
}

static size_t b64u_decode(const char* in, unsigned char* out) {
	size_t in_len  = strlen(in);
	size_t out_len = 0;
	int	   bits = 0, char_count = 0;
	for (size_t i = 0; i < in_len; i++) {
		int c = in[i];
		if (c == '=')
			break;
		if (c >= 'A' && c <= 'Z')
			c -= 'A';
		else if (c >= 'a' && c <= 'z')
			c = c - 'a' + 26;
		else if (c >= '0' && c <= '9')
			c = c - '0' + 52;
		else if (c == '-' || c == '+')
			c = 62;
		else if (c == '_' || c == '/')
			c = 63;
		else
			continue;
		bits = (bits << 6) | c;
		char_count++;
		if (char_count == 4) {
			out[out_len++] = (bits >> 16) & 0xff;
			out[out_len++] = (bits >> 8) & 0xff;
			out[out_len++] = bits & 0xff;
			bits		   = 0;
			char_count	   = 0;
		}
	}
	if (char_count == 2)
		out[out_len++] = (bits >> 4) & 0xff;
	else if (char_count == 3) {
		out[out_len++] = (bits >> 10) & 0xff;
		out[out_len++] = (bits >> 2) & 0xff;
	}
	return out_len;
}

char* webauthn_generate_challenge(void) {
	unsigned char buf[32];
	RAND_bytes(buf, sizeof(buf));
	char* b64 = malloc(64);
	if (b64)
		b64u_encode(buf, sizeof(buf), b64);
	return b64;
}

/* Helper to extract authData from CBOR attestationObject via simple pattern matching */
static const unsigned char* find_auth_data(const unsigned char* cbor, size_t len, size_t* out_len) {
	/* look for "authData" string: 0x68 'a' 'u' 't' 'h' 'D' 'a' 't' 'a' */
	static const unsigned char authData_key[] = {0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'};
	for (size_t i = 0; i < len - sizeof(authData_key); i++) {
		if (memcmp(cbor + i, authData_key, sizeof(authData_key)) == 0) {
			size_t p = i + sizeof(authData_key);
			if (p >= len)
				return NULL;
			/* Read CBOR Byte String header */
			int type = cbor[p] >> 5;
			if (type != 2)
				continue;
			int val = cbor[p] & 0x1f;
			p++;
			size_t data_len = 0;
			if (val < 24) {
				data_len = val;
			} else if (val == 24 && p < len) {
				data_len = cbor[p++];
			} else if (val == 25 && p + 1 < len) {
				data_len = (cbor[p] << 8) | cbor[p + 1];
				p += 2;
			} else
				return NULL;

			if (p + data_len <= len) {
				*out_len = data_len;
				return cbor + p;
			}
		}
	}
	return NULL;
}

/* Simple COSE key extraction: searches for X (-2) and Y (-3) coordinates of P-256 */
static sso_error_t extract_cose_ec2_key(const unsigned char* cose_cbor, size_t len, char** out_pem) {
	/* We expect a CBOR map. We just scan for 0x21 (key -2 for X) and 0x22 (key -3 for Y) followed by 32 bytes */
	const unsigned char* x = NULL;
	const unsigned char* y = NULL;
	for (size_t i = 0; i < len - 34; i++) {
		if (cose_cbor[i] == 0x21 && cose_cbor[i + 1] == 0x58 && cose_cbor[i + 2] == 0x20) {
			x = cose_cbor + i + 3;
		}
		if (cose_cbor[i] == 0x22 && cose_cbor[i + 1] == 0x58 && cose_cbor[i + 2] == 0x20) {
			y = cose_cbor + i + 3;
		}
	}
	if (!x || !y)
		return SSO_ERR_TOKEN_INVALID;

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

	EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	BIGNUM* bn_x  = BN_bin2bn(x, 32, NULL);
	BIGNUM* bn_y  = BN_bin2bn(y, 32, NULL);
	EC_KEY_set_public_key_affine_coordinates(eckey, bn_x, bn_y);
	BN_free(bn_x);
	BN_free(bn_y);

	EVP_PKEY* pkey = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(pkey, eckey);

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(bio, pkey);

	char* pem_data = NULL;
	long  pem_len  = BIO_get_mem_data(bio, &pem_data);
	*out_pem	   = malloc(pem_len + 1);
	memcpy(*out_pem, pem_data, pem_len);
	(*out_pem)[pem_len] = '\0';

	BIO_free(bio);
	EVP_PKEY_free(pkey);
	return SSO_OK;
}

static sso_error_t verify_client_data(const unsigned char* client_data_raw, size_t len, const char* expected_challenge,
									  const char* expected_origin) {
	yyjson_doc* doc = yyjson_read((const char*)client_data_raw, len, 0);
	if (!doc)
		return SSO_ERR_INVALID_PARAM;
	yyjson_val* root	  = yyjson_doc_get_root(doc);
	const char* challenge = yyjson_get_str(yyjson_obj_get(root, "challenge"));
	const char* origin	  = yyjson_get_str(yyjson_obj_get(root, "origin"));
	sso_error_t err		  = SSO_OK;
	if (!challenge || !origin || strcmp(challenge, expected_challenge) != 0 || strcmp(origin, expected_origin) != 0) {
		LOG_ERROR("[webauthn] client_data mismatch. expected ch=%s, or=%s", expected_challenge, expected_origin);
		err = SSO_ERR_AUTH_FAILED;
	}
	yyjson_doc_free(doc);
	return err;
}

sso_error_t webauthn_register_verify(const char* attestation_b64u, const char* client_data_b64u,
									 const char* expected_challenge, const char* expected_origin,
									 char** out_credential_id_b64u, char** out_public_key_pem) {
	unsigned char* att		 = malloc(strlen(attestation_b64u));
	size_t		   att_len	 = b64u_decode(attestation_b64u, att);
	unsigned char* cdata	 = malloc(strlen(client_data_b64u));
	size_t		   cdata_len = b64u_decode(client_data_b64u, cdata);

	sso_error_t err = verify_client_data(cdata, cdata_len, expected_challenge, expected_origin);
	if (err != SSO_OK)
		goto end;

	size_t				 auth_data_len = 0;
	const unsigned char* auth_data	   = find_auth_data(att, att_len, &auth_data_len);
	if (!auth_data || auth_data_len < 37) {
		err = SSO_ERR_INVALID_PARAM;
		goto end;
	}

	/* Parse authData */
	unsigned char flags = auth_data[32];
	if (!(flags & 0x40)) {
		err = SSO_ERR_INVALID_PARAM;
		goto end;
	} /* Attested credential data flag must be set */

	size_t p = 37; /* RPID Hash (32) + Flags (1) + SignCount (4) */
	p += 16;	   /* AAGUID */
	if (p + 2 > auth_data_len) {
		err = SSO_ERR_INVALID_PARAM;
		goto end;
	}

	int cred_len = (auth_data[p] << 8) | auth_data[p + 1];
	p += 2;
	if (p + cred_len > auth_data_len) {
		err = SSO_ERR_INVALID_PARAM;
		goto end;
	}

	char* cred_b64u = malloc(cred_len * 2 + 1);
	b64u_encode(auth_data + p, cred_len, cred_b64u);
	*out_credential_id_b64u = cred_b64u;
	p += cred_len;

	err = extract_cose_ec2_key(auth_data + p, auth_data_len - p, out_public_key_pem);

end:
	free(att);
	free(cdata);
	return err;
}

sso_error_t webauthn_login_verify(const char* authenticator_data_b64u, const char* client_data_b64u,
								  const char* signature_b64u, const char* expected_challenge,
								  const char* expected_origin, const char* public_key_pem) {
	unsigned char* authData		= malloc(strlen(authenticator_data_b64u));
	size_t		   authData_len = b64u_decode(authenticator_data_b64u, authData);

	unsigned char* cdata	 = malloc(strlen(client_data_b64u));
	size_t		   cdata_len = b64u_decode(client_data_b64u, cdata);

	unsigned char* sig	   = malloc(strlen(signature_b64u));
	size_t		   sig_len = b64u_decode(signature_b64u, sig);

	sso_error_t err = verify_client_data(cdata, cdata_len, expected_challenge, expected_origin);
	if (err != SSO_OK)
		goto end;

	unsigned char cdata_hash[32];
	SHA256(cdata, cdata_len, cdata_hash);

	/* Construct signed data: authData || SHA256(clientData) */
	unsigned char* signed_data = malloc(authData_len + 32);
	memcpy(signed_data, authData, authData_len);
	memcpy(signed_data + authData_len, cdata_hash, 32);
	size_t signed_data_len = authData_len + 32;

	/* Verify signature */
	BIO*	  bio  = BIO_new_mem_buf(public_key_pem, -1);
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (!pkey) {
		err = SSO_ERR_GENERAL;
		free(signed_data);
		goto end;
	}

	EVP_MD_CTX* mctx = EVP_MD_CTX_new();
	EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey);
	EVP_DigestVerifyUpdate(mctx, signed_data, signed_data_len);
	int res = EVP_DigestVerifyFinal(mctx, sig, sig_len);
	EVP_MD_CTX_free(mctx);
	EVP_PKEY_free(pkey);
	free(signed_data);

	if (res != 1) {
		LOG_WARN("[webauthn] Invalid assertion signature!");
		err = SSO_ERR_AUTH_FAILED;
	}

end:
	free(authData);
	free(cdata);
	free(sig);
	return err;
}
