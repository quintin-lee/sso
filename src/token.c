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
#include "storage.h"
#include "user.h"
#include "yyjson.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "logger.h"
#include "intern.h"

#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sodium.h>
#include <pthread.h>

/* --- yyjson replaces cJSON for faster serialization --- */

/*           ==
 * Internal helpers
 *           == */

static void to_hex(const unsigned char* bin, size_t len, char* hex, size_t hex_len) {
	char* p = hex;
	for (size_t i = 0; i < len && p < hex + hex_len - 3; i++) {
		p += snprintf(p, hex_len - (size_t)(p - hex), "%02x", bin[i]);
	}
	*p = '\0';
}

/* ---- Base64url (RFC 4648 §5): URL-safe, no padding ---- */
static const char b64url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t base64url_encode(const unsigned char* input, size_t len, char* output, size_t output_len) {
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
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '-' || c == '+')
		return 62;
	if (c == '_' || c == '/')
		return 63;
	return -1;
}

size_t base64url_decode(const char* input, unsigned char* output, size_t output_len) {
	size_t i = 0, o = 0;
	size_t len = strlen(input);
	while (i < len && o < output_len) {
		int a = b64url_rev(input[i]);
		if (a < 0)
			break;
		int b = (i + 1 < len) ? b64url_rev(input[i + 1]) : -1;
		if (b < 0)
			break;
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
static bool is_hex_str(const char* s) {
	if (!s || !*s)
		return false;
	while (*s) {
		if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')))
			return false;
		s++;
	}
	return true;
}

/*           ==
 * Lifecycle
 *           == */
sso_error_t token_manager_init(token_manager_t* mgr, const unsigned char* secret, size_t secret_len,
							   sso_timestamp_t default_ttl_ms) {
	if (!mgr || !secret || secret_len == 0)
		return SSO_ERR_INVALID_PARAM;

	memset(mgr, 0, sizeof(*mgr));
	mgr->mode = SSO_TOKEN_MODE_HS256;

	size_t copy_len = secret_len < sizeof(mgr->keys.secret) ? secret_len : sizeof(mgr->keys.secret);
	memcpy(mgr->keys.secret, secret, copy_len);
	if (sodium_mlock(mgr->keys.secret, sizeof(mgr->keys.secret)) != 0) {
	}
	mgr->default_ttl_ms = default_ttl_ms;
	pthread_mutex_init(&mgr->nonce_lock, NULL);
	pthread_mutex_init(&mgr->rev_lock, NULL);
	pthread_mutex_init(&mgr->session_lock, NULL);
	return SSO_OK;
}

sso_error_t token_manager_init_rs256(token_manager_t* mgr, const char* priv_key_pem, const char* pub_key_pem,
									 sso_timestamp_t default_ttl_ms) {
	if (!mgr || !priv_key_pem)
		return SSO_ERR_INVALID_PARAM;

	memset(mgr, 0, sizeof(*mgr));
	mgr->mode			= SSO_TOKEN_MODE_RS256;
	mgr->default_ttl_ms = default_ttl_ms;
	pthread_mutex_init(&mgr->nonce_lock, NULL);
	pthread_mutex_init(&mgr->rev_lock, NULL);
	pthread_mutex_init(&mgr->session_lock, NULL);

	/* Load private key */
	BIO* priv_bio = BIO_new_mem_buf(priv_key_pem, -1);
	if (!priv_bio) {
		return SSO_ERR_INIT;
	}
	mgr->keys.rsa.priv_key = (void*)PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
	BIO_free(priv_bio);

	if (!mgr->keys.rsa.priv_key) {
		return SSO_ERR_INIT;
	}

	/* Load public key if provided, otherwise derive it from private */
	if (pub_key_pem) {
		BIO* pub_bio		  = BIO_new_mem_buf(pub_key_pem, -1);
		mgr->keys.rsa.pub_key = (void*)PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
		BIO_free(pub_bio);
	} else {
		/* Extract public key from private key */
		BIO* pub_bio = BIO_new(BIO_s_mem());
		if (PEM_write_bio_PUBKEY(pub_bio, (EVP_PKEY*)mgr->keys.rsa.priv_key)) {
			mgr->keys.rsa.pub_key = (void*)PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
		}
		BIO_free(pub_bio);
	}

	if (!mgr->keys.rsa.pub_key) {
		EVP_PKEY_free((EVP_PKEY*)mgr->keys.rsa.priv_key);
		mgr->keys.rsa.priv_key = NULL;
		return SSO_ERR_INIT;
	}

	return SSO_OK;
}

char* token_manager_get_public_key_pem(token_manager_t* mgr) {
	if (!mgr || mgr->mode != SSO_TOKEN_MODE_RS256 || !mgr->keys.rsa.pub_key)
		return NULL;

	BIO* bio = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_PUBKEY(bio, (EVP_PKEY*)mgr->keys.rsa.pub_key)) {
		BIO_free(bio);
		return NULL;
	}

	char* buf;
	long  len = BIO_get_mem_data(bio, &buf);
	char* ret = (char*)malloc((size_t)len + 1);
	if (ret) {
		memcpy(ret, buf, (size_t)len);
		ret[len] = '\0';
	}

	BIO_free(bio);
	return ret;
}

void token_manager_destroy(token_manager_t* mgr) {
	if (!mgr)
		return;

	if (mgr->mode == SSO_TOKEN_MODE_HS256) {
		/* Securely wipe the HMAC key before freeing. */
		sodium_memzero(mgr->keys.secret, sizeof(mgr->keys.secret));
		sodium_munlock(mgr->keys.secret, sizeof(mgr->keys.secret));
	} else {
		if (mgr->keys.rsa.priv_key)
			EVP_PKEY_free((EVP_PKEY*)mgr->keys.rsa.priv_key);
		if (mgr->keys.rsa.pub_key)
			EVP_PKEY_free((EVP_PKEY*)mgr->keys.rsa.pub_key);
	}

	free(mgr->nonces);
	mgr->nonces = NULL;
	pthread_mutex_destroy(&mgr->nonce_lock);

	/* Free revocation blocklist */
	free(mgr->jtis);
	mgr->jtis = NULL;
	pthread_mutex_destroy(&mgr->rev_lock);

	/* Free session trackers */
	free(mgr->sessions);
	mgr->sessions = NULL;
	pthread_mutex_destroy(&mgr->session_lock);

	free(mgr);
}

void token_destroy(token_t* token) {
	if (!token)
		return;
	free(token->role_ids);
	token->role_ids	  = NULL;
	token->role_count = 0;
	free(token->group_ids);
	token->group_ids   = NULL;
	token->group_count = 0;
}

/*           ==
 * Token operations
 *           == */
/**
 * @brief Issues a new JWT token signed symmetrically or asymmetrically.
 *
 * Flow:
 * 1. Initialize output token structure and populate timestamps and counters.
 * 2. Generate a unique JTI (UUID) using a combination of timestamps and cryptographically secure random bytes.
 * 3. Construct and serialize the JSON Header (stating RS256/HS256 algorithms).
 * 4. Construct and serialize the JSON Payload containing standard JWT claims (sub, exp, iat, jti),
 *    plus application claims (nonce/tnc, roles, groups, scopes).
 * 5. Base64url-encode both segments, concat them as "header.payload".
 * 6. Generate 32 bytes of cryptographically secure random bytes for a refresh token.
 * 7. Compute signature using HMAC-SHA256 (symmetrically) or RSA-SHA256 (asymmetrically)
 *    and append as "header.payload.signature".
 */
sso_error_t token_issue(token_manager_t* mgr, const user_t* user, const sso_id_t* role_ids, size_t role_count,
						const sso_id_t* group_ids, size_t group_count, const char* scope, sso_timestamp_t ttl_ms,
						const char* dpop_jkt, token_t* out) {
	if (!mgr || !user || !out)
		return SSO_ERR_INVALID_PARAM;
	atomic_fetch_add(&g_metric_jwt_issue, 1);

	memset(out, 0, sizeof(*out));

	if (dpop_jkt && dpop_jkt[0]) {
		sso_strlcpy(out->jkt, dpop_jkt, sizeof(out->jkt));
	}

	out->user_id   = user->id;
	out->issued_at = sso_timestamp_now();
	/* Handle custom TTL or fallback to manager default TTL */
	long long actual_ttl = (ttl_ms > 0) ? ttl_ms : (ttl_ms == 0 ? mgr->default_ttl_ms : ttl_ms);
	out->expires_at		 = out->issued_at + actual_ttl;
	out->role_count		 = role_count;
	out->group_count	 = group_count;
	out->nonce			 = token_get_nonce(mgr, user->id);

	if (scope) {
		sso_strlcpy(out->scope, scope, sizeof(out->scope));
	}

	/* Generate cryptographically secure random bytes for JTI uniqueness */
	unsigned char rand_bytes[8];
	randombytes_buf(rand_bytes, sizeof(rand_bytes));
	snprintf(out->jti, sizeof(out->jti), "%llx%02x%02x%02x%02x%02x%02x%02x%02x", (unsigned long long)out->issued_at,
			 rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3], rand_bytes[4], rand_bytes[5], rand_bytes[6],
			 rand_bytes[7]);

	/* Duplicate arrays into the token object to keep them self-contained */
	if (role_ids && role_count > 0) {
		out->role_ids = (sso_id_t*)malloc(role_count * sizeof(sso_id_t));
		if (!out->role_ids)
			return SSO_ERR_OUT_OF_MEMORY;
		memcpy(out->role_ids, role_ids, role_count * sizeof(sso_id_t));
	}
	if (group_ids && group_count > 0) {
		out->group_ids = (sso_id_t*)malloc(group_count * sizeof(sso_id_t));
		if (!out->group_ids) {
			free(out->role_ids);
			out->role_ids = NULL;
			return SSO_ERR_OUT_OF_MEMORY;
		}
		memcpy(out->group_ids, group_ids, group_count * sizeof(sso_id_t));
	}

	/* --- Step A: Assemble and encode JWT Header --- */
	yyjson_mut_doc *header_doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val *header = yyjson_mut_obj(header_doc);
	yyjson_mut_doc_set_root(header_doc, header);
	const char* alg_str = "HS256";
	if (mgr->mode == SSO_TOKEN_MODE_RS256) alg_str = "RS256";
	else if (mgr->mode == SSO_TOKEN_MODE_CRYDI3) alg_str = "CRYDI3";

	yyjson_mut_obj_add_str(header_doc, header, "alg", alg_str);
	yyjson_mut_obj_add_str(header_doc, header, "typ", "JWT");
	if (mgr->mode == SSO_TOKEN_MODE_RS256) {
		yyjson_mut_obj_add_str(header_doc, header, "kid", "sso-key-1");
	} else if (mgr->mode == SSO_TOKEN_MODE_CRYDI3) {
		yyjson_mut_obj_add_str(header_doc, header, "kid", "sso-pqc-1");
	}
	char* header_str = yyjson_mut_write(header_doc, 0, NULL);
	yyjson_mut_doc_free(header_doc);

	char b64_header[256];
	base64url_encode((unsigned char*)header_str, strlen(header_str), b64_header, sizeof(b64_header));
	free(header_str);

	/* --- Step B: Assemble and encode JWT Payload --- */
	yyjson_mut_doc *payload_doc = yyjson_mut_doc_new(NULL);
	yyjson_mut_val *root = yyjson_mut_obj(payload_doc);
	yyjson_mut_doc_set_root(payload_doc, root);
	yyjson_mut_obj_add_str(payload_doc, root, "jti", out->jti);
	yyjson_mut_obj_add_uint(payload_doc, root, "sub", (uint64_t)out->user_id);
	yyjson_mut_obj_add_uint(payload_doc, root, "iat", (uint64_t)out->issued_at);
	yyjson_mut_obj_add_uint(payload_doc, root, "exp", (uint64_t)out->expires_at);
	yyjson_mut_obj_add_uint(payload_doc, root, "tnc", (uint64_t)out->nonce);
	yyjson_mut_obj_add_str(payload_doc, root, "iss", "sso-server");
	yyjson_mut_obj_add_str(payload_doc, root, "aud", "sso-api");

	if (out->scope[0] != '\0') {
		/* Scope can be interned because it's usually from a small finite set (e.g. "read write") */
		yyjson_mut_obj_add_str(payload_doc, root, "scope", intern_string(out->scope));
	}
	if (out->oauth_nonce[0] != '\0') {
		yyjson_mut_obj_add_str(payload_doc, root, "nonce", out->oauth_nonce);
	}

	yyjson_mut_val *roles_arr = yyjson_mut_arr(payload_doc);
	for (size_t i = 0; i < role_count; i++) {
		yyjson_mut_arr_add_uint(payload_doc, roles_arr, (uint64_t)role_ids[i]);
	}
	yyjson_mut_obj_add_val(payload_doc, root, "roles", roles_arr);

	if (group_count > 0) {
		yyjson_mut_val *groups_arr = yyjson_mut_arr(payload_doc);
		for (size_t i = 0; i < group_count; i++) {
			yyjson_mut_arr_add_uint(payload_doc, groups_arr, (uint64_t)group_ids[i]);
		}
		yyjson_mut_obj_add_val(payload_doc, root, "groups", groups_arr);
	}

	if (out->jkt[0] != '\0') {
		yyjson_mut_val *cnf = yyjson_mut_obj(payload_doc);
		yyjson_mut_obj_add_str(payload_doc, cnf, "jkt", out->jkt);
		yyjson_mut_obj_add_val(payload_doc, root, "cnf", cnf);
	}

	char* payload_str = yyjson_mut_write(payload_doc, 0, NULL);
	yyjson_mut_doc_free(payload_doc);
	if (!payload_str) {
		token_destroy(out);
		return SSO_ERR_OUT_OF_MEMORY;
	}

	char* b64_payload	= (char*)malloc(2048);
	char* signing_input = (char*)malloc(2560);
	if (!b64_payload || !signing_input) {
		free(b64_payload);
		free(signing_input);
		free(payload_str);
		token_destroy(out);
		return SSO_ERR_OUT_OF_MEMORY;
	}
	base64url_encode((unsigned char*)payload_str, strlen(payload_str), b64_payload, 2048);
	free(payload_str);

	/* Construct the standard signing input string header.payload */
	snprintf(signing_input, 2560, "%s.%s", b64_header, b64_payload);

	/* --- Step C: Generate secure random refresh token string --- */
	unsigned char rt_bytes[32];
	randombytes_buf(rt_bytes, sizeof(rt_bytes));
	base64url_encode(rt_bytes, sizeof(rt_bytes), out->raw_refresh_token, sizeof(out->raw_refresh_token));

	/* --- Step D: Create Cryptographic Signature --- */
	if (mgr->mode == SSO_TOKEN_MODE_HS256) {
		/* Symmetric signing via OpenSSL HMAC-SHA256 */
		unsigned char hmac_result[EVP_MAX_MD_SIZE];
		unsigned int  hmac_len = 0;
		HMAC(EVP_sha256(), mgr->keys.secret, (int)sizeof(mgr->keys.secret), (unsigned char*)signing_input,
			 strlen(signing_input), hmac_result, &hmac_len);

		char sig_b64[EVP_MAX_MD_SIZE * 2 + 1];
		base64url_encode(hmac_result, hmac_len, sig_b64, sizeof(sig_b64));
		snprintf(out->token_str, sizeof(out->token_str), "%s.%s", signing_input, sig_b64);
	} else if (mgr->mode == SSO_TOKEN_MODE_CRYDI3) {
		/* Post-Quantum Cryptography (PQC) mock signature (CRYSTALS-Dilithium-3) */
		/* In V5, this will be bound to liboqs / OpenSSL PQC provider */
		size_t pqc_sig_len = 3293; /* Typical Dilithium-3 signature length */
		unsigned char* pqc_sig = (unsigned char*)malloc(pqc_sig_len);
		if (!pqc_sig) goto rs_fail;
		memset(pqc_sig, 0xAA, pqc_sig_len); /* Mock signature bytes */
		
		char* sig_b64 = (char*)malloc(pqc_sig_len * 2 + 2);
		if (!sig_b64) {
			free(pqc_sig);
			goto rs_fail;
		}
		base64url_encode(pqc_sig, pqc_sig_len, sig_b64, pqc_sig_len * 2 + 2);
		snprintf(out->token_str, sizeof(out->token_str), "%s.%s", signing_input, sig_b64);
		
		free(pqc_sig);
		free(sig_b64);
	} else {
		/* Asymmetric signing via OpenSSL RSA-SHA256 signature */
		EVP_MD_CTX*	   md_ctx  = EVP_MD_CTX_new();
		EVP_PKEY_CTX*  pk_ctx  = NULL;
		size_t		   sig_len = 0;
		unsigned char* sig	   = NULL;

		if (EVP_DigestSignInit(md_ctx, &pk_ctx, EVP_sha256(), NULL, (EVP_PKEY*)mgr->keys.rsa.priv_key) <= 0)
			goto rs_fail;
		if (EVP_DigestSignUpdate(md_ctx, signing_input, strlen(signing_input)) <= 0)
			goto rs_fail;
		if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0)
			goto rs_fail;

		sig = (unsigned char*)malloc(sig_len);
		if (!sig) {
			goto rs_fail;
		}
		if (EVP_DigestSignFinal(md_ctx, sig, &sig_len) <= 0) {
			free(sig);
			goto rs_fail;
		}

		char* sig_b64 = (char*)malloc(sig_len * 2 + 2);
		if (!sig_b64) {
			free(sig);
			goto rs_fail;
		}
		base64url_encode(sig, sig_len, sig_b64, sig_len * 2 + 2);
		snprintf(out->token_str, sizeof(out->token_str), "%s.%s", signing_input, sig_b64);

		free(sig);
		free(sig_b64);
		EVP_MD_CTX_free(md_ctx);
		goto success;

	rs_fail:
		token_destroy(out);
		if (md_ctx)
			EVP_MD_CTX_free(md_ctx);
		free(b64_payload);
		free(signing_input);
		return SSO_ERR_INIT;
	}

success:
	free(b64_payload);
	free(signing_input);
	return SSO_OK;
}

/* ─── Lightweight JWT payload scanner ────────────────────────────────────
 *
 * The JWT payload is a fixed-format JSON object generated by token_issue().
 * Instead of a full yyjson parse (malloc-heavy, slow), we scan for known keys
 * with a single pass over the decoded string.  Required fields: sub, exp.
 */
static sso_error_t scan_jwt_payload(const char* json, token_t* out) {
	if (!json || !out)
		return SSO_ERR_INVALID_PARAM;
	bool found_sub = false, found_exp = false;

	const char* p = json;
	while (*p) {
		/* Find opening quote of a key */
		while (*p && *p != '"')
			p++;
		if (!*p)
			break;
		p++;

		const char* key = p;
		while (*p && *p != '"')
			p++;
		if (!*p)
			break;
		size_t klen = (size_t)(p - key);
		p++; /* skip closing quote */
		if (!*p)
			break;

		/* Skip colon */
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
			p++;
		if (*p != ':')
			continue;
		p++;
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
			p++;
		if (!*p)
			break;

		switch (klen) {
			case 3:
				if (memcmp(key, "jti", 3) == 0 && *p == '"') {
					p++; /* skip opening quote */
					const char* v = p;
					while (*p && *p != '"')
						p++;
					size_t vlen = (size_t)(p - v);
					if (vlen < sizeof(out->jti)) {
						memcpy(out->jti, v, vlen);
						out->jti[vlen] = '\0';
					}
					if (*p)
						p++; /* skip closing quote */
				} else if (memcmp(key, "sub", 3) == 0 && *p >= '0' && *p <= '9') {
					out->user_id = (sso_id_t)strtoull(p, (char**)&p, 10);
					found_sub	 = true;
				} else if (memcmp(key, "iat", 3) == 0 && *p >= '0' && *p <= '9') {
					out->issued_at = (sso_timestamp_t)strtoull(p, (char**)&p, 10);
				} else if (memcmp(key, "exp", 3) == 0 && *p >= '0' && *p <= '9') {
					out->expires_at = (sso_timestamp_t)strtoull(p, (char**)&p, 10);
					found_exp		= true;
				} else if (memcmp(key, "tnc", 3) == 0 && *p >= '0' && *p <= '9') {
					out->nonce = (uint64_t)strtoull(p, (char**)&p, 10);
				} else if (memcmp(key, "cnf", 3) == 0 && *p == '{') {
					p++;
					while (*p && *p != '}') {
						while (*p && *p != '"' && *p != '}')
							p++;
						if (*p == '}')
							break;
						p++;
						const char* ikey = p;
						while (*p && *p != '"')
							p++;
						size_t iklen = (size_t)(p - ikey);
						if (*p)
							p++;
						while (*p == ' ' || *p == ':')
							p++;
						if (iklen == 3 && memcmp(ikey, "jkt", 3) == 0 && *p == '"') {
							p++;
							const char* iv = p;
							while (*p && *p != '"')
								p++;
							size_t ivlen = (size_t)(p - iv);
							if (ivlen < sizeof(out->jkt)) {
								memcpy(out->jkt, iv, ivlen);
								out->jkt[ivlen] = '\0';
							}
							if (*p)
								p++;
						} else {
							if (*p == '"') {
								p++;
								while (*p && *p != '"')
									p++;
								if (*p)
									p++;
							} else {
								while (*p && *p != ',' && *p != '}')
									p++;
							}
						}
						while (*p == ' ' || *p == ',')
							p++;
					}
					if (*p == '}')
						p++;
				}
				break;
			case 5:
				if (memcmp(key, "scope", 5) == 0 && *p == '"') {
					p++; /* skip opening quote */
					const char* v = p;
					while (*p && *p != '"')
						p++;
					size_t vlen = (size_t)(p - v);
					if (vlen < sizeof(out->scope)) {
						memcpy(out->scope, v, vlen);
						out->scope[vlen] = '\0';
					}
					if (*p)
						p++;
				} else if (memcmp(key, "nonce", 5) == 0 && *p == '"') {
					p++; /* skip opening quote */
					const char* v = p;
					while (*p && *p != '"')
						p++;
					size_t vlen = (size_t)(p - v);
					if (vlen < sizeof(out->oauth_nonce)) {
						memcpy(out->oauth_nonce, v, vlen);
						out->oauth_nonce[vlen] = '\0';
					}
					if (*p)
						p++;
				} else if (memcmp(key, "roles", 5) == 0 && *p == '[') {
					p++;
					sso_id_t ids[64];
					size_t	 count = 0;
					while (*p && *p != ']' && count < 64) {
						while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')
							p++;
						if (*p >= '0' && *p <= '9')
							ids[count++] = (sso_id_t)strtoull(p, (char**)&p, 10);
						else
							break;
					}
					if (count > 0) {
						out->role_ids = (sso_id_t*)malloc(count * sizeof(sso_id_t));
						if (out->role_ids) {
							memcpy(out->role_ids, ids, count * sizeof(sso_id_t));
							out->role_count = count;
						}
					}
					while (*p && *p != ']')
						p++;
					if (*p)
						p++;
				}
				break;
			case 6:
				if (memcmp(key, "groups", 6) == 0 && *p == '[') {
					p++;
					sso_id_t ids[64];
					size_t	 count = 0;
					while (*p && *p != ']' && count < 64) {
						while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')
							p++;
						if (*p >= '0' && *p <= '9')
							ids[count++] = (sso_id_t)strtoull(p, (char**)&p, 10);
						else
							break;
					}
					if (count > 0) {
						out->group_ids = (sso_id_t*)malloc(count * sizeof(sso_id_t));
						if (out->group_ids) {
							memcpy(out->group_ids, ids, count * sizeof(sso_id_t));
							out->group_count = count;
						}
					}
					while (*p && *p != ']')
						p++;
					if (*p)
						p++;
				}
				break;
		}
	}

	return (found_sub && found_exp) ? SSO_OK : SSO_ERR_TOKEN_INVALID;
}

/**
 * @brief Decodes, validates the cryptographic signature, and scans claims of a JWT.
 *
 * Flow:
 * 1. Split the token string by dot '.' characters into header, payload, and signature.
 * 2. Form the original signing_input string "header.payload".
 * 3. Verify signature:
 *    - Symmetrically: compute HMAC-SHA256 of signing_input with the server secret,
 *      then verify it matches the decoded signature.
 *    - Asymmetrically: decode signature from base64url and verify using OpenSSL DigestVerify
 *      with the RSA public key.
 * 4. Base64url-decode the payload segment and verify it.
 * 5. Parse/scan the JSON payload claims.
 * 6. Verify expiration timestamp.
 */
sso_error_t token_verify(token_manager_t* mgr, const char* token_str, token_t* out) {
	if (!mgr || !token_str || !out)
		return SSO_ERR_INVALID_PARAM;

	memset(out, 0, sizeof(*out));
	sso_strlcpy(out->token_str, token_str, SSO_MAX_TOKEN_STR);

	/* Split raw token string into header, payload, and signature components */
	const char* dot1 = strchr(token_str, '.');
	if (!dot1)
		return SSO_ERR_TOKEN_INVALID;

	const char* dot2 = strchr(dot1 + 1, '.');
	if (!dot2)
		return SSO_ERR_TOKEN_INVALID;

	size_t hdr_len = (size_t)(dot1 - token_str);
	size_t b64_len = (size_t)(dot2 - dot1 - 1);

	char		   b64_header[128];
	char*		   b64_payload	 = (char*)malloc(2048);
	char*		   signing_input = (char*)malloc(2560);
	unsigned char* decoded		 = (unsigned char*)malloc(4096);
	sso_error_t	   tv_err		 = SSO_OK;
	if (!b64_payload || !signing_input || !decoded) {
		tv_err = SSO_ERR_OUT_OF_MEMORY;
		goto token_verify_cleanup;
	}
	if (hdr_len >= sizeof(b64_header) || b64_len >= 2048) {
		tv_err = SSO_ERR_TOKEN_INVALID;
		goto token_verify_cleanup;
	}

	memcpy(b64_header, token_str, hdr_len);
	b64_header[hdr_len] = '\0';

	memcpy(b64_payload, dot1 + 1, b64_len);
	b64_payload[b64_len] = '\0';

	const char* sig_part = dot2 + 1;

	/* Reconstruct signing input string = header.payload */
	snprintf(signing_input, 2560, "%s.%s", b64_header, b64_payload);

	/* Detect hex-encoded legacy signature format vs new base64url format */
	bool legacy_hex = is_hex_str(sig_part);

	/* --- Verify Signature Integrity --- */
	if (mgr->mode == SSO_TOKEN_MODE_HS256) {
		/* Symmetric HS256 HMAC-SHA256 signature verification */
		unsigned char hmac_result[EVP_MAX_MD_SIZE];
		unsigned int  hmac_len = 0;
		HMAC(EVP_sha256(), mgr->keys.secret, (int)sizeof(mgr->keys.secret), (unsigned char*)signing_input,
			 strlen(signing_input), hmac_result, &hmac_len);

		if (legacy_hex) {
			char expected_hex[EVP_MAX_MD_SIZE * 2 + 1];
			to_hex(hmac_result, hmac_len, expected_hex, sizeof(expected_hex));
			if (strcmp(sig_part, expected_hex) != 0) {
				tv_err = SSO_ERR_TOKEN_INVALID;
				goto token_verify_cleanup;
			}
		} else {
			char expected_b64[EVP_MAX_MD_SIZE * 2 + 1];
			base64url_encode(hmac_result, hmac_len, expected_b64, sizeof(expected_b64));
			if (strcmp(sig_part, expected_b64) != 0) {
				tv_err = SSO_ERR_TOKEN_INVALID;
				goto token_verify_cleanup;
			}
		}
	} else {
		/* Asymmetric RS256 RSA-SHA256 signature verification */
		unsigned char* sig	   = NULL;
		size_t		   sig_len = 0;

		if (legacy_hex) {
			sig_len = strlen(sig_part) / 2;
			sig		= (unsigned char*)malloc(sig_len);
			if (!sig) {
				tv_err = SSO_ERR_TOKEN_INVALID;
				goto token_verify_cleanup;
			}
			for (size_t i = 0; i < sig_len; i++) {
				unsigned int val;
				sscanf(sig_part + i * 2, "%02x", &val);
				sig[i] = (unsigned char)val;
			}
		} else {
			sig_len = strlen(sig_part) / 4 * 3 + 4;
			sig		= (unsigned char*)malloc(sig_len);
			if (!sig) {
				tv_err = SSO_ERR_TOKEN_INVALID;
				goto token_verify_cleanup;
			}
			sig_len = base64url_decode(sig_part, sig, sig_len);
		}

		EVP_MD_CTX*	  md_ctx = EVP_MD_CTX_new();
		EVP_PKEY_CTX* pk_ctx = NULL;
		sso_error_t	  v_err	 = SSO_OK;

		if (EVP_DigestVerifyInit(md_ctx, &pk_ctx, EVP_sha256(), NULL, (EVP_PKEY*)mgr->keys.rsa.pub_key) <= 0)
			v_err = SSO_ERR_INIT;
		if (v_err == SSO_OK && EVP_DigestVerifyUpdate(md_ctx, signing_input, strlen(signing_input)) <= 0)
			v_err = SSO_ERR_INIT;
		if (v_err == SSO_OK && EVP_DigestVerifyFinal(md_ctx, sig, sig_len) <= 0)
			v_err = SSO_ERR_TOKEN_INVALID;

		free(sig);
		EVP_MD_CTX_free(md_ctx);
		if (v_err != SSO_OK) {
			tv_err = v_err;
			goto token_verify_cleanup;
		}
	}

	/* --- Decode and Scan JSON Payload Claims --- */
	size_t decoded_len = base64url_decode(b64_payload, decoded, 4096 - 1);
	if (decoded_len == 0) {
		tv_err = SSO_ERR_TOKEN_INVALID;
		goto token_verify_cleanup;
	}
	decoded[decoded_len] = '\0';

	/* Single-pass scan of standard and custom claims */
	sso_error_t scan_err = scan_jwt_payload((const char*)decoded, out);
	if (scan_err != SSO_OK) {
		tv_err = scan_err;
		goto token_verify_cleanup;
	}

	/* Verify if the token expiration date is in the past */
	if (sso_timestamp_now() > out->expires_at) {
		token_destroy(out);
		tv_err = SSO_ERR_TOKEN_EXPIRED;
		goto token_verify_cleanup;
	}

	tv_err = SSO_OK;

token_verify_cleanup:
	free(b64_payload);
	free(signing_input);
	free(decoded);
	return tv_err;
}

sso_error_t token_refresh(token_manager_t* mgr, const token_t* old_token, sso_timestamp_t ttl_ms, token_t* out) {
	if (!mgr || !old_token || !out)
		return SSO_ERR_INVALID_PARAM;

	/* Issue a new token for the same user, reusing roles/groups from the old token */
	user_t user;
	memset(&user, 0, sizeof(user));
	user.id = old_token->user_id;
	/* user data not fully available here — but token_issue only needs user->id */

	return token_issue(mgr, &user, old_token->role_ids, old_token->role_count, old_token->group_ids,
					   old_token->group_count, old_token->scope, ttl_ms > 0 ? ttl_ms : mgr->default_ttl_ms, out->jkt,
					   out);
}

/*           ==
 * Revocation (dynamic growing blocklist) — per token_manager instance
 *           == */
#define REVOCATIONS_INIT_CAP 64

static int compare_jtis(const void* a, const void* b) {
	return strcmp((const char*)a, (const char*)b);
}

sso_error_t token_revoke(token_manager_t* mgr, const char* jti, sso_timestamp_t expires_at) {
	if (!mgr || !jti)
		return SSO_ERR_INVALID_PARAM;
	atomic_fetch_add(&g_metric_jwt_revoke, 1);

	/* 1. Persist to storage backend if available */
	if (mgr->storage) {
		storage_backend_t* sb = (storage_backend_t*)mgr->storage;
		if (sb->jti_revoke) {
			sso_error_t err = sb->jti_revoke(sb, jti, expires_at);
			if (err != SSO_OK)
				return err;
		}
	}

	/* 2. Also keep in-memory for fast check / fallback */
	pthread_mutex_lock(&mgr->rev_lock);

	if (mgr->jtis == NULL) {
		mgr->jtis = (char (*)[TOKEN_REVOCATION_STR_LEN])calloc(REVOCATIONS_INIT_CAP, TOKEN_REVOCATION_STR_LEN);
		if (!mgr->jtis) {
			pthread_mutex_unlock(&mgr->rev_lock);
			return SSO_ERR_OUT_OF_MEMORY;
		}
		mgr->rev_capacity = REVOCATIONS_INIT_CAP;
	}

	if (mgr->rev_count >= mgr->rev_capacity) {
		size_t new_cap = mgr->rev_capacity * 2;
		char (*new_jtis)[TOKEN_REVOCATION_STR_LEN] =
				(char (*)[TOKEN_REVOCATION_STR_LEN])realloc(mgr->jtis, new_cap * TOKEN_REVOCATION_STR_LEN);
		if (!new_jtis) {
			pthread_mutex_unlock(&mgr->rev_lock);
			return SSO_ERR_OUT_OF_MEMORY;
		}
		mgr->jtis		  = new_jtis;
		mgr->rev_capacity = new_cap;
	}

	sso_strlcpy(mgr->jtis[mgr->rev_count], jti, TOKEN_REVOCATION_STR_LEN);
	mgr->jtis[mgr->rev_count][TOKEN_REVOCATION_STR_LEN - 1] = '\0';
	mgr->rev_count++;
	mgr->rev_sorted = false;

	pthread_mutex_unlock(&mgr->rev_lock);
	return SSO_OK;
}

void token_register_session(token_manager_t* mgr, sso_id_t user_id, const char* jti) {
	if (!mgr || !jti)
		return;

	pthread_mutex_lock(&mgr->session_lock);
	session_track_t* track = NULL;
	for (size_t i = 0; i < mgr->session_count; i++) {
		if (mgr->sessions[i].user_id == user_id) {
			track = &mgr->sessions[i];
			break;
		}
	}

	if (!track) {
		if (mgr->session_count >= mgr->session_cap) {
			size_t			 new_cap	  = mgr->session_cap == 0 ? 128 : mgr->session_cap * 2;
			session_track_t* new_sessions = (session_track_t*)realloc(mgr->sessions, new_cap * sizeof(session_track_t));
			if (!new_sessions) {
				pthread_mutex_unlock(&mgr->session_lock);
				return;
			}
			mgr->sessions	 = new_sessions;
			mgr->session_cap = new_cap;
		}
		track = &mgr->sessions[mgr->session_count++];
		memset(track, 0, sizeof(*track));
		track->user_id = user_id;
	}

	if (track->active_count < SSO_MAX_CONCURRENT_SESSIONS) {
		sso_strlcpy(track->jtis[track->active_count], jti, TOKEN_REVOCATION_STR_LEN);
		track->active_count++;
	} else {
		/* Evict oldest */
		char oldest_jti[TOKEN_REVOCATION_STR_LEN];
		sso_strlcpy(oldest_jti, track->jtis[track->oldest_idx], TOKEN_REVOCATION_STR_LEN);

		sso_strlcpy(track->jtis[track->oldest_idx], jti, TOKEN_REVOCATION_STR_LEN);
		track->oldest_idx = (track->oldest_idx + 1) % SSO_MAX_CONCURRENT_SESSIONS;

		pthread_mutex_unlock(&mgr->session_lock);

		LOG_INFO("[session] User %llu reached concurrent limit. Evicting oldest session JTI: %s",
				 (unsigned long long)user_id, oldest_jti);
		token_revoke(mgr, oldest_jti, 0);
		return;
	}
	pthread_mutex_unlock(&mgr->session_lock);
}

bool token_is_revoked(token_manager_t* mgr, const char* jti) {
	if (!mgr || !jti)
		return false;

	/* 1. Check in-memory list first */
	pthread_mutex_lock(&mgr->rev_lock);
	if (mgr->jtis && mgr->rev_count > 0) {
		if (!mgr->rev_sorted) {
			qsort(mgr->jtis, mgr->rev_count, TOKEN_REVOCATION_STR_LEN, compare_jtis);
			mgr->rev_sorted = true;
		}
		bool found = bsearch(jti, mgr->jtis, mgr->rev_count, TOKEN_REVOCATION_STR_LEN, compare_jtis) != NULL;
		if (found) {
			pthread_mutex_unlock(&mgr->rev_lock);
			return true;
		}
	}
	pthread_mutex_unlock(&mgr->rev_lock);

	/* 2. Fall back to storage backend if available */
	if (mgr->storage) {
		storage_backend_t* sb = (storage_backend_t*)mgr->storage;
		if (sb->jti_is_revoked) {
			return sb->jti_is_revoked(sb, jti);
		}
	}

	return false;
}

/*           ==
 * User token nonces (for "logout all sessions")
 *           == */
sso_error_t token_set_nonce(token_manager_t* mgr, sso_id_t user_id, uint64_t nonce) {
	if (!mgr)
		return SSO_ERR_INVALID_PARAM;
	pthread_mutex_lock(&mgr->nonce_lock);
	for (size_t i = 0; i < mgr->nonce_count; i++) {
		if (mgr->nonces[i].uid == user_id) {
			mgr->nonces[i].nonce = nonce;
			pthread_mutex_unlock(&mgr->nonce_lock);
			return SSO_OK;
		}
	}
	size_t		  new_cap	 = mgr->nonce_cap ? mgr->nonce_cap * 2 : 16;
	nonce_pair_t* new_nonces = (nonce_pair_t*)realloc(mgr->nonces, new_cap * sizeof(nonce_pair_t));
	if (!new_nonces) {
		pthread_mutex_unlock(&mgr->nonce_lock);
		return SSO_ERR_OUT_OF_MEMORY;
	}
	mgr->nonces							= new_nonces;
	mgr->nonce_cap						= new_cap;
	mgr->nonces[mgr->nonce_count].uid	= user_id;
	mgr->nonces[mgr->nonce_count].nonce = nonce;
	mgr->nonce_count++;
	pthread_mutex_unlock(&mgr->nonce_lock);
	return SSO_OK;
}

uint64_t token_get_nonce(token_manager_t* mgr, sso_id_t user_id) {
	if (!mgr)
		return 0;
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

sso_error_t token_bump_nonce(token_manager_t* mgr, sso_id_t user_id) {
	if (!mgr)
		return SSO_ERR_INVALID_PARAM;
	uint64_t current = token_get_nonce(mgr, user_id);
	return token_set_nonce(mgr, user_id, current + 1);
}
