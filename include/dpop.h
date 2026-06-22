/*
 * dpop.h — DPoP (Demonstration of Proof-of-Possession) header declarations.
 *
 * Implements RFC 9449 DPoP binding for OAuth 2.0 tokens.  Binds an
 * access/refresh token to a client-held private key by requiring each
 * API request to carry a signed DPoP proof JWT in the HTTP header.
 * Provides functions to generate, validate, and cache DPoP proofs
 * using ECDSA (P-256) key pairs.
 */

#ifndef SSO_DPOP_H
#define SSO_DPOP_H

#include "sso.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Parses and verifies a DPoP Proof JWT header.
 *
 * @param dpop_proof The raw DPoP header string.
 * @param method The HTTP method of the current request (e.g., "POST").
 * @param url The full HTTP URL of the current request.
 * @param expected_jkt If validating a resource request, the jkt bound to the access token.
 *                     If NULL, this is an initial token request and no previous binding exists.
 * @param out_jkt Buffer to store the calculated JWK Thumbprint (jkt) if verification succeeds.
 *                Must be at least 44 bytes (base64url of SHA-256).
 * @return SSO_OK if the DPoP proof is valid and the signature matches.
 */
sso_error_t dpop_verify_proof(const char* dpop_proof, const char* method, const char* url, const char* expected_jkt,
							  char* out_jkt);

#ifdef __cplusplus
}
#endif

#endif /* SSO_DPOP_H */
