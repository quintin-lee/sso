/*
 * webauthn.h — WebAuthn / FIDO2 credential verification declarations.
 *
 * Implements passwordless authentication via the WebAuthn API (W3C
 * Recommendation).  Supports registration (attestation) and login
 * (assertion) flows using platform authenticators (Touch ID, Windows
 * Hello) and roaming authenticators (YubiKey, etc.).  Decodes and
 * verifies CBOR-encoded attestationObject and authenticatorData.
 */

#ifndef SSO_WEBAUTHN_H
#define SSO_WEBAUTHN_H

#include "sso.h"

/* Returns an allocated base64url encoded challenge */
char* webauthn_generate_challenge(void);

/*
 * Registration: Parses attestationObject (CBOR base64url) and clientDataJSON (base64url).
 * If valid against expected_challenge and expected_origin, extracts the credential_id
 * and public_key_pem (allocated strings).
 * Returns SSO_OK on success.
 */
sso_error_t webauthn_register_verify(const char* attestation_b64u, const char* client_data_b64u,
									 const char* expected_challenge, const char* expected_origin,
									 char** out_credential_id_b64u, char** out_public_key_pem);

/*
 * Authentication: Verifies the signature from navigator.credentials.get()
 * authenticator_data_b64u: binary authData base64url encoded
 * client_data_b64u: JSON client data base64url encoded
 * signature_b64u: ASN.1 DER signature base64url encoded
 * public_key_pem: the PEM stored during registration
 */
sso_error_t webauthn_login_verify(const char* authenticator_data_b64u, const char* client_data_b64u,
								  const char* signature_b64u, const char* expected_challenge,
								  const char* expected_origin, const char* public_key_pem);

#endif
