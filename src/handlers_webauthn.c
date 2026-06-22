/*
 * handlers_webauthn.c — WebAuthn registration and authentication handlers.
 *
 * Implements the WebAuthn ceremony endpoints: challenge generation for
 * registration and login, credential registration callback, and assertion
 * verification callback.  Challenges are HMAC-signed with the server
 * secret so no server-side challenge state is required.
 */

#include "handlers.h"
#include "webauthn.h"
#include "user.h"
#include "token.h"
#include "risk.h"
#include "ratelimit.h"
#include "yyjson.h"
#include "logger.h"
#include <string.h>
#include <openssl/hmac.h>

/* Helper to sign challenge losslessly without db state */
static void sign_challenge(const char* challenge, const sso_context_t* ctx, char* out_sig) {
	sso_config_t* cfg = (sso_config_t*)ctx->config;
	unsigned int  len = 0;
	unsigned char mac[32];
	HMAC(EVP_sha256(), cfg->token_secret, strlen(cfg->token_secret), (const unsigned char*)challenge, strlen(challenge),
		 mac, &len);
	for (int i = 0; i < 32; i++) {
		sprintf(out_sig + i * 2, "%02x", mac[i]);
	}
}

sso_error_t handle_webauthn_register_challenge(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	auth_context_t* actx = (auth_context_t*)req->userdata;
	if (!actx) {
		sso_response_error(resp, 401, "Authentication required");
		return SSO_OK;
	}

	char* challenge = webauthn_generate_challenge();
	char  sig[65];
	sign_challenge(challenge, ctx, sig);

	yyjson_mut_doc* doc	 = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* root = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, root);

	yyjson_mut_obj_add_str(doc, root, "challenge", challenge);
	yyjson_mut_obj_add_str(doc, root, "challenge_sig", sig);
	yyjson_mut_obj_add_uint(doc, root, "user_id", actx->user.id);
	yyjson_mut_obj_add_str(doc, root, "username", actx->user.username);

	char* json = yyjson_mut_write(doc, 0, NULL);
	sso_response_ok(resp, json);
	free(json);
	yyjson_mut_doc_free(doc);
	free(challenge);
	return SSO_OK;
}

sso_error_t handle_webauthn_register(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	auth_context_t* actx = (auth_context_t*)req->userdata;
	if (!actx) {
		sso_response_error(resp, 401, "Authentication required");
		return SSO_OK;
	}

	yyjson_doc* req_doc = yyjson_read(req->body, req->body_len, 0);
	if (!req_doc) {
		sso_response_error(resp, 400, "Invalid JSON");
		return SSO_OK;
	}
	yyjson_val* root			 = yyjson_doc_get_root(req_doc);
	const char* challenge		 = yyjson_get_str(yyjson_obj_get(root, "challenge"));
	const char* sig				 = yyjson_get_str(yyjson_obj_get(root, "challenge_sig"));
	const char* attestation_b64u = yyjson_get_str(yyjson_obj_get(root, "attestation_object"));
	const char* client_data_b64u = yyjson_get_str(yyjson_obj_get(root, "client_data_json"));

	if (!challenge || !sig || !attestation_b64u || !client_data_b64u) {
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 400, "Missing parameters");
		return SSO_OK;
	}

	char expected_sig[65];
	sign_challenge(challenge, ctx, expected_sig);
	if (strcmp(sig, expected_sig) != 0) {
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 400, "Invalid challenge signature");
		return SSO_OK;
	}

	char expected_origin[512];
	snprintf(expected_origin, sizeof(expected_origin), "http://%s", req->host);

	char*		cred_id = NULL;
	char*		pub_key = NULL;
	sso_error_t err = webauthn_register_verify(attestation_b64u, client_data_b64u, challenge, expected_origin, &cred_id,
											   &pub_key);
	yyjson_doc_free(req_doc);

	if (err != SSO_OK) {
		sso_response_error(resp, 400, "WebAuthn registration verification failed");
		return SSO_OK;
	}

	/* Save credentials in user attributes */
	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	user_t			user;
	if (user_get_by_id(umgr, actx->user.id, &user) == SSO_OK) {
		yyjson_mut_doc* mdoc = NULL;
		if (user.attributes[0]) {
			yyjson_doc* rdoc = yyjson_read(user.attributes, strlen(user.attributes), 0);
			mdoc			 = yyjson_doc_mut_copy(rdoc, NULL);
			yyjson_doc_free(rdoc);
		} else {
			mdoc = yyjson_mut_doc_new(NULL);
			yyjson_mut_obj(mdoc);
		}
		yyjson_mut_val* mroot = yyjson_mut_doc_get_root(mdoc);
		if (!mroot) {
			mroot = yyjson_mut_obj(mdoc);
			yyjson_mut_doc_set_root(mdoc, mroot);
		}

		yyjson_mut_obj_add_str(mdoc, mroot, "webauthn_credential_id", cred_id);
		yyjson_mut_obj_add_str(mdoc, mroot, "webauthn_public_key", pub_key);

		const char* json_str = yyjson_mut_write(mdoc, 0, NULL);
		sso_strlcpy(user.attributes, json_str, sizeof(user.attributes));
		free((void*)json_str);
		yyjson_mut_doc_free(mdoc);

		user_update(umgr, &user);
	}

	free(cred_id);
	free(pub_key);

	yyjson_mut_doc* doc	  = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* mroot = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, mroot);
	yyjson_mut_obj_add_str(doc, mroot, "message", "WebAuthn credentials registered successfully");
	char* json = yyjson_mut_write(doc, 0, NULL);
	sso_response_ok(resp, json);
	free(json);
	yyjson_mut_doc_free(doc);
	return SSO_OK;
}

sso_error_t handle_webauthn_login_challenge(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	yyjson_doc* req_doc = yyjson_read(req->body, req->body_len, 0);
	if (!req_doc) {
		sso_response_error(resp, 400, "Invalid JSON");
		return SSO_OK;
	}
	yyjson_val* root	 = yyjson_doc_get_root(req_doc);
	const char* username = yyjson_get_str(yyjson_obj_get(root, "username"));
	if (!username) {
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 400, "Missing username");
		return SSO_OK;
	}

	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	user_t			user;
	if (user_get_by_username(umgr, username, &user) != SSO_OK || user.status != USER_STATUS_ACTIVE) {
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 401, "User not found or inactive");
		return SSO_OK;
	}
	yyjson_doc_free(req_doc);

	/* Extract Credential ID from attributes */
	const char* cred_id	 = NULL;
	yyjson_doc* attr_doc = yyjson_read(user.attributes, strlen(user.attributes), 0);
	if (attr_doc) {
		cred_id = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(attr_doc), "webauthn_credential_id"));
	}

	if (!cred_id) {
		if (attr_doc)
			yyjson_doc_free(attr_doc);
		sso_response_error(resp, 400, "WebAuthn is not configured for this user");
		return SSO_OK;
	}

	char* challenge = webauthn_generate_challenge();
	char  sig[65];
	sign_challenge(challenge, ctx, sig);

	yyjson_mut_doc* doc	  = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* mroot = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, mroot);

	yyjson_mut_obj_add_str(doc, mroot, "challenge", challenge);
	yyjson_mut_obj_add_str(doc, mroot, "challenge_sig", sig);
	yyjson_mut_obj_add_str(doc, mroot, "credential_id", cred_id);

	char* json = yyjson_mut_write(doc, 0, NULL);
	sso_response_ok(resp, json);
	free(json);
	yyjson_mut_doc_free(doc);
	free(challenge);
	if (attr_doc)
		yyjson_doc_free(attr_doc);
	return SSO_OK;
}

sso_error_t handle_webauthn_login(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	yyjson_doc* req_doc = yyjson_read(req->body, req->body_len, 0);
	if (!req_doc) {
		sso_response_error(resp, 400, "Invalid JSON");
		return SSO_OK;
	}
	yyjson_val* root			 = yyjson_doc_get_root(req_doc);
	const char* username		 = yyjson_get_str(yyjson_obj_get(root, "username"));
	const char* challenge		 = yyjson_get_str(yyjson_obj_get(root, "challenge"));
	const char* sig				 = yyjson_get_str(yyjson_obj_get(root, "challenge_sig"));
	const char* auth_data_b64u	 = yyjson_get_str(yyjson_obj_get(root, "authenticator_data"));
	const char* client_data_b64u = yyjson_get_str(yyjson_obj_get(root, "client_data_json"));
	const char* signature_b64u	 = yyjson_get_str(yyjson_obj_get(root, "signature"));

	if (!username || !challenge || !sig || !auth_data_b64u || !client_data_b64u || !signature_b64u) {
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 400, "Missing parameters");
		return SSO_OK;
	}

	char expected_sig[65];
	sign_challenge(challenge, ctx, expected_sig);
	if (strcmp(sig, expected_sig) != 0) {
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 400, "Invalid challenge signature");
		return SSO_OK;
	}

	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	user_t			user;
	if (user_get_by_username(umgr, username, &user) != SSO_OK || user.status != USER_STATUS_ACTIVE) {
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 401, "User not found or inactive");
		return SSO_OK;
	}

	/* Verify Risk Score */
	int risk_score = risk_evaluate_login(user.id, req->client_ip, req->user_agent);
	if (risk_score >= RISK_SCORE_HIGH) {
		risk_record_login_attempt(user.id, req->client_ip, 0);
		yyjson_doc_free(req_doc);
		sso_response_error(resp, 401, "High risk login blocked");
		return SSO_OK;
	}

	/* Extract Public Key */
	const char* pub_key	 = NULL;
	yyjson_doc* attr_doc = yyjson_read(user.attributes, strlen(user.attributes), 0);
	if (attr_doc) {
		pub_key = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(attr_doc), "webauthn_public_key"));
	}

	if (!pub_key) {
		yyjson_doc_free(req_doc);
		if (attr_doc)
			yyjson_doc_free(attr_doc);
		sso_response_error(resp, 400, "WebAuthn is not configured for this user");
		return SSO_OK;
	}

	char expected_origin[512];
	snprintf(expected_origin, sizeof(expected_origin), "http://%s", req->host);

	sso_error_t err = webauthn_login_verify(auth_data_b64u, client_data_b64u, signature_b64u, challenge,
											expected_origin, pub_key);
	yyjson_doc_free(req_doc);
	if (attr_doc)
		yyjson_doc_free(attr_doc);

	if (err != SSO_OK) {
		risk_record_login_attempt(user.id, req->client_ip, 0);
		sso_response_error(resp, 401, "WebAuthn authentication failed");
		return SSO_OK;
	}

	/* Issue JWT */
	risk_record_login_success_with_ua(user.id, req->client_ip, req->user_agent);
	if (ctx->rate_limiter) {
		rate_limiter_reset((rate_limiter_t*)ctx->rate_limiter, req->client_ip);
	}

	sso_id_t roles[16], groups[16];
	size_t	 rc = 0, gc = 0;
	user_get_roles(umgr, user.id, roles, &rc, 16);
	user_get_groups(umgr, user.id, groups, &gc, 16);

	token_manager_t* tmgr = (token_manager_t*)ctx->token_mgr;
	token_t			 t_access, t_refresh;
	token_issue(tmgr, &user, roles, rc, groups, gc, "*", 0, req->dpop_proof[0] ? req->dpop_proof : NULL, &t_access);
	token_issue(tmgr, &user, roles, rc, groups, gc, "refresh", 86400000 * 7, NULL, &t_refresh);

	yyjson_mut_doc* doc	  = yyjson_mut_doc_new(NULL);
	yyjson_mut_val* mroot = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, mroot);

	yyjson_mut_obj_add_str(doc, mroot, "access_token", t_access.token_str);
	yyjson_mut_obj_add_str(doc, mroot, "refresh_token", t_refresh.token_str);
	yyjson_mut_obj_add_str(doc, mroot, "token_type", req->dpop_proof[0] ? "DPoP" : "Bearer");
	yyjson_mut_obj_add_uint(doc, mroot, "expires_in", t_access.expires_at - sso_timestamp_now());

	char* json = yyjson_mut_write(doc, 0, NULL);
	sso_response_ok(resp, json);
	free(json);
	yyjson_mut_doc_free(doc);
	return SSO_OK;
}
