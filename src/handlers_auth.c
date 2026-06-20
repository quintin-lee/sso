#include "sso.h"
#include "server.h"
#include "handlers.h"
#include "logger.h"
#include "user.h"
#include "token.h"
#include "ratelimit.h"
#include "config.h"
#include "cJSON.h"
#include "storage.h"
#include "role.h"
#include "mfa.h"
#include "risk.h"
#include <string.h>
#include "dpop.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

sso_error_t handle_login(sso_context_t *ctx, const http_request_t *req,
                         http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    /* Rate limiting: 5 attempts per minute per IP */
    if (ctx->rate_limiter) {
        sso_error_t rerr = rate_limiter_check((rate_limiter_t *)ctx->rate_limiter, 
                                               req->client_ip, 60000, 5);
        if (rerr != SSO_OK) {
            sso_response_error(resp, 429, "Too many login attempts. Please wait.");
            return SSO_OK;
        }
    }

    char *username = json_str_value(req->body, "username");
    char *password = json_str_value(req->body, "password");
    if (!username || !password) {
        free(username); free(password);
        sso_response_error(resp, 400, "username and password required");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    sso_error_t err = user_authenticate(umgr, username, password, &user);
    free(username); free(password);

    if (err != SSO_OK) {
        risk_record_login_attempt(0, req->client_ip, 0);
        sso_response_error(resp, 401, "Invalid credentials");
        return SSO_OK;
    }

    /* Risk Assessment */
    int risk_score = risk_evaluate_login(user.id, req->client_ip, NULL);
    if (risk_score >= RISK_SCORE_HIGH) {
        risk_record_login_attempt(user.id, req->client_ip, 0);
        sso_response_error(resp, 401, "High risk login blocked");
        return SSO_OK;
    }

    if (risk_score >= RISK_SCORE_MEDIUM && !user.mfa_enabled) {
        risk_record_login_attempt(user.id, req->client_ip, 0);
        sso_response_error(resp, 401, "Medium risk login requires MFA, but MFA is not configured. Access blocked.");
        return SSO_OK;
    }

    int force_mfa = (risk_score >= RISK_SCORE_MEDIUM);

    /* DPoP Proof Evaluation */
    char dpop_jkt[64] = {0};
    if (req->dpop_proof[0]) {
        char full_url[1024];
        snprintf(full_url, sizeof(full_url), "http://%s%s", req->host[0] ? req->host : "localhost", req->path);
        if (dpop_verify_proof(req->dpop_proof, req->method_str, full_url, NULL, dpop_jkt) != SSO_OK) {
            sso_response_error(resp, 401, "Invalid DPoP Proof");
            return SSO_OK;
        }
    }

    /* Success: reset rate limit for this IP */
    if (ctx->rate_limiter) {
        rate_limiter_reset((rate_limiter_t *)ctx->rate_limiter, req->client_ip);
    }
    
    risk_record_login_attempt(user.id, req->client_ip, 1);

    sso_id_t roles[16], groups[16];
    size_t rc = 0, gc = 0;
    user_get_roles(umgr, user.id, roles, &rc, 16);
    user_get_groups(umgr, user.id, groups, &gc, 16);

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;

    if (user.mfa_enabled || force_mfa) {
        token_t mfa_token;
        /* Issue a short-lived token with "mfa" scope */
        token_issue(tmgr, &user, NULL, 0, NULL, 0, "mfa", 300000, &mfa_token);
        
        /* Success: return MFA requirement */
        char *buf = (char *)malloc(8192);
        if (!buf) {
            token_destroy(&mfa_token);
            sso_response_error(resp, 500, "Out of memory");
            return SSO_OK;
        }
        snprintf(buf, 8192,
            "{"
            "\"mfa_required\":true,"
            "\"mfa_token\":\"%s\""
            "}",
            mfa_token.token_str);
        token_destroy(&mfa_token);
        sso_response_ok(resp, buf);
        free(buf);
        return SSO_OK;
    }

    token_t access_token, refresh_token;
    memset(&access_token, 0, sizeof(access_token));
    memset(&refresh_token, 0, sizeof(refresh_token));
    if (dpop_jkt[0]) {
        sso_strlcpy(access_token.jkt, dpop_jkt, sizeof(access_token.jkt));
        sso_strlcpy(refresh_token.jkt, dpop_jkt, sizeof(refresh_token.jkt));
    }
    err = token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 900000, &access_token);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to issue access token");
        return SSO_OK;
    }
    err = token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 604800000, &refresh_token);
    if (err != SSO_OK) {
        token_destroy(&access_token);
        sso_response_error(resp, 500, "Failed to issue refresh token");
        return SSO_OK;
    }

    snprintf(resp->extra_headers, sizeof(resp->extra_headers),
             "Set-Cookie: sso_token=%s; Path=/; HttpOnly; SameSite=Lax\r\n"
             "X-SSO-Access-Token: %s\r\n"
             "X-SSO-Refresh-Token: %s\r\n",
             access_token.token_str,
             access_token.token_str, refresh_token.token_str);

    char *buf = (char *)malloc(8192);
    if (!buf) {
        token_destroy(&access_token);
        token_destroy(&refresh_token);
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }
    snprintf(buf, 8192,
        "{"
        "\"expires_in\":%lld,"
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"display_name\":\"%s\""
        "}",
        (long long)access_token.expires_at,
        (unsigned long long)user.id,
        user.username,
        user.display_name);

    /* Track this session for concurrency control */
    token_register_session(tmgr, user.id, access_token.jti);

    token_destroy(&access_token);
    token_destroy(&refresh_token);
    sso_response_ok(resp, buf);
    free(buf);
    return SSO_OK;
}

sso_error_t handle_mfa_setup(sso_context_t *ctx, const http_request_t *req,
                             http_response_t *resp) {
    (void)ctx;
    const auth_context_t *auth = (const auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    char secret[64];
    mfa_generate_secret(secret, sizeof(secret));

    char buf[128];
    snprintf(buf, sizeof(buf), "{\"secret\":\"%s\"}", secret);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

sso_error_t handle_mfa_enable(sso_context_t *ctx, const http_request_t *req,
                              http_response_t *resp) {
    const auth_context_t *auth = (const auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *secret = json_str_value(req->body, "secret");
    char *code = json_str_value(req->body, "code");

    if (!secret || !code) {
        free(secret); free(code);
        sso_response_error(resp, 400, "secret and code required");
        return SSO_OK;
    }

    if (!mfa_verify_totp(secret, code)) {
        free(secret); free(code);
        sso_response_error(resp, 400, "Invalid TOTP code");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user = auth->user;
    user.mfa_enabled = 1;
    sso_strlcpy(user.mfa_secret, secret, sizeof(user.mfa_secret));
    
    sso_error_t err = user_update(umgr, &user);
    free(secret); free(code);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to update user");
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"enabled\":true}");
    return SSO_OK;
}

sso_error_t handle_mfa_verify(sso_context_t *ctx, const http_request_t *req,
                              http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *mfa_token_str = json_str_value(req->body, "mfa_token");
    char *code = json_str_value(req->body, "code");

    if (!mfa_token_str || !code) {
        free(mfa_token_str); free(code);
        sso_response_error(resp, 400, "mfa_token and code required");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t mfa_token;
    sso_error_t err = token_verify(tmgr, mfa_token_str, &mfa_token);
    free(mfa_token_str);

    if (err != SSO_OK) {
        free(code);
        sso_response_error(resp, 401, "Invalid or expired MFA token");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    err = user_get_by_id(umgr, mfa_token.user_id, &user);
    token_destroy(&mfa_token);

    if (err != SSO_OK) {
        free(code);
        sso_response_error(resp, 401, "User not found");
        return SSO_OK;
    }

    if (!mfa_verify_totp(user.mfa_secret, code)) {
        free(code);
        atomic_fetch_add(&g_metric_mfa_failure, 1);
        sso_response_error(resp, 401, "Invalid TOTP code");
        return SSO_OK;
    }
    free(code);
    atomic_fetch_add(&g_metric_mfa_success, 1);

    /* MFA verified: issue final tokens */
    sso_id_t roles[16], groups[16];
    size_t rc = 0, gc = 0;
    user_get_roles(umgr, user.id, roles, &rc, 16);
    user_get_groups(umgr, user.id, groups, &gc, 16);

    token_t access_token, refresh_token;
    err = token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 900000, &access_token);
    if (err == SSO_OK) {
        err = token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 604800000, &refresh_token);
    }

    if (err != SSO_OK) {
        token_destroy(&access_token);
        sso_response_error(resp, 500, "Failed to issue final tokens");
        return SSO_OK;
    }

    snprintf(resp->extra_headers, sizeof(resp->extra_headers),
             "X-SSO-Access-Token: %s\r\n"
             "X-SSO-Refresh-Token: %s\r\n",
             access_token.token_str, refresh_token.token_str);

    char *buf = (char *)malloc(8192);
    if (!buf) {
        token_destroy(&access_token);
        token_destroy(&refresh_token);
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }
    snprintf(buf, 8192,
        "{"
        "\"expires_in\":%lld,"
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"display_name\":\"%s\""
        "}",
        (long long)access_token.expires_at,
        (unsigned long long)user.id,
        user.username,
        user.display_name);
    token_destroy(&access_token);
    token_destroy(&refresh_token);
    sso_response_ok(resp, buf);
    free(buf);
    return SSO_OK;
}

sso_error_t handle_send_sms(sso_context_t *ctx, const http_request_t *req,
                            http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *phone = json_str_value(req->body, "phone");
    if (!phone) {
        sso_response_error(resp, 400, "phone required");
        return SSO_OK;
    }

    /* 1. 安全防刷检查：IP 限流 (1 min / 1 request) */
    if (ctx->rate_limiter) {
        sso_error_t rerr = rate_limiter_check((rate_limiter_t *)ctx->rate_limiter, 
                                               req->client_ip, 60000, 1);
        if (rerr != SSO_OK) {
            free(phone);
            sso_response_error(resp, 429, "Too many SMS requests. Please wait 1 minute.");
            return SSO_OK;
        }
    }

    /* 2. 生成 6 位随机验证码 */
    char code[8];
    snprintf(code, sizeof(code), "%06d", rand() % 1000000);

    /* 3. 存储到数据库 sms_codes 表，设置 5 分钟 (300秒) 过期 */
    storage_backend_t *sb = (storage_backend_t *)ctx->storage_backend;
    sso_error_t err = SSO_ERR_NOT_IMPLEMENTED;
    if (sb && sb->save_sms_code) {
        err = sb->save_sms_code(sb, phone, code, sso_timestamp_now() + 300000);
    }

    if (err != SSO_OK) {
        free(phone);
        sso_response_error(resp, 500, "Failed to generate SMS code");
        return SSO_OK;
    }

    /* 4. 调用真实发送逻辑 (libcurl) */
    err = send_real_sms(phone, code);
    if (err != SSO_OK) {
        free(phone);
        sso_response_error(resp, 500, "SMS gateway error");
        return SSO_OK;
    }
    
    free(phone);
    sso_response_ok(resp, "{\"status\":\"sent\"}");
    return SSO_OK;
}

sso_error_t handle_login_by_sms(sso_context_t *ctx, const http_request_t *req,
                                http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    /* Rate limiting: IP-based (5 attempts/min/IP) to prevent brute-force */
    if (ctx->rate_limiter) {
        sso_error_t rerr = rate_limiter_check((rate_limiter_t *)ctx->rate_limiter,
                                               req->client_ip, 60000, 5);
        if (rerr != SSO_OK) {
            sso_response_error(resp, 429, "Too many SMS login attempts. Please wait.");
            return SSO_OK;
        }
    }

    char *phone = json_str_value(req->body, "phone");
    char *code  = json_str_value(req->body, "code");

    if (!phone || !code) {
        if (phone) free(phone);
        if (code) free(code);
        sso_response_error(resp, 400, "phone and code required");
        return SSO_OK;
    }

    /* Phone-level rate limiting (3 attempts/min/phone) to prevent targeted brute-force */
    if (ctx->rate_limiter) {
        char phone_key[128];
        snprintf(phone_key, sizeof(phone_key), "sms_login:%s", phone);
        sso_error_t rerr = rate_limiter_check((rate_limiter_t *)ctx->rate_limiter,
                                               phone_key, 60000, 3);
        if (rerr != SSO_OK) {
            free(phone); free(code);
            sso_response_error(resp, 429, "Too many attempts for this phone number. Please wait.");
            return SSO_OK;
        }
    }

    storage_backend_t *sb = (storage_backend_t *)ctx->storage_backend;
    if (!sb || !sb->get_sms_code || !sb->delete_sms_code) {
        free(phone); free(code);
        sso_response_error(resp, 500, "SMS feature not enabled in storage backend");
        return SSO_OK;
    }

    /* 1. 验证码校验 */
    char expected_code[16];
    sso_error_t err = sb->get_sms_code(sb, phone, expected_code);
    if (err != SSO_OK || strcmp(code, expected_code) != 0) {
        free(phone); free(code);
        sso_response_error(resp, 401, "Invalid or expired verification code");
        return SSO_OK;
    }

    /* 验证成功即销毁，防重放 */
    sb->delete_sms_code(sb, phone);
    free(code);

    /* 2. 获取用户 (如果不存在则自动注册) */
    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    err = user_get_by_phone(umgr, phone, &user);
    if (err == SSO_ERR_NOT_FOUND) {
        /* 自动注册：对于手机验证码登录，无需密码 */
        err = user_create_by_phone(umgr, phone, &user);
    }
    
    if (err != SSO_OK || user.status != USER_STATUS_ACTIVE) {
        free(phone);
        sso_response_error(resp, 403, "Account disabled or error");
        return SSO_OK;
    }
    free(phone);

    /* 3. 签发 JWT Token (复用现有的 token_issue) */
    sso_id_t roles[16], groups[16];
    size_t rc = 0, gc = 0;
    user_get_roles(umgr, user.id, roles, &rc, 16);
    user_get_groups(umgr, user.id, groups, &gc, 16);

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t token;
    err = token_issue(tmgr, &user, roles, rc, groups, gc, NULL, 3600000, &token);
    
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to issue token");
        return SSO_OK;
    }

    /* 4. 返回标准 Token */
    char *buf = (char *)malloc(8192);
    if (!buf) {
        token_destroy(&token);
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }
    snprintf(buf, 8192,
        "{"
        "\"token\":\"%s\","
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"phone\":\"%s\""
        "}",
        token.token_str,
        (unsigned long long)user.id,
        user.username,
        user.phone);
    sso_response_ok(resp, buf);
    free(buf);
    token_destroy(&token);
    return SSO_OK;
}

sso_error_t handle_register(sso_context_t *ctx, const http_request_t *req,
                            http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *username = json_str_value(req->body, "username");
    char *password = json_str_value(req->body, "password");
    char *email    = json_str_value(req->body, "email");
    char *display  = json_str_value(req->body, "display_name");

    if (!username || !password) {
        free(username); free(password); free(email); free(display);
        sso_response_error(resp, 400, "username and password required");
        return SSO_OK;
    }

    const char *pw_err = validate_password(password);
    if (pw_err) {
        free(username); free(password); free(email); free(display);
        sso_response_error(resp, 400, pw_err);
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    sso_error_t err = user_create(umgr, username, password,
                                  email ? email : "",
                                  display ? display : username,
                                  &user);

    if (err == SSO_OK) {
        /* Assign default 'user' role */
        role_manager_t *rmgr = (role_manager_t *)ctx->role_mgr;
        role_t member_role;
        if (role_get_by_name(rmgr, "user", &member_role) == SSO_OK) {
            role_assign_to_user(rmgr, member_role.id, user.id);
        } else {
            /* If 'user' role doesn't exist, try to create it */
            if (role_create(rmgr, "user", "Regular member", SSO_ID_NONE, &member_role) == SSO_OK) {
                role_assign_to_user(rmgr, member_role.id, user.id);
            }
        }
    }

    free(username); free(password); free(email); free(display);

    if (err == SSO_ERR_ALREADY_EXISTS) {
        sso_response_error(resp, 409, "Username already exists");
        return SSO_OK;
    }
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to create user");
        return SSO_OK;
    }

    char buf[512];
    snprintf(buf, sizeof(buf),
        "{\"user_id\":%llu,\"username\":\"%s\",\"created\":true}",
        (unsigned long long)user.id, user.username);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

sso_error_t handle_verify(sso_context_t *ctx, const http_request_t *req,
                          http_response_t *resp) {
    const char *token_str = NULL;
    if (req->body) {
        const char *t = json_str_value(req->body, "token");
        if (t) { token_str = t; }
    }
    if (!token_str && req->auth_token[0]) {
        token_str = req->auth_token;
    }
    if (!token_str) {
        sso_response_error(resp, 401, "Token required");
        return SSO_OK;
    }

    LOG_INFO("[verify] Verifying token: %.16s...", token_str);
    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t tok;
    sso_error_t err = token_verify(tmgr, token_str, &tok);
    if (token_str != req->auth_token) free((void*)token_str);

    if (err != SSO_OK) {
        LOG_WARN("[verify] Token verification failed: %s", sso_strerror(err));
        sso_response_error(resp, 401, sso_strerror(err));
        return SSO_OK;
    }
    if (token_is_revoked(tmgr, tok.jti)) {
        LOG_WARN("[verify] Token %s is revoked", tok.jti);
        sso_response_error(resp, 401, "Token revoked");
        token_destroy(&tok);
        return SSO_OK;
    }

    /* DPoP Verification if Token is bound to a JWK Thumbprint */
    if (tok.jkt[0]) {
        if (!req->dpop_proof[0]) {
            LOG_WARN("[verify] Missing required DPoP proof for bound token");
            sso_response_error(resp, 401, "DPoP Proof Required");
            token_destroy(&tok);
            return SSO_OK;
        }
        
        char verified_jkt[64] = {0};
        char full_url[1024];
        snprintf(full_url, sizeof(full_url), "http://%s%s", req->host[0] ? req->host : "localhost", req->path);
        
        if (dpop_verify_proof(req->dpop_proof, req->method_str, full_url, tok.jkt, verified_jkt) != SSO_OK) {
            LOG_WARN("[verify] Invalid DPoP proof signature or thumbprint mismatch");
            sso_response_error(resp, 401, "Invalid DPoP Proof");
            token_destroy(&tok);
            return SSO_OK;
        }
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    err = user_get_by_id(umgr, tok.user_id, &user);
    if (err != SSO_OK) {
        LOG_WARN("[verify] User not found for ID %llu", (unsigned long long)tok.user_id);
        sso_response_error(resp, 401, "User not found");
        token_destroy(&tok);
        return SSO_OK;
    }

    LOG_INFO("[verify] Authentication successful for user: %s", user.username);
    
    char rotation_header[1024] = "";
    sso_timestamp_t now = sso_timestamp_now();
    sso_timestamp_t ttl = tok.expires_at - tok.issued_at;
    
    /* Silent Token Rotation: if more than half of the TTL has passed, issue a fresh token */
    if (ttl > 0 && now >= tok.issued_at && (now - tok.issued_at) > (ttl / 2)) {
        token_t new_tok;
        memset(&new_tok, 0, sizeof(new_tok));
        if (tok.jkt[0]) sso_strlcpy(new_tok.jkt, tok.jkt, sizeof(new_tok.jkt));
        
        if (token_issue(tmgr, &user, tok.role_ids, tok.role_count, tok.group_ids, tok.group_count, tok.scope, ttl, &new_tok) == SSO_OK) {
            snprintf(rotation_header, sizeof(rotation_header), "X-SSO-Access-Token: %s\r\n", new_tok.token_str);
            LOG_INFO("[verify] Silent rotation triggered. Issued new token for user %llu", (unsigned long long)user.id);
            token_destroy(&new_tok);
        }
    }

    snprintf(resp->extra_headers, sizeof(resp->extra_headers), 
             "X-SSO-User: %s\r\n"
             "X-SSO-Email: %s\r\n"
             "%s", 
             user.username, user.email, rotation_header);

    char *buf = (char *)malloc(8192);
    if (!buf) {
        token_destroy(&tok);
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }
    snprintf(buf, 8192,
        "{"
        "\"valid\":true,"
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"email\":\"%s\","
        "\"display_name\":\"%s\","
        "\"expires_at\":%lld"
        "}",
        (unsigned long long)user.id,
        user.username,
        user.email,
        user.display_name,
        (long long)tok.expires_at);
    sso_response_ok(resp, buf);
    free(buf);
    token_destroy(&tok);
    return SSO_OK;
}

sso_error_t handle_refresh(sso_context_t *ctx, const http_request_t *req,
                           http_response_t *resp) {
    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *refresh_token_str = json_str_value(req->body, "refresh_token");
    if (!refresh_token_str) {
        sso_response_error(resp, 400, "refresh_token required");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t old_token;
    sso_error_t err = token_verify(tmgr, refresh_token_str, &old_token);
    free(refresh_token_str);
    if (err != SSO_OK) {
        const char *msg = (err == SSO_ERR_TOKEN_EXPIRED) ? "Refresh token expired" : "Invalid refresh token";
        sso_response_error(resp, 401, msg);
        return SSO_OK;
    }

    if (token_is_revoked(tmgr, old_token.jti)) {
        token_destroy(&old_token);
        sso_response_error(resp, 401, "Refresh token revoked");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    err = user_get_by_id(umgr, old_token.user_id, &user);
    if (err != SSO_OK) {
        token_destroy(&old_token);
        sso_response_error(resp, 401, "User not found");
        return SSO_OK;
    }

    token_t access_token, refresh_token;
    err = token_issue(tmgr, &user,
                      old_token.role_ids, old_token.role_count,
                      old_token.group_ids, old_token.group_count,
                      NULL, 900000, &access_token);
    if (err == SSO_OK) {
        err = token_issue(tmgr, &user,
                          old_token.role_ids, old_token.role_count,
                          old_token.group_ids, old_token.group_count,
                          NULL, 604800000, &refresh_token);
    }
    token_destroy(&old_token);

    if (err != SSO_OK) {
        token_destroy(&access_token);
        sso_response_error(resp, 500, "Failed to issue tokens");
        return SSO_OK;
    }

    snprintf(resp->extra_headers, sizeof(resp->extra_headers),
             "X-SSO-Access-Token: %s\r\n"
             "X-SSO-Refresh-Token: %s\r\n",
             access_token.token_str, refresh_token.token_str);

    char *buf = (char *)malloc(8192);
    if (!buf) {
        token_destroy(&access_token);
        token_destroy(&refresh_token);
        sso_response_error(resp, 500, "Out of memory");
        return SSO_OK;
    }
    snprintf(buf, 8192,
        "{"
        "\"status\":\"refreshed\""
        "}");
    token_destroy(&access_token);
    token_destroy(&refresh_token);
    sso_response_ok(resp, buf);
    free(buf);
    return SSO_OK;
}

sso_error_t handle_logout(sso_context_t *ctx, const http_request_t *req,
                          http_response_t *resp) {
    auth_context_t *auth = (auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    sso_error_t err = token_revoke(tmgr, auth->token.jti, auth->token.expires_at);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to revoke token");
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"logged_out\":true}");
    return SSO_OK;
}

sso_error_t handle_logout_all(sso_context_t *ctx, const http_request_t *req,
                              http_response_t *resp) {
    auth_context_t *auth = (auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    sso_error_t err = token_bump_nonce(tmgr, auth->user.id);
    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to revoke all sessions");
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"logged_out_all\":true}");
    return SSO_OK;
}

sso_error_t handle_change_password(sso_context_t *ctx, const http_request_t *req,
                                   http_response_t *resp) {
    auth_context_t *auth = (auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    if (!req->body) {
        sso_response_error(resp, 400, "Request body required");
        return SSO_OK;
    }

    char *new_pass = json_str_value(req->body, "password");
    const char *pw_err = validate_password(new_pass);
    if (pw_err) {
        if (new_pass) free(new_pass);
        sso_response_error(resp, 400, pw_err);
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    sso_error_t err = user_set_password(umgr, auth->user.id, new_pass);
    free(new_pass);

    if (err != SSO_OK) {
        sso_response_error(resp, 500, "Failed to update password");
        return SSO_OK;
    }

    sso_response_ok(resp, "{\"updated\":true}");
    return SSO_OK;
}

sso_error_t handle_me(sso_context_t *ctx, const http_request_t *req,
                        http_response_t *resp) {
    (void)ctx;
    const auth_context_t *auth = (const auth_context_t *)req->userdata;
    if (!auth) {
        sso_response_error(resp, 401, "Authentication required");
        return SSO_OK;
    }

    snprintf(resp->extra_headers, sizeof(resp->extra_headers), "X-SSO-User: %s\r\n", auth->user.username);

    char buf[4096];
    snprintf(buf, sizeof(buf),
        "{"
        "\"id\":%llu,"
        "\"username\":\"%s\","
        "\"email\":\"%s\","
        "\"display_name\":\"%s\","
        "\"token_jti\":\"%s\""
        "}",
        (unsigned long long)auth->user.id,
        auth->user.username,
        auth->user.email,
        auth->user.display_name,
        auth->token.jti);
    sso_response_ok(resp, buf);
    return SSO_OK;
}

sso_error_t handle_certs(sso_context_t *ctx, const http_request_t *req,
                         http_response_t *resp) {
    (void)req;
    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    if (tmgr->mode != SSO_TOKEN_MODE_RS256) {
        sso_response_error(resp, 404, "Server not in RS256 mode");
        return SSO_OK;
    }

    char *pem = token_manager_get_public_key_pem(tmgr);
    if (!pem) {
        sso_response_error(resp, 500, "Failed to export public key");
        return SSO_OK;
    }

    /* Wrap in JSON */
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "public_key", pem);
    cJSON_AddStringToObject(root, "alg", "RS256");

    char *json = cJSON_PrintUnformatted(root);
    sso_response_ok(resp, json);

    cJSON_free(json);
    cJSON_Delete(root);
    free(pem);
    return SSO_OK;
}

/* ========================================================================
 * GET /api/v1/auth/session-check
 *
 * Nginx auth_request endpoint. Validates a Bearer JWT token and returns:
 *   200 + X-SSO-User / X-SSO-Email headers on success
 *   401 on failure
 *
 * Designed for nginx auth_request: expects the token in the
 * Authorization header (set by nginx via proxy_set_header from cookie).
 * ======================================================================== */
sso_error_t handle_session_check(sso_context_t *ctx,
                                 const http_request_t *req,
                                 http_response_t *resp) {
    const char *token_str = req->auth_token;
    if (!token_str || !token_str[0]) {
        sso_response_error(resp, 401, "No token");
        return SSO_OK;
    }

    token_manager_t *tmgr = (token_manager_t *)ctx->token_mgr;
    token_t tok;
    sso_error_t err = token_verify(tmgr, token_str, &tok);
    if (err != SSO_OK) {
        sso_response_error(resp, 401, sso_strerror(err));
        return SSO_OK;
    }
    if (token_is_revoked(tmgr, tok.jti)) {
        token_destroy(&tok);
        sso_response_error(resp, 401, "Token revoked");
        return SSO_OK;
    }

    user_manager_t *umgr = (user_manager_t *)ctx->user_mgr;
    user_t user;
    err = user_get_by_id(umgr, tok.user_id, &user);
    if (err != SSO_OK || user.status != USER_STATUS_ACTIVE) {
        token_destroy(&tok);
        sso_response_error(resp, 401, "User not found or inactive");
        return SSO_OK;
    }

    /* Set X-SSO-User header for nginx auth_request_set to capture */
    snprintf(resp->extra_headers, sizeof(resp->extra_headers),
             "X-SSO-User: %s\r\n"
             "X-SSO-Email: %s\r\n"
             "X-SSO-User-Id: %llu\r\n",
             user.username,
             user.email,
             (unsigned long long)user.id);

    /* Return minimal JSON body */
    char buf[512];
    snprintf(buf, sizeof(buf),
        "{"
        "\"active\":true,"
        "\"user_id\":%llu,"
        "\"username\":\"%s\","
        "\"email\":\"%s\""
        "}",
        (unsigned long long)user.id,
        user.username,
        user.email);
    sso_response_ok(resp, buf);
    token_destroy(&tok);
    return SSO_OK;
}
