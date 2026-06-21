#ifndef HANDLERS_H
#define HANDLERS_H

#include "sso.h"
#include "server.h"
#include "config.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>

/* -----------------------------------------------------------------------
 * Shared utilities
 * ----------------------------------------------------------------------- */
uint64_t	get_time_ms(void);
void		parse_query_params(const http_request_t* req, char* q, int* status, int* page, int* limit);
sso_id_t	extract_path_id(const char* path, const char* prefix);
sso_error_t send_real_sms(const char* phone, const char* code);
char*		json_str_value(const char* json, const char* key);
int64_t		json_int_value(const char* json, const char* key, int64_t def);
const char* validate_password(const char* password, const password_policy_t* policy);

/* -----------------------------------------------------------------------
 * Page / monitoring handlers
 * ----------------------------------------------------------------------- */
sso_error_t handle_health(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);

sso_error_t handle_metrics(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_admin_status(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_list_audit_logs(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);

/* -----------------------------------------------------------------------
 * Auth handlers
 * ----------------------------------------------------------------------- */
sso_error_t handle_login(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_mfa_setup(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_mfa_enable(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_mfa_verify(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_send_sms(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_login_by_sms(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_webauthn_register_challenge(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_webauthn_register(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_webauthn_login_challenge(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_webauthn_login(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_register(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_verify(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_refresh(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_logout(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_logout_all(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_change_password(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_me(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_certs(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_session_check(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);

/* -----------------------------------------------------------------------
 * Check handlers
 * ----------------------------------------------------------------------- */
sso_error_t handle_check_permission(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_check_functional(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_check_api(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_check_data(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_check_rbac(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_check_location(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_check_lbac(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_check_abac(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);

/* -----------------------------------------------------------------------
 * Admin CRUD handlers
 * ----------------------------------------------------------------------- */
sso_error_t handle_list_users(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_create_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_get_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_update_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_delete_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_list_roles(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_create_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_update_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_delete_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_assign_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_unassign_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_list_groups(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_create_group(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_update_group(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_delete_group(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_add_group_member(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_remove_group_member(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_list_policies(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_create_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_update_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_delete_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_assign_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_unassign_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_get_user_policies(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_get_policy_targets(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_list_clients(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_create_client(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_update_client(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);
sso_error_t handle_delete_client(sso_context_t* ctx, const http_request_t* req, http_response_t* resp);

/* -----------------------------------------------------------------------
 * Demo / interactive mode entry points
 * ----------------------------------------------------------------------- */
int run_demo(sso_config_t* cfg);
int interactive_config(sso_config_t* cfg);

#endif /* HANDLERS_H */
