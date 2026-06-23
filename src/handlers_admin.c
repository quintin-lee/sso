/*
 * handlers_admin.c — Admin CRUD HTTP request handlers.
 *
 * Implements all /api/v1/users, /roles, /groups, /policies, and
 * /clients endpoints.  Provides create, read, update, delete, and
 * assignment (user<->role, user<->group, policy<->target) operations
 * via JSON request/response over the embedded HTTP server.
 */

#include "sso.h"
#include "server.h"
#include "handlers.h"
#include "logger.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "storage.h"
#include "permission.h"

#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define admin_audit_log(cfg, ...) admin_audit_log(ctx, __VA_ARGS__)

sso_error_t handle_create_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* username = req_json_str_value(req, "username");
	char* password = req_json_str_value(req, "password");
	char* email	   = req_json_str_value(req, "email");
	char* display  = req_json_str_value(req, "display_name");

	if (!username || !password) {
		/* free(username); */
		/* free(password); */
		/* free(email); */
		/* free(display); */
		sso_response_error(resp, 400, "username and password required");
		return SSO_OK;
	}

	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	user_t			user;
	sso_error_t err = user_create(umgr, username, password, email ? email : "", display ? display : username, &user);
	/* free(username); */
	/* free(password); */
	/* free(email); */
	/* free(display); */

	if (err == SSO_ERR_ALREADY_EXISTS) {
		sso_response_error(resp, 409, "Username already exists");
		return SSO_OK;
	}
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to create user");
		return SSO_OK;
	}

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"user_id\":%llu,\"username\":\"%s\",\"created\":true}", (unsigned long long)user.id,
			 user.username);
	sso_response_ok(resp, buf);
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		if (a) {
			admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "create_user",
							"users", user.id, "success", buf);
		} else {
			admin_audit_log((sso_config_t*)ctx->config, 0, "system", req->client_ip, "create_user", "users", user.id,
							"success", buf);
		}
	}
	return SSO_OK;
}

sso_error_t handle_create_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* name = req_json_str_value(req, "name");
	if (!name) {
		sso_response_error(resp, 400, "name required");
		return SSO_OK;
	}
	char*	 desc	   = req_json_str_value(req, "description");
	sso_id_t parent_id = (sso_id_t)json_int_value(req->body, "parent_role_id", 0);

	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;
	role_t			role;
	sso_error_t		err = role_create(rmgr, name, desc ? desc : "", parent_id, &role);
	/* free(name); */
	/* free(desc); */
	if (err == SSO_OK) {
		int status = (int)json_int_value(req->body, "status", -1);
		if (status >= 0) {
			role.status = (role_status_t)status;
			role_update(rmgr, &role);
		}
	}
	if (err == SSO_ERR_ALREADY_EXISTS) {
		sso_response_error(resp, 409, "Role already exists");
		return SSO_OK;
	}
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to create role");
		return SSO_OK;
	}

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"role_id\":%llu,\"name\":\"%s\",\"created\":true}", (unsigned long long)role.id,
			 role.name);
	sso_response_ok(resp, buf);
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "create_role",
						"roles", role.id, "success", buf);
	}
	return SSO_OK;
}

sso_error_t handle_assign_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	/* Parse role_id from path: /api/v1/roles/NNN/assign */
	sso_id_t	role_id = 0;
	const char* p		= req->path;
	/* Skip to role id segment */
	const char* id_start = strstr(p, "/roles/");
	if (id_start) {
		id_start += 7; /* past "/roles/" */
		role_id = (sso_id_t)atoll(id_start);
	}

	if (!role_id) {
		sso_response_error(resp, 400, "Invalid role ID in path");
		return SSO_OK;
	}

	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	sso_id_t user_id  = (sso_id_t)json_int_value(req->body, "user_id", 0);
	sso_id_t group_id = (sso_id_t)json_int_value(req->body, "group_id", 0);

	if (user_id == 0 && group_id == 0) {
		sso_response_error(resp, 400, "user_id or group_id required");
		return SSO_OK;
	}

	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;
	sso_error_t		err;
	if (user_id != 0) {
		err = role_assign_to_user(rmgr, role_id, user_id);
	} else {
		err = role_assign_to_group(rmgr, role_id, group_id);
	}
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"assigned\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Assigned role %llu to %s %llu", (unsigned long long)role_id,
				 user_id ? "user" : "group", (unsigned long long)(user_id ? user_id : group_id));
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "assign_role",
						"roles", role_id, "success", det);
	}
	return SSO_OK;
}

/* ========================================================================
 * List handlers — return JSON arrays of objects
 * ======================================================================== */

sso_error_t handle_list_users(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	char q[SSO_MAX_QUERY];
	int	 status, page, limit;
	parse_query_params(req, q, &status, &page, &limit);

	int offset = (page - 1) * limit;

	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;
	sso_id_t		ids[100];
	size_t			count		= 0;
	size_t			total_count = 0;

	sso_error_t err = user_list(umgr, q, status, offset, limit, ids, &count, &total_count);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to list users");
		return SSO_OK;
	}

	size_t total_json_len = 1024; /* Metadata + brackets */
	for (size_t i = 0; i < count; i++)
		total_json_len += 3072;

	char* json = (char*)arena_alloc((arena_t*)&req->arena, (1) * (total_json_len + 1));
	if (!json) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	snprintf(json, total_json_len, "{\"total\":%zu,\"page\":%d,\"limit\":%d,\"items\":[", total_count, page, limit);

	char* buf = (char*)arena_alloc((arena_t*)&req->arena, 4096);
	if (!buf) {
		/* free(json); */
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	for (size_t i = 0; i < count; i++) {
		user_t u;
		err = user_get_by_id(umgr, ids[i], &u);
		if (err != SSO_OK)
			continue;

		/* Get roles for this user */
		sso_id_t role_ids[16];
		size_t	 rc = 0;
		user_get_roles(umgr, u.id, role_ids, &rc, 16);

		char roles_json[1024];
		roles_json[0] = '\0';
		strcat(roles_json, "[");
		for (size_t j = 0; j < rc; j++) {
			role_t r;
			if (role_get_by_id(rmgr, role_ids[j], &r) == SSO_OK) {
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "%s{\"id\":%llu,\"name\":\"%s\"}", j > 0 ? "," : "",
						 (unsigned long long)r.id, r.name);
				strcat(roles_json, tmp);
			}
		}
		strcat(roles_json, "]");

		/* Get groups for this user */
		sso_id_t group_ids[16];
		size_t	 gc = 0;
		user_get_groups(umgr, u.id, group_ids, &gc, 16);
		group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;

		char groups_json[1024];
		groups_json[0] = '\0';
		strcat(groups_json, "[");
		for (size_t j = 0; j < gc; j++) {
			group_t g;
			if (group_get_by_id(gmgr, group_ids[j], &g) == SSO_OK) {
				char tmp[128];
				snprintf(tmp, sizeof(tmp), "%s{\"id\":%llu,\"name\":\"%s\"}", j > 0 ? "," : "",
						 (unsigned long long)g.id, g.name);
				strcat(groups_json, tmp);
			}
		}
		strcat(groups_json, "]");

		snprintf(buf, 4096,
				 "%s{"
				 "\"id\":%llu,"
				 "\"username\":\"%s\","
				 "\"email\":\"%s\","
				 "\"display_name\":\"%s\","
				 "\"phone\":\"%s\","
				 "\"status\":%d,"
				 "\"roles\":%s,"
				 "\"groups\":%s,"
				 "\"created_at\":%lld"
				 "}",
				 i > 0 ? "," : "", (unsigned long long)u.id, u.username, u.email, u.display_name, u.phone,
				 (int)u.status, roles_json, groups_json, (long long)u.created_at);
		strcat(json, buf);
	}
	strcat(json, "]}");
	/* free(buf); */

	sso_response_ok(resp, json);
	/* free(json); */
	return SSO_OK;
}

sso_error_t handle_get_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t user_id = extract_path_id(req->path, "/api/v1/users/");
	if (user_id == 0) {
		sso_response_error(resp, 400, "Invalid user ID");
		return SSO_OK;
	}

	user_manager_t*	 umgr = (user_manager_t*)ctx->user_mgr;
	role_manager_t*	 rmgr = (role_manager_t*)ctx->role_mgr;
	group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;

	user_t		u;
	sso_error_t err = user_get_by_id(umgr, user_id, &u);
	if (err != SSO_OK) {
		sso_response_error(resp, 404, "User not found");
		return SSO_OK;
	}

	sso_id_t role_ids[16];
	size_t	 rc = 0;
	user_get_roles(umgr, u.id, role_ids, &rc, 16);

	char roles_json[1024];
	roles_json[0] = '\0';
	strcat(roles_json, "[");
	for (size_t j = 0; j < rc; j++) {
		role_t r;
		if (role_get_by_id(rmgr, role_ids[j], &r) == SSO_OK) {
			char buf[128];
			snprintf(buf, sizeof(buf), "%s{\"id\":%llu,\"name\":\"%s\"}", j > 0 ? "," : "", (unsigned long long)r.id,
					 r.name);
			strcat(roles_json, buf);
		}
	}
	strcat(roles_json, "]");

	sso_id_t group_ids[16];
	size_t	 gc = 0;
	user_get_groups(umgr, u.id, group_ids, &gc, 16);

	char groups_json[1024];
	groups_json[0] = '\0';
	strcat(groups_json, "[");
	for (size_t j = 0; j < gc; j++) {
		group_t g;
		if (group_get_by_id(gmgr, group_ids[j], &g) == SSO_OK) {
			char buf[128];
			snprintf(buf, sizeof(buf), "%s{\"id\":%llu,\"name\":\"%s\"}", j > 0 ? "," : "", (unsigned long long)g.id,
					 g.name);
			strcat(groups_json, buf);
		}
	}
	strcat(groups_json, "]");

	char* json = (char*)arena_alloc((arena_t*)&req->arena, 4096);
	if (!json) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	snprintf(json, 4096,
			 "{"
			 "\"id\":%llu,"
			 "\"username\":\"%s\","
			 "\"email\":\"%s\","
			 "\"display_name\":\"%s\","
			 "\"phone\":\"%s\","
			 "\"status\":%d,"
			 "\"roles\":%s,"
			 "\"groups\":%s,"
			 "\"created_at\":%lld"
			 "}",
			 (unsigned long long)u.id, u.username, u.email, u.display_name, u.phone, (int)u.status, roles_json,
			 groups_json, (long long)u.created_at);

	sso_response_ok(resp, json);
	/* free(json); */
	return SSO_OK;
}

sso_error_t handle_list_roles(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	char q[SSO_MAX_QUERY];
	int	 status, page, limit;
	parse_query_params(req, q, &status, &page, &limit);

	int offset = (page - 1) * limit;

	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;
	sso_id_t		ids[100];
	size_t			count		= 0;
	size_t			total_count = 0;

	sso_error_t err = role_list(rmgr, q, status, offset, limit, ids, &count, &total_count);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to list roles");
		return SSO_OK;
	}

	size_t total_json_len = 1024;
	for (size_t i = 0; i < count; i++)
		total_json_len += 2048;

	char* json = (char*)arena_alloc((arena_t*)&req->arena, (1) * (total_json_len + 1));
	if (!json) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	snprintf(json, total_json_len, "{\"total\":%zu,\"page\":%d,\"limit\":%d,\"items\":[", total_count, page, limit);

	char* buf = (char*)arena_alloc((arena_t*)&req->arena, 4096);
	if (!buf) {
		/* free(json); */
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	for (size_t i = 0; i < count; i++) {
		role_t r;
		err = role_get_by_id(rmgr, ids[i], &r);
		if (err != SSO_OK)
			continue;

		/* Get parent role name */
		char parent_name[64] = "";
		if (r.parent_role_id != 0) {
			role_t parent;
			if (role_get_by_id(rmgr, r.parent_role_id, &parent) == SSO_OK) {
				snprintf(parent_name, sizeof(parent_name), "%s", parent.name);
			}
		}

		snprintf(buf, 4096,
				 "%s{"
				 "\"id\":%llu,"
				 "\"name\":\"%s\","
				 "\"description\":\"%s\","
				 "\"parent_role_id\":%llu,"
				 "\"parent_name\":\"%s\","
				 "\"status\":%d,"
				 "\"created_at\":%lld"
				 "}",
				 i > 0 ? "," : "", (unsigned long long)r.id, r.name, r.description,
				 (unsigned long long)r.parent_role_id, parent_name, (int)r.status, (long long)r.created_at);
		strcat(json, buf);
	}
	strcat(json, "]}");
	/* free(buf); */

	sso_response_ok(resp, json);
	/* free(json); */
	return SSO_OK;
}

sso_error_t handle_list_policies(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	char q[SSO_MAX_QUERY];
	int	 status, page, limit;
	parse_query_params(req, q, &status, &page, &limit);

	int offset = (page - 1) * limit;

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;
	sso_id_t		  ids[100];
	size_t			  count		  = 0;
	size_t			  total_count = 0;

	sso_error_t err = policy_list(pmgr, q, status, offset, limit, ids, &count, &total_count);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to list policies");
		return SSO_OK;
	}

	size_t total_json_len = 1024;
	for (size_t i = 0; i < count; i++)
		total_json_len += 8192;

	char* json = (char*)arena_alloc((arena_t*)&req->arena, (1) * (total_json_len + 1));
	if (!json) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	snprintf(json, total_json_len, "{\"total\":%zu,\"page\":%d,\"limit\":%d,\"items\":[", total_count, page, limit);

	char* buf = (char*)arena_alloc((arena_t*)&req->arena, 10240);
	if (!buf) {
		/* free(json); */
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	for (size_t i = 0; i < count; i++) {
		policy_t p;
		err = policy_get_by_id(pmgr, ids[i], &p);
		if (err != SSO_OK)
			continue;

		snprintf(buf, 10240,
				 "%s{"
				 "\"id\":%llu,"
				 "\"name\":\"%s\","
				 "\"strategy_type\":%d,"
				 "\"strategy_name\":\"%s\","
				 "\"effect\":%d,"
				 "\"priority\":%d,"
				 "\"status\":%d,"
				 "\"rules\":%.8000s,"
				 "\"created_at\":%lld"
				 "}",
				 i > 0 ? "," : "", (unsigned long long)p.id, p.name, (int)p.strategy_type,
				 perm_strategy_name(p.strategy_type), (int)p.effect, p.priority, (int)p.status, p.rules,
				 (long long)p.created_at);
		strcat(json, buf);
	}
	strcat(json, "]}");
	/* free(buf); */

	sso_response_ok(resp, json);
	/* free(json); */
	return SSO_OK;
}

sso_error_t handle_list_groups(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	char q[SSO_MAX_QUERY];
	int	 status, page, limit;
	parse_query_params(req, q, &status, &page, &limit);

	int offset = (page - 1) * limit;

	group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;
	sso_id_t		 ids[100];
	size_t			 count		 = 0;
	size_t			 total_count = 0;

	sso_error_t err = group_list(gmgr, q, status, offset, limit, ids, &count, &total_count);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to list groups");
		return SSO_OK;
	}

	size_t total_json_len = 1024;
	for (size_t i = 0; i < count; i++)
		total_json_len += 2048;

	char* json = (char*)arena_alloc((arena_t*)&req->arena, (1) * (total_json_len + 1));
	if (!json) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	snprintf(json, total_json_len, "{\"total\":%zu,\"page\":%d,\"limit\":%d,\"items\":[", total_count, page, limit);

	char* buf = (char*)arena_alloc((arena_t*)&req->arena, 4096);
	if (!buf) {
		/* free(json); */
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}

	for (size_t i = 0; i < count; i++) {
		group_t g;
		err = group_get_by_id(gmgr, ids[i], &g);
		if (err != SSO_OK)
			continue;

		char parent_name[64] = "";
		if (g.parent_group_id != 0) {
			group_t parent;
			if (group_get_by_id(gmgr, g.parent_group_id, &parent) == SSO_OK) {
				snprintf(parent_name, sizeof(parent_name), "%s", parent.name);
			}
		}

		snprintf(buf, 4096,
				 "%s{"
				 "\"id\":%llu,"
				 "\"name\":\"%s\","
				 "\"description\":\"%s\","
				 "\"parent_group_id\":%llu,"
				 "\"parent_name\":\"%s\","
				 "\"status\":%d,"
				 "\"created_at\":%lld"
				 "}",
				 i > 0 ? "," : "", (unsigned long long)g.id, g.name, g.description,
				 (unsigned long long)g.parent_group_id, parent_name, (int)g.status, (long long)g.created_at);
		strcat(json, buf);
	}
	strcat(json, "]}");
	/* free(buf); */

	sso_response_ok(resp, json);
	/* free(json); */
	return SSO_OK;
}

sso_error_t handle_create_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* name = req_json_str_value(req, "name");
	if (!name) {
		sso_response_error(resp, 400, "name required");
		return SSO_OK;
	}

	int	  strategy_type = (int)json_int_value(req->body, "strategy_type", 1);
	int	  effect		= (int)json_int_value(req->body, "effect", 1);
	int	  priority		= (int)json_int_value(req->body, "priority", 50);
	char* rules			= req_json_str_value(req, "rules");

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;
	policy_t		  policy;
	sso_error_t err = policy_create(pmgr, name, (perm_strategy_type_t)strategy_type, (policy_effect_t)effect, priority,
									rules ? rules : "{}", &policy);
	/* free(name); */
	/* free(rules); */

	if (err == SSO_ERR_ALREADY_EXISTS) {
		sso_response_error(resp, 409, "Policy already exists");
		return SSO_OK;
	}
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to create policy");
		return SSO_OK;
	}

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"policy_id\":%llu,\"name\":\"%s\",\"created\":true}", (unsigned long long)policy.id,
			 policy.name);
	sso_response_ok(resp, buf);
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "create_policy",
						"policies", policy.id, "success", buf);
	}
	return SSO_OK;
}

sso_error_t handle_assign_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t	policy_id = 0;
	const char* p		  = req->path;
	const char* id_start  = strstr(p, "/policies/");
	if (id_start) {
		id_start += 10;
		policy_id = (sso_id_t)atoll(id_start);
	}

	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	int		 target_type = (int)json_int_value(req->body, "target_type", 0);
	sso_id_t target_id	 = (sso_id_t)json_int_value(req->body, "target_id", 0);

	if (target_id == 0) {
		sso_response_error(resp, 400, "target_id required");
		return SSO_OK;
	}

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;
	sso_error_t		  err  = policy_assign_to(pmgr, policy_id, (policy_target_type_t)target_type, target_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"assigned\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		const char*		tnames[] = {"user", "role", "group"};
		snprintf(det, sizeof(det), "Assigned policy %llu to %s %llu", (unsigned long long)policy_id,
				 (size_t)target_type < 3 ? tnames[target_type] : "?", (unsigned long long)target_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "assign_policy",
						"policies", policy_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_create_group(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* name = req_json_str_value(req, "name");
	if (!name) {
		sso_response_error(resp, 400, "name required");
		return SSO_OK;
	}
	char*	 desc	   = req_json_str_value(req, "description");
	sso_id_t parent_id = (sso_id_t)json_int_value(req->body, "parent_group_id", 0);

	group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;
	group_t			 group;
	sso_error_t		 err = group_create(gmgr, name, desc ? desc : "", parent_id, &group);
	/* free(name); */
	/* free(desc); */
	if (err == SSO_OK) {
		int status = (int)json_int_value(req->body, "status", -1);
		if (status >= 0) {
			group.status = (group_status_t)status;
			group_update(gmgr, &group);
		}
	}
	if (err == SSO_ERR_ALREADY_EXISTS) {
		sso_response_error(resp, 409, "Group already exists");
		return SSO_OK;
	}
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to create group");
		return SSO_OK;
	}

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"id\":%llu,\"name\":\"%s\",\"created\":true}", (unsigned long long)group.id,
			 group.name);
	sso_response_ok(resp, buf);
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "create_group",
						"groups", group.id, "success", buf);
	}
	return SSO_OK;
}

sso_error_t handle_update_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t user_id = extract_path_id(req->path, "/users/");
	if (!user_id || !req->body) {
		sso_response_error(resp, 400, "user_id and body required");
		return SSO_OK;
	}

	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	user_t			user;
	sso_error_t		err = user_get_by_id(umgr, user_id, &user);
	if (err != SSO_OK) {
		sso_response_error(resp, 404, "User not found");
		return SSO_OK;
	}

	char* email	  = req_json_str_value(req, "email");
	char* display = req_json_str_value(req, "display_name");
	int	  status  = (int)json_int_value(req->body, "status", -1);

	if (email) {
		sso_strlcpy(user.email, email, SSO_MAX_EMAIL);
		/* free(email); */
	}
	if (display) {
		sso_strlcpy(user.display_name, display, SSO_MAX_DISPLAY_NAME);
		/* free(display); */
	}
	if (status >= 0) {
		user.status = (user_status_t)status;
	}

	err = user_update(umgr, &user);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"updated\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Updated user %llu (%s)", (unsigned long long)user.id, user.username);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "update_user",
						"users", user.id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_delete_user(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t user_id = extract_path_id(req->path, "/users/");
	if (!user_id) {
		sso_response_error(resp, 400, "user_id required");
		return SSO_OK;
	}

	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	sso_error_t		err	 = user_delete(umgr, user_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"deleted\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Deleted user %llu", (unsigned long long)user_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "delete_user",
						"users", user_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_update_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t role_id = extract_path_id(req->path, "/roles/");
	if (!role_id || !req->body) {
		sso_response_error(resp, 400, "role_id and body required");
		return SSO_OK;
	}

	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;
	role_t			role;
	sso_error_t		err = role_get_by_id(rmgr, role_id, &role);
	if (err != SSO_OK) {
		sso_response_error(resp, 404, "Role not found");
		return SSO_OK;
	}

	char*	 name	= req_json_str_value(req, "name");
	char*	 desc	= req_json_str_value(req, "description");
	sso_id_t parent = (sso_id_t)json_int_value(req->body, "parent_role_id", -1);
	int		 status = (int)json_int_value(req->body, "status", -1);

	if (name) {
		sso_strlcpy(role.name, name, SSO_MAX_ROLE_NAME);
		/* free(name); */
	}
	if (desc) {
		sso_strlcpy(role.description, desc, SSO_MAX_DESCRIPTION);
		/* free(desc); */
	}
	if (parent != (sso_id_t)-1) {
		role.parent_role_id = parent;
	}
	if (status >= 0) {
		role.status = (role_status_t)status;
	}

	err = role_update(rmgr, &role);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"updated\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Updated role %llu (%s)", (unsigned long long)role.id, role.name);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "update_role",
						"roles", role.id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_delete_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t role_id = extract_path_id(req->path, "/roles/");
	if (!role_id) {
		sso_response_error(resp, 400, "role_id required");
		return SSO_OK;
	}

	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;
	sso_error_t		err	 = role_delete(rmgr, role_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"deleted\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Deleted role %llu", (unsigned long long)role_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "delete_role",
						"roles", role_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_unassign_role(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t role_id = extract_path_id(req->path, "/roles/");
	if (!role_id || !req->body) {
		sso_response_error(resp, 400, "role_id and body required");
		return SSO_OK;
	}

	sso_id_t user_id  = (sso_id_t)json_int_value(req->body, "user_id", 0);
	sso_id_t group_id = (sso_id_t)json_int_value(req->body, "group_id", 0);

	role_manager_t* rmgr = (role_manager_t*)ctx->role_mgr;
	sso_error_t		err;
	if (user_id != 0) {
		err = role_unassign_from_user(rmgr, role_id, user_id);
	} else if (group_id != 0) {
		err = role_unassign_from_group(rmgr, role_id, group_id);
	} else {
		sso_response_error(resp, 400, "user_id or group_id required");
		return SSO_OK;
	}

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"unassigned\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Unassigned role %llu from %s %llu", (unsigned long long)role_id,
				 user_id ? "user" : "group", (unsigned long long)(user_id ? user_id : group_id));
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "unassign_role",
						"roles", role_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_update_group(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t group_id = extract_path_id(req->path, "/groups/");
	if (!group_id || !req->body) {
		sso_response_error(resp, 400, "group_id and body required");
		return SSO_OK;
	}

	group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;
	group_t			 group;
	sso_error_t		 err = group_get_by_id(gmgr, group_id, &group);
	if (err != SSO_OK) {
		sso_response_error(resp, 404, "Group not found");
		return SSO_OK;
	}

	char*	 name	= req_json_str_value(req, "name");
	char*	 desc	= req_json_str_value(req, "description");
	sso_id_t parent = (sso_id_t)json_int_value(req->body, "parent_group_id", -1);
	int		 status = (int)json_int_value(req->body, "status", -1);

	if (name) {
		sso_strlcpy(group.name, name, SSO_MAX_GROUP_NAME);
		/* free(name); */
	}
	if (desc) {
		sso_strlcpy(group.description, desc, SSO_MAX_DESCRIPTION);
		/* free(desc); */
	}
	if (parent != (sso_id_t)-1) {
		group.parent_group_id = parent;
	}
	if (status >= 0) {
		group.status = (group_status_t)status;
	}

	err = group_update(gmgr, &group);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"updated\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Updated group %llu (%s)", (unsigned long long)group.id, group.name);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "update_group",
						"groups", group.id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_delete_group(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	sso_id_t group_id = extract_path_id(req->path, "/groups/");
	if (!group_id) {
		sso_response_error(resp, 400, "group_id required");
		return SSO_OK;
	}

	group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;
	sso_error_t		 err  = group_delete(gmgr, group_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"deleted\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Deleted group %llu", (unsigned long long)group_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "delete_group",
						"groups", group_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_update_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t policy_id = extract_path_id(req->path, "/policies/");
	if (!policy_id || !req->body) {
		sso_response_error(resp, 400, "policy_id and body required");
		return SSO_OK;
	}

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;
	policy_t		  policy;
	sso_error_t		  err = policy_get_by_id(pmgr, policy_id, &policy);
	if (err != SSO_OK) {
		sso_response_error(resp, 404, "Policy not found");
		return SSO_OK;
	}

	char* name	   = req_json_str_value(req, "name");
	char* rules	   = req_json_str_value(req, "rules");
	int	  effect   = (int)json_int_value(req->body, "effect", -1);
	int	  priority = (int)json_int_value(req->body, "priority", -1);
	int	  status   = (int)json_int_value(req->body, "status", -1);

	if (name) {
		sso_strlcpy(policy.name, name, SSO_MAX_POLICY_NAME);
		/* free(name); */
	}
	if (rules) {
		sso_strlcpy(policy.rules, rules, SSO_MAX_RULES_JSON);
		/* free(rules); */
	}
	if (effect >= 0)
		policy.effect = (policy_effect_t)effect;
	if (priority >= 0)
		policy.priority = priority;
	if (status >= 0)
		policy.status = (policy_status_t)status;

	err = policy_update(pmgr, &policy);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"updated\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Updated policy %llu (%s)", (unsigned long long)policy.id, policy.name);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "update_policy",
						"policies", policy.id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_delete_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	(void)req;
	sso_id_t policy_id = extract_path_id(req->path, "/policies/");
	if (!policy_id) {
		sso_response_error(resp, 400, "policy_id required");
		return SSO_OK;
	}

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;
	sso_error_t		  err  = policy_delete(pmgr, policy_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"deleted\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Deleted policy %llu", (unsigned long long)policy_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "delete_policy",
						"policies", policy_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_unassign_policy(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t policy_id = extract_path_id(req->path, "/policies/");
	if (!policy_id || !req->body) {
		sso_response_error(resp, 400, "policy_id and body required");
		return SSO_OK;
	}

	sso_id_t target_id	 = (sso_id_t)json_int_value(req->body, "target_id", 0);
	int		 target_type = (int)json_int_value(req->body, "target_type", -1);
	if (!target_id || target_type < 0) {
		sso_response_error(resp, 400, "target_id and target_type required");
		return SSO_OK;
	}

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;
	sso_error_t		  err  = policy_unassign_from(pmgr, policy_id, (policy_target_type_t)target_type, target_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"unassigned\":true}");
	{
		auth_context_t* a		 = (auth_context_t*)req->userdata;
		const char*		tnames[] = {"user", "role", "group"};
		char			det[256];
		snprintf(det, sizeof(det), "Unassigned policy %llu from %s %llu", (unsigned long long)policy_id,
				 (size_t)target_type < 3 ? tnames[target_type] : "?", (unsigned long long)target_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "unassign_policy",
						"policies", policy_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_add_group_member(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t group_id = extract_path_id(req->path, "/groups/");
	if (!group_id || !req->body) {
		sso_response_error(resp, 400, "group_id and body required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		sso_response_error(resp, 400, "user_id required");
		return SSO_OK;
	}

	group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;
	sso_error_t		 err  = group_add_user(gmgr, group_id, user_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"added\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Added user %llu to group %llu", (unsigned long long)user_id,
				 (unsigned long long)group_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "add_group_member",
						"groups", group_id, "success", det);
	}
	return SSO_OK;
}
sso_error_t handle_remove_group_member(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	/* Path: /api/v1/groups/:id/members/:user_id */
	sso_id_t group_id = extract_path_id(req->path, "/groups/");

	/* Extract user_id from end of path */
	const char* last_slash = strrchr(req->path, '/');
	if (!last_slash || !group_id) {
		sso_response_error(resp, 400, "invalid path");
		return SSO_OK;
	}
	sso_id_t user_id = (sso_id_t)atoll(last_slash + 1);

	group_manager_t* gmgr = (group_manager_t*)ctx->group_mgr;
	sso_error_t		 err  = group_remove_user(gmgr, group_id, user_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"removed\":true}");
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Removed user %llu from group %llu", (unsigned long long)user_id,
				 (unsigned long long)group_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "remove_group_member",
						"groups", group_id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_get_user_policies(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t user_id = extract_path_id(req->path, "/api/v1/users/");
	if (user_id == 0) {
		sso_response_error(resp, 400, "Invalid user ID");
		return SSO_OK;
	}

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;
	policy_t		  policies[64];
	size_t			  count = 0;
	sso_error_t		  err	= policy_get_direct_policies(pmgr, POLICY_TARGET_USER, user_id, policies, &count, 64);
	if (err != SSO_OK && err != SSO_ERR_NOT_FOUND) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	char* arr  = (char*)arena_alloc((arena_t*)&req->arena, 3072);
	char* json = (char*)arena_alloc((arena_t*)&req->arena, 4096);
	if (!arr || !json) {
		/* free(arr); */
		/* free(json); */
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	arr[0] = '\0';
	strcat(arr, "[");
	for (size_t i = 0; i < count; i++) {
		char buf[256];
		snprintf(buf, sizeof(buf), "%s{\"id\":%llu,\"name\":\"%s\"}", i > 0 ? "," : "",
				 (unsigned long long)policies[i].id, policies[i].name);
		strcat(arr, buf);
	}
	strcat(arr, "]");

	snprintf(json, 4096, "{\"policies\":%s}", arr);
	sso_response_ok(resp, json);
	/* free(arr); */
	/* free(json); */
	return SSO_OK;
}

sso_error_t handle_get_policy_targets(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	sso_id_t policy_id = extract_path_id(req->path, "/policies/");
	if (!policy_id) {
		sso_response_error(resp, 400, "policy_id required");
		return SSO_OK;
	}

	policy_manager_t* pmgr = (policy_manager_t*)ctx->policy_mgr;

	/* Build response with all three target types */
	char users_json[1024]  = "";
	char roles_json[1024]  = "";
	char groups_json[1024] = "";

	/* Users */
	{
		sso_id_t ids[64];
		size_t	 cnt = 0;
		if (policy_get_targets(pmgr, policy_id, POLICY_TARGET_USER, ids, &cnt, 64) == SSO_OK || cnt > 0) {
			strcat(users_json, "[");
			for (size_t i = 0; i < cnt; i++) {
				char buf[64];
				snprintf(buf, sizeof(buf), "%s%llu", i > 0 ? "," : "", (unsigned long long)ids[i]);
				strcat(users_json, buf);
			}
			strcat(users_json, "]");
		} else {
			strcat(users_json, "[]");
		}
	}

	/* Roles */
	{
		sso_id_t ids[64];
		size_t	 cnt = 0;
		if (policy_get_targets(pmgr, policy_id, POLICY_TARGET_ROLE, ids, &cnt, 64) == SSO_OK || cnt > 0) {
			strcat(roles_json, "[");
			for (size_t i = 0; i < cnt; i++) {
				char buf[64];
				snprintf(buf, sizeof(buf), "%s%llu", i > 0 ? "," : "", (unsigned long long)ids[i]);
				strcat(roles_json, buf);
			}
			strcat(roles_json, "]");
		} else {
			strcat(roles_json, "[]");
		}
	}

	/* Groups */
	{
		sso_id_t ids[64];
		size_t	 cnt = 0;
		if (policy_get_targets(pmgr, policy_id, POLICY_TARGET_GROUP, ids, &cnt, 64) == SSO_OK || cnt > 0) {
			strcat(groups_json, "[");
			for (size_t i = 0; i < cnt; i++) {
				char buf[64];
				snprintf(buf, sizeof(buf), "%s%llu", i > 0 ? "," : "", (unsigned long long)ids[i]);
				strcat(groups_json, buf);
			}
			strcat(groups_json, "]");
		} else {
			strcat(groups_json, "[]");
		}
	}

	char* json = (char*)arena_alloc((arena_t*)&req->arena, 4096);
	if (!json) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	snprintf(json, 4096, "{\"user_ids\":%s,\"role_ids\":%s,\"group_ids\":%s}", users_json, roles_json, groups_json);
	sso_response_ok(resp, json);
	/* free(json); */
	return SSO_OK;
}

sso_error_t handle_list_clients(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	char q[SSO_MAX_QUERY] = "";
	int	 status = -1, page = 1, limit = 10;
	parse_query_params(req, q, &status, &page, &limit);
	int offset = (page - 1) * limit;

	oauth_client_t* clients = (oauth_client_t*)arena_alloc((arena_t*)&req->arena, (64) * (sizeof(oauth_client_t)));
	if (!clients) {
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	size_t count = 0;

	storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
	if (!sb || !sb->oauth_client_list) {
		sso_response_error(resp, 500, "OAuth client storage unavailable");
		/* free(clients); */
		return SSO_OK;
	}

	sso_error_t err = sb->oauth_client_list(sb, offset, limit, clients, &count, 64);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to list OAuth clients");
		/* free(clients); */
		return SSO_OK;
	}

	// Build JSON output dynamically
	size_t total_json_len = 2048 + count * 1536;
	char*  json			  = (char*)arena_alloc((arena_t*)&req->arena, (1) * (total_json_len));
	if (!json) {
		sso_response_error(resp, 500, "Out of memory");
		/* free(clients); */
		return SSO_OK;
	}

	strcat(json, "{\"total\":");
	char count_buf[32];
	snprintf(count_buf, sizeof(count_buf), "%d", (int)(offset + count + (count == (size_t)limit ? 1 : 0)));
	strcat(json, count_buf);
	strcat(json, ",\"page\":");
	snprintf(count_buf, sizeof(count_buf), "%d", page);
	strcat(json, count_buf);
	strcat(json, ",\"limit\":");
	snprintf(count_buf, sizeof(count_buf), "%d", limit);
	strcat(json, count_buf);
	strcat(json, ",\"items\":[");

	for (size_t i = 0; i < count; i++) {
		char item[1024];
		snprintf(item, sizeof(item),
				 "%s{"
				 "\"id\":%llu,"
				 "\"client_id\":\"%s\","
				 "\"redirect_uris\":\"%s\","
				 "\"app_name\":\"%s\","
				 "\"app_description\":\"%s\","
				 "\"app_logo_url\":\"%s\","
				 "\"allowed_scopes\":\"%s\","
				 "\"allowed_grant_types\":\"%s\","
				 "\"token_ttl_ms\":%ld,"
				 "\"status\":%d,"
				 "\"created_at\":%llu,"
				 "\"updated_at\":%llu"
				 "}",
				 i > 0 ? "," : "", (unsigned long long)clients[i].id, clients[i].client_id, clients[i].redirect_uris,
				 clients[i].app_name, clients[i].app_description, clients[i].app_logo_url, clients[i].allowed_scopes,
				 clients[i].allowed_grant_types, clients[i].token_ttl_ms, clients[i].status,
				 (unsigned long long)clients[i].created_at, (unsigned long long)clients[i].updated_at);
		strcat(json, item);
	}
	strcat(json, "]}");

	sso_response_ok(resp, json);
	/* free(json); */
	/* free(clients); */
	return SSO_OK;
}

sso_error_t handle_create_client(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* client_id			  = req_json_str_value(req, "client_id");
	char* client_secret		  = req_json_str_value(req, "client_secret");
	char* redirect_uris		  = req_json_str_value(req, "redirect_uris");
	char* app_name			  = req_json_str_value(req, "app_name");
	char* app_description	  = req_json_str_value(req, "app_description");
	char* app_logo_url		  = req_json_str_value(req, "app_logo_url");
	char* allowed_scopes	  = req_json_str_value(req, "allowed_scopes");
	char* allowed_grant_types = req_json_str_value(req, "allowed_grant_types");
	long  token_ttl_ms		  = (long)json_int_value(req->body, "token_ttl_ms", 3600000);
	int	  status			  = (int)json_int_value(req->body, "status", 1);

	if (!client_id || !client_secret || !redirect_uris) {
		/* free(client_id); */
		/* free(client_secret); */
		/* free(redirect_uris); */
		/* free(app_name); */
		/* free(app_description); */
		/* free(app_logo_url); */
		/* free(allowed_scopes); */
		/* free(allowed_grant_types); */
		sso_response_error(resp, 400, "client_id, client_secret, and redirect_uris required");
		return SSO_OK;
	}

	storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
	if (!sb || !sb->oauth_client_create) {
		/* free(client_id); */
		/* free(client_secret); */
		/* free(redirect_uris); */
		/* free(app_name); */
		/* free(app_description); */
		/* free(app_logo_url); */
		/* free(allowed_scopes); */
		/* free(allowed_grant_types); */
		sso_response_error(resp, 500, "OAuth client storage unavailable");
		return SSO_OK;
	}

	oauth_client_t client;
	memset(&client, 0, sizeof(client));

	sso_strlcpy(client.client_id, client_id, sizeof(client.client_id));
	sso_strlcpy(client.redirect_uris, redirect_uris, sizeof(client.redirect_uris));
	if (app_name)
		sso_strlcpy(client.app_name, app_name, sizeof(client.app_name));
	if (app_description)
		sso_strlcpy(client.app_description, app_description, sizeof(client.app_description));
	if (app_logo_url)
		sso_strlcpy(client.app_logo_url, app_logo_url, sizeof(client.app_logo_url));
	if (allowed_scopes)
		sso_strlcpy(client.allowed_scopes, allowed_scopes, sizeof(client.allowed_scopes));
	if (allowed_grant_types)
		sso_strlcpy(client.allowed_grant_types, allowed_grant_types, sizeof(client.allowed_grant_types));
	client.token_ttl_ms = token_ttl_ms;
	client.status		= status;
	client.created_at	= get_time_ms();
	client.updated_at	= client.created_at;

	// Hash the client secret using libsodium crypto_pwhash_str
	if (crypto_pwhash_str(client.client_secret_hash, client_secret, strlen(client_secret),
						  crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
		/* free(client_id); */
		/* free(client_secret); */
		/* free(redirect_uris); */
		/* free(app_name); */
		/* free(app_description); */
		/* free(app_logo_url); */
		/* free(allowed_scopes); */
		/* free(allowed_grant_types); */
		sso_response_error(resp, 500, "Failed to hash client secret");
		return SSO_OK;
	}

	sso_error_t err = sb->oauth_client_create(sb, &client);
	/* free(client_id); */
	/* free(client_secret); */
	/* free(redirect_uris); */
	/* free(app_name); */
	/* free(app_description); */
	/* free(app_logo_url); */
	/* free(allowed_scopes); */
	/* free(allowed_grant_types); */

	if (err == SSO_ERR_ALREADY_EXISTS) {
		sso_response_error(resp, 409, "Client ID already exists");
		return SSO_OK;
	}
	if (err != SSO_OK) {
		sso_response_error(resp, 500, "Failed to create client");
		return SSO_OK;
	}

	char buf[256];
	snprintf(buf, sizeof(buf), "{\"client_id\":\"%s\",\"created\":true}", client.client_id);
	sso_response_ok(resp, buf);

	// Audit Log
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "create_client",
						"clients", 0, "success", buf);
	}
	return SSO_OK;
}

sso_error_t handle_update_client(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	/* Path format: /api/v1/clients/:client_id */
	const char* p = strstr(req->path, "/clients/");
	if (!p) {
		sso_response_error(resp, 400, "client_id required in path");
		return SSO_OK;
	}
	p += 9; // past "/clients/"

	char path_client_id[64];
	sso_strlcpy(path_client_id, p, sizeof(path_client_id));
	path_client_id[sizeof(path_client_id) - 1] = '\0';
	// Remove any trailing slash if present
	char* slash = strchr(path_client_id, '/');
	if (slash)
		*slash = '\0';

	if (strlen(path_client_id) == 0 || !req->body) {
		sso_response_error(resp, 400, "client_id and body required");
		return SSO_OK;
	}

	storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
	if (!sb || !sb->oauth_client_get || !sb->oauth_client_update) {
		sso_response_error(resp, 500, "OAuth client storage unavailable");
		return SSO_OK;
	}

	oauth_client_t client;
	memset(&client, 0, sizeof(client));
	sso_error_t err = sb->oauth_client_get(sb, path_client_id, &client);
	if (err != SSO_OK) {
		sso_response_error(resp, 404, "Client not found");
		return SSO_OK;
	}

	char* redirect_uris		  = req_json_str_value(req, "redirect_uris");
	char* app_name			  = req_json_str_value(req, "app_name");
	char* app_description	  = req_json_str_value(req, "app_description");
	char* app_logo_url		  = req_json_str_value(req, "app_logo_url");
	char* allowed_scopes	  = req_json_str_value(req, "allowed_scopes");
	char* allowed_grant_types = req_json_str_value(req, "allowed_grant_types");
	char* client_secret		  = req_json_str_value(req, "client_secret");
	int	  status			  = (int)json_int_value(req->body, "status", -1);
	long  token_ttl_ms		  = (long)json_int_value(req->body, "token_ttl_ms", -1);

	if (redirect_uris) {
		sso_strlcpy(client.redirect_uris, redirect_uris, sizeof(client.redirect_uris));
		/* free(redirect_uris); */
	}
	if (app_name) {
		sso_strlcpy(client.app_name, app_name, sizeof(client.app_name));
		/* free(app_name); */
	}
	if (app_description) {
		sso_strlcpy(client.app_description, app_description, sizeof(client.app_description));
		/* free(app_description); */
	}
	if (app_logo_url) {
		sso_strlcpy(client.app_logo_url, app_logo_url, sizeof(client.app_logo_url));
		/* free(app_logo_url); */
	}
	if (allowed_scopes) {
		sso_strlcpy(client.allowed_scopes, allowed_scopes, sizeof(client.allowed_scopes));
		/* free(allowed_scopes); */
	}
	if (allowed_grant_types) {
		sso_strlcpy(client.allowed_grant_types, allowed_grant_types, sizeof(client.allowed_grant_types));
		/* free(allowed_grant_types); */
	}
	if (status >= 0) {
		client.status = status;
	}
	if (token_ttl_ms >= 0) {
		client.token_ttl_ms = token_ttl_ms;
	}
	if (client_secret && strlen(client_secret) > 0) {
		if (crypto_pwhash_str(client.client_secret_hash, client_secret, strlen(client_secret),
							  crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
			/* free(client_secret); */
			sso_response_error(resp, 500, "Failed to hash client secret");
			return SSO_OK;
		}
	}
	/* free(client_secret); */

	client.updated_at = get_time_ms();

	err = sb->oauth_client_update(sb, &client);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"updated\":true}");

	// Audit Log
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Updated client %s", path_client_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "update_client",
						"clients", client.id, "success", det);
	}
	return SSO_OK;
}

sso_error_t handle_delete_client(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	/* Path format: /api/v1/clients/:client_id */
	const char* p = strstr(req->path, "/clients/");
	if (!p) {
		sso_response_error(resp, 400, "client_id required in path");
		return SSO_OK;
	}
	p += 9; // past "/clients/"

	char path_client_id[64];
	sso_strlcpy(path_client_id, p, sizeof(path_client_id));
	path_client_id[sizeof(path_client_id) - 1] = '\0';
	// Remove any trailing slash if present
	char* slash = strchr(path_client_id, '/');
	if (slash)
		*slash = '\0';

	if (strlen(path_client_id) == 0) {
		sso_response_error(resp, 400, "client_id required");
		return SSO_OK;
	}

	storage_backend_t* sb = (storage_backend_t*)ctx->storage_backend;
	if (!sb || !sb->oauth_client_delete) {
		sso_response_error(resp, 500, "OAuth client storage unavailable");
		return SSO_OK;
	}

	sso_error_t err = sb->oauth_client_delete(sb, path_client_id);
	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, "{\"deleted\":true}");

	// Audit Log
	{
		auth_context_t* a = (auth_context_t*)req->userdata;
		char			det[256];
		snprintf(det, sizeof(det), "Deleted client %s", path_client_id);
		admin_audit_log((sso_config_t*)ctx->config, a->user.id, a->user.username, req->client_ip, "delete_client",
						"clients", 0, "success", det);
	}
	return SSO_OK;
}
