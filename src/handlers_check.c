// handlers_check.c — Permission check HTTP request handlers.
//
// Implements the /api/v1/check/* endpoints for all seven permission
// strategies: functional, API, data, RBAC, location, LBAC, and ABAC.
// Each handler parses the request body, builds an eval_context_t,
// and returns the engine's allow/deny decision as a JSON response.

#include "sso.h"
#include "server.h"
#include "handlers.h"
#include "logger.h"
#include "permission.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* POST /api/v1/check */
sso_error_t handle_check_permission(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	eval_context_t	ectx;
	user_t			user;
	user_manager_t* umgr = (user_manager_t*)ctx->user_mgr;
	if (user_get_by_id(umgr, user_id, &user) != SSO_OK) {
		sso_response_error(resp, 404, "User not found");
		return SSO_OK;
	}

	eval_context_init(&ectx, &user);

	/* Populate the context with all available parameters from the JSON body */
	char* function_code = req_json_str_value(req, "function_code");
	if (function_code) {
		sso_strlcpy(ectx.params.functional.function_code, function_code, sizeof(ectx.params.functional.function_code));
		/* free(function_code); */
	}

	char* api_method = req_json_str_value(req, "api_method");
	char* api_path	 = req_json_str_value(req, "api_path");
	if (api_method && api_path) {
		sso_strlcpy(ectx.params.api.http_method, api_method, sizeof(ectx.params.api.http_method));
		sso_strlcpy(ectx.params.api.request_path, api_path, sizeof(ectx.params.api.request_path));
		/* free(api_method); */
		/* free(api_path); */
	}

	char* resource_type = req_json_str_value(req, "resource_type");
	if (resource_type) {
		sso_strlcpy(ectx.params.data.resource_type, resource_type, sizeof(ectx.params.data.resource_type));
		/* free(resource_type); */

		char* record = req_json_str_value(req, "record");
		if (record) {
			ectx.params.data.record = record; /* Must be freed later */
		}
	}

	char* role_name = req_json_str_value(req, "role_name");
	if (role_name) {
		sso_strlcpy(ectx.params.rbac.role_name, role_name, sizeof(ectx.params.rbac.role_name));
		/* free(role_name); */
	}

	char* source_ip = req_json_str_value(req, "source_ip");
	if (source_ip) {
		sso_strlcpy(ectx.params.location.source_ip, source_ip, sizeof(ectx.params.location.source_ip));
		/* free(source_ip); */
	}

	char* lbac_user_labels	  = req_json_str_value(req, "lbac_user_labels");
	char* lbac_resource_label = req_json_str_value(req, "lbac_resource_label");
	if (lbac_user_labels && lbac_resource_label) {
		sso_strlcpy(ectx.params.lbac.user_labels, lbac_user_labels, sizeof(ectx.params.lbac.user_labels));
		sso_strlcpy(ectx.params.lbac.resource_label, lbac_resource_label, sizeof(ectx.params.lbac.resource_label));
		/* free(lbac_user_labels); */
		/* free(lbac_resource_label); */
	}

	char* abac_subject_attrs  = req_json_str_value(req, "abac_subject_attrs");
	char* abac_resource_attrs = req_json_str_value(req, "abac_resource_attrs");
	char* abac_action		  = req_json_str_value(req, "abac_action");
	if (abac_subject_attrs) {
		sso_strlcpy(ectx.params.abac.subject_attrs, abac_subject_attrs, sizeof(ectx.params.abac.subject_attrs));
		/* free(abac_subject_attrs); */
	}
	if (abac_resource_attrs) {
		sso_strlcpy(ectx.params.abac.resource_attrs, abac_resource_attrs, sizeof(ectx.params.abac.resource_attrs));
		/* free(abac_resource_attrs); */
	}
	if (abac_action) {
		sso_strlcpy(ectx.params.abac.action, abac_action, sizeof(ectx.params.abac.action));
		/* free(abac_action); */
	}

	char* env_attrs = req_json_str_value(req, "environment");
	if (env_attrs) {
		sso_strlcpy(ectx.environment, env_attrs, sizeof(ectx.environment));
		/* free(env_attrs); */
	}

	bool		allowed = false;
	char*		trace	= NULL;
	sso_error_t err		= perm_engine_evaluate((permission_engine_t*)ctx->perm_engine, &ectx, &allowed, &trace);

	if (err != SSO_OK) {
		if (ectx.params.data.record)
			/* free((void*)ectx.params.data.record); */
			if (trace)
				/* free(trace); */
				eval_context_destroy(&ectx);
		sso_response_error(resp, 500, "Permission evaluation failed");
		return SSO_OK;
	}

	/* Build JSON response */
	char* buf			= (char*)arena_alloc((arena_t*)&req->arena, 8192);
	char* escaped_trace = (char*)arena_alloc((arena_t*)&req->arena, 4096);
	char* fields_buf	= (char*)arena_alloc((arena_t*)&req->arena, 1024);
	if (!buf || !escaped_trace || !fields_buf) {
		/* free(buf); */
		/* free(escaped_trace); */
		/* free(fields_buf); */
		if (ectx.params.data.record)
			/* free((void*)ectx.params.data.record); */
			if (trace)
				/* free(trace); */
				eval_context_destroy(&ectx);
		sso_response_error(resp, 500, "Out of memory");
		return SSO_OK;
	}
	escaped_trace[0] = '\0';

	/* Safely format trace for JSON if present */
	if (trace) {
		size_t j = 0;
		for (size_t i = 0; trace[i] && j < 4096 - 3; i++) {
			if (trace[i] == '"') {
				escaped_trace[j++] = '\\';
				escaped_trace[j++] = '"';
			} else if (trace[i] == '\n') {
				escaped_trace[j++] = '\\';
				escaped_trace[j++] = 'n';
			} else if (trace[i] == '\t') {
				escaped_trace[j++] = '\\';
				escaped_trace[j++] = 't';
			} else
				escaped_trace[j++] = trace[i];
		}
	}

	/* Serialize allowed fields if present */
	strcpy(fields_buf, "[]");
	if (ectx.params.data.field_filter_count > 0) {
		strcpy(fields_buf, "[");
		for (size_t i = 0; i < ectx.params.data.field_filter_count; i++) {
			char fbuf[128];
			snprintf(fbuf, sizeof(fbuf), "\"%s\"%s", ectx.params.data.field_filter[i],
					 i < ectx.params.data.field_filter_count - 1 ? "," : "");
			strncat(fields_buf, fbuf, 1024 - strlen(fields_buf) - 1);
		}
		strcat(fields_buf, "]");
	}

	snprintf(buf, 8192,
			 "{"
			 "\"allowed\":%s,"
			 "\"allowed_fields\":%s,"
			 "\"trace\":\"%s\""
			 "}",
			 allowed ? "true" : "false", fields_buf, trace ? escaped_trace : "");

	sso_response_ok(resp, buf);

	if (ectx.params.data.record)
		free((void*)ectx.params.data.record);
	if (trace)
		/* free(trace); */
		eval_context_destroy(&ectx);
	/* free(buf); */
	/* free(escaped_trace); */
	/* free(fields_buf); */

	return SSO_OK;
}

/* POST /api/v1/check/functional */
sso_error_t handle_check_functional(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* function_code = req_json_str_value(req, "function_code");
	if (!function_code) {
		sso_response_error(resp, 400, "function_code required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		/* free(function_code); */
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	bool		allowed = false;
	sso_error_t err		= perm_check_function(ctx, user_id, function_code, &allowed);

	char result_code[64];
	sso_strlcpy(result_code, function_code, sizeof(result_code));
	/* free(function_code); */

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"allowed\":%s,\"user_id\":%llu,\"function\":\"%s\"}", allowed ? "true" : "false",
			 (unsigned long long)user_id, result_code);
	sso_response_ok(resp, buf);
	return SSO_OK;
}

/* POST /api/v1/check/api */
sso_error_t handle_check_api(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* method = req_json_str_value(req, "method");
	char* path	 = req_json_str_value(req, "path");
	if (!method || !path) {
		/* free(method); */
		/* free(path); */
		sso_response_error(resp, 400, "method and path required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		/* free(method); */
		/* free(path); */
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	bool		allowed = false;
	sso_error_t err		= perm_check_api(ctx, user_id, method, path, &allowed);
	/* free(method); */
	/* free(path); */

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"allowed\":%s,\"user_id\":%llu}", allowed ? "true" : "false",
			 (unsigned long long)user_id);
	sso_response_ok(resp, buf);
	return SSO_OK;
}

/* POST /api/v1/check/data */
sso_error_t handle_check_data(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* resource_type = req_json_str_value(req, "resource_type");
	char* record_json	= req_json_str_value(req, "record");
	if (!resource_type) {
		/* free(resource_type); */
		/* free(record_json); */
		sso_response_error(resp, 400, "resource_type required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		/* free(resource_type); */
		/* free(record_json); */
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	bool		allowed		= false;
	char**		fields		= NULL;
	size_t		field_count = 0;
	sso_error_t err = perm_check_data(ctx, user_id, resource_type, record_json, &allowed, &fields, &field_count);
	/* free(resource_type); */
	/* free(record_json); */
	/* Note: fields is owned by the SSO system — do not free here */

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	char   buf[2048];
	size_t off = (size_t)snprintf(buf, sizeof(buf), "{\"allowed\":%s,\"user_id\":%llu", allowed ? "true" : "false",
								  (unsigned long long)user_id);

	if (fields && field_count > 0) {
		off += (size_t)snprintf(buf + off, sizeof(buf) - off, ",\"fields\":[");
		for (size_t i = 0; i < field_count; i++) {
			off += (size_t)snprintf(buf + off, sizeof(buf) - off, "%s\"%s\"", i > 0 ? "," : "", fields[i]);
			/* free(fields[i]); */
		}
		off += (size_t)snprintf(buf + off, sizeof(buf) - off, "]");
		/* free(fields); */
	}
	snprintf(buf + off, sizeof(buf) - off, "}");
	sso_response_ok(resp, buf);
	return SSO_OK;
}

/* POST /api/v1/check/rbac */
sso_error_t handle_check_rbac(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* role_name = req_json_str_value(req, "role_name");
	if (!role_name) {
		sso_response_error(resp, 400, "role_name required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		/* free(role_name); */
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	bool		allowed = false;
	sso_error_t err		= perm_check_rbac(ctx, user_id, role_name, &allowed);

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"allowed\":%s,\"user_id\":%llu,\"role\":\"%s\"}", allowed ? "true" : "false",
			 (unsigned long long)user_id, role_name);
	/* free(role_name); */

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, buf);
	return SSO_OK;
}

/* POST /api/v1/check/location */
sso_error_t handle_check_location(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* source_ip	  = req_json_str_value(req, "source_ip");
	char* geo_country = req_json_str_value(req, "geo_country");
	if (!source_ip) {
		/* free(source_ip); */
		/* free(geo_country); */
		sso_response_error(resp, 400, "source_ip required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		/* free(source_ip); */
		/* free(geo_country); */
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	bool		allowed = false;
	sso_error_t err		= perm_check_location(ctx, user_id, source_ip, geo_country, &allowed);

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"allowed\":%s,\"user_id\":%llu,\"source_ip\":\"%s\"}", allowed ? "true" : "false",
			 (unsigned long long)user_id, source_ip);
	/* free(source_ip); */
	/* free(geo_country); */

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, buf);
	return SSO_OK;
}

/* POST /api/v1/check/lbac */
sso_error_t handle_check_lbac(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* user_labels	 = req_json_str_value(req, "user_labels");
	char* resource_label = req_json_str_value(req, "resource_label");
	if (!user_labels || !resource_label) {
		/* free(user_labels); */
		/* free(resource_label); */
		sso_response_error(resp, 400, "user_labels and resource_label required");
		return SSO_OK;
	}

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		/* free(user_labels); */
		/* free(resource_label); */
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	bool		allowed = false;
	sso_error_t err		= perm_check_lbac(ctx, user_id, user_labels, resource_label, &allowed);

	char buf[512];
	snprintf(buf, sizeof(buf), "{\"allowed\":%s,\"user_id\":%llu,\"user_labels\":\"%s\",\"resource_label\":\"%s\"}",
			 allowed ? "true" : "false", (unsigned long long)user_id, user_labels, resource_label);
	/* free(user_labels); */
	/* free(resource_label); */

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, buf);
	return SSO_OK;
}

/* POST /api/v1/check/abac */
sso_error_t handle_check_abac(sso_context_t* ctx, const http_request_t* req, http_response_t* resp) {
	if (!req->body) {
		sso_response_error(resp, 400, "Request body required");
		return SSO_OK;
	}

	char* subject_attrs	 = req_json_str_value(req, "subject_attrs");
	char* resource_attrs = req_json_str_value(req, "resource_attrs");
	char* action_str	 = req_json_str_value(req, "action");

	sso_id_t user_id = (sso_id_t)json_int_value(req->body, "user_id", 0);
	if (user_id == 0) {
		auth_context_t* auth = (auth_context_t*)req->userdata;
		if (auth)
			user_id = auth->user.id;
	}
	if (user_id == 0) {
		/* free(subject_attrs); */
		/* free(resource_attrs); */
		/* free(action_str); */
		sso_response_error(resp, 400, "user_id or authentication required");
		return SSO_OK;
	}

	bool		allowed = false;
	sso_error_t err		= perm_check_abac(ctx, user_id, subject_attrs, resource_attrs, action_str, &allowed);

	char buf[1024];
	snprintf(buf, sizeof(buf), "{\"allowed\":%s,\"user_id\":%llu}", allowed ? "true" : "false",
			 (unsigned long long)user_id);
	/* free(subject_attrs); */
	/* free(resource_attrs); */
	/* free(action_str); */

	if (err != SSO_OK) {
		sso_response_error(resp, 500, sso_strerror(err));
		return SSO_OK;
	}

	sso_response_ok(resp, buf);
	return SSO_OK;
}
