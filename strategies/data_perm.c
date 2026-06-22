/*
 * data_perm.c — Data scope (row/field-level) permission strategy.
 *
 * Controls access to individual data records based on row-level
 * conditions and field-level visibility filters.  Row conditions are
 * field-operator-value triplets (eq, neq, gt, lt) evaluated against
 * the target record.  Field filters whitelist which fields the caller
 * is allowed to see; any field not in the list is stripped from the
 * response.
 *
 * At compile time the JSON rules are parsed into a data_compiled_rule_t
 * struct containing condition arrays and allowed-fields lists.
 *
 * JSON rule format:
 *   { "resource_type": "employee",
 *     "conditions":    [{"field": "dept", "op": "eq", "value": "eng"}],
 *     "allowed_fields": ["name", "email"],
 *     "effect": "allow" }
 *
 * Example: engineers can view only the name and email of employee
 * records that belong to the engineering department.
 */

#include "sso.h"
#include "policy.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Pre-compiled Data rule structures
 * ----------------------------------------------------------------------- */
typedef struct {
	char field[64];
	char op[16];
	char expected[256];
} data_condition_t;

typedef struct {
	char			  resource_type[64];
	data_condition_t* conditions;
	size_t			  cond_count;
	char**			  allowed_fields;
	size_t			  field_count;
	bool			  is_allow;
} data_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t data_init(permission_strategy_t* self, sso_context_t* ctx) {
	(void)self;
	(void)ctx;
	return SSO_OK;
}

static void data_destroy(permission_strategy_t* self) {
	(void)self;
}

static sso_error_t data_compile(permission_strategy_t* self, const char* rules_json, void** compiled_rule) {
	(void)self;
	if (!rules_json || !compiled_rule)
		return SSO_ERR_INVALID_PARAM;

	yyjson_doc* doc = yyjson_read(rules_json, strlen(rules_json), 0);
	if (!doc)
		return SSO_ERR_RULE_INVALID;

	yyjson_val* root = yyjson_doc_get_root(doc);

	data_compiled_rule_t* compiled = (data_compiled_rule_t*)calloc(1, sizeof(data_compiled_rule_t));
	if (!compiled) {
		yyjson_doc_free(doc);
		return SSO_ERR_OUT_OF_MEMORY;
	}

	yyjson_val* res_type = yyjson_obj_get(root, "resource_type");
	if (yyjson_is_str(res_type))
		sso_strlcpy(compiled->resource_type, yyjson_get_str(res_type), 63);

	/* Parse record-level conditions */
	yyjson_val* conds = yyjson_obj_get(root, "conditions");
	if (yyjson_is_arr(conds)) {
		compiled->cond_count = yyjson_arr_size(conds);
		compiled->conditions = (data_condition_t*)calloc(compiled->cond_count, sizeof(data_condition_t));
		size_t		idx, max;
		yyjson_val* item;
		yyjson_arr_foreach(conds, idx, max, item) {
			yyjson_val* f = yyjson_obj_get(item, "field");
			yyjson_val* o = yyjson_obj_get(item, "op");
			yyjson_val* v = yyjson_obj_get(item, "value");
			if (yyjson_is_str(f))
				sso_strlcpy(compiled->conditions[idx].field, yyjson_get_str(f), 63);
			if (yyjson_is_str(o))
				sso_strlcpy(compiled->conditions[idx].op, yyjson_get_str(o), 15);
			if (v) {
				if (yyjson_is_str(v))
					sso_strlcpy(compiled->conditions[idx].expected, yyjson_get_str(v), 255);
				else if (yyjson_is_num(v))
					snprintf(compiled->conditions[idx].expected, 255, "%g", yyjson_get_num(v));
			}
		}
	}

	/* Parse field-level visibility */
	yyjson_val* fields = yyjson_obj_get(root, "allowed_fields");
	if (yyjson_is_arr(fields)) {
		compiled->field_count	 = yyjson_arr_size(fields);
		compiled->allowed_fields = (char**)calloc(compiled->field_count, sizeof(char*));
		size_t		idx, max;
		yyjson_val* f;
		yyjson_arr_foreach(fields, idx, max, f) {
			if (yyjson_is_str(f))
				compiled->allowed_fields[idx] = strdup(yyjson_get_str(f));
		}
	}

	yyjson_val* effect = yyjson_obj_get(root, "effect");
	compiled->is_allow = !(yyjson_is_str(effect) && strcmp(yyjson_get_str(effect), "deny") == 0);

	yyjson_doc_free(doc);
	*compiled_rule = compiled;
	return SSO_OK;
}

static void data_free_compiled(permission_strategy_t* self, void* compiled_rule) {
	(void)self;
	if (!compiled_rule)
		return;
	data_compiled_rule_t* compiled = (data_compiled_rule_t*)compiled_rule;
	free(compiled->conditions);
	for (size_t i = 0; i < compiled->field_count; i++)
		free(compiled->allowed_fields[i]);
	free(compiled->allowed_fields);
	free(compiled);
}

static bool apply_data_op(const char* op, const char* actual, const char* expected) {
	if (strcmp(op, "eq") == 0)
		return strcmp(actual, expected) == 0;
	if (strcmp(op, "neq") == 0)
		return strcmp(actual, expected) != 0;
	/* Basic numeric ops */
	double av = strtod(actual, NULL);
	double ev = strtod(expected, NULL);
	if (strcmp(op, "gt") == 0)
		return av > ev;
	if (strcmp(op, "lt") == 0)
		return av < ev;
	return false;
}

static sso_error_t data_evaluate(permission_strategy_t* self, eval_context_t* ctx, const policy_t* policy,
								 void* compiled_rule, bool* result) {
	(void)self;
	(void)policy;
	if (!ctx || !result || !compiled_rule)
		return SSO_ERR_INVALID_PARAM;

	data_compiled_rule_t* compiled = (data_compiled_rule_t*)compiled_rule;

	/* 1. Resource Type Check */
	if (strcmp(ctx->params.data.resource_type, compiled->resource_type) != 0) {
		return SSO_ERR_NOT_FOUND;
	}

	/* 2. Condition Check (Record-level) */
	if (ctx->params.data.record) {
		yyjson_doc* record = yyjson_read(ctx->params.data.record, strlen(ctx->params.data.record), 0);
		if (!record)
			return SSO_ERR_RULE_INVALID;
		yyjson_val* record_root = yyjson_doc_get_root(record);

		for (size_t i = 0; i < compiled->cond_count; i++) {
			yyjson_val* val = yyjson_obj_get(record_root, compiled->conditions[i].field);
			if (!val) {
				yyjson_doc_free(record);
				return SSO_ERR_NOT_FOUND;
			}

			char actual[256];
			if (yyjson_is_str(val))
				sso_strlcpy(actual, yyjson_get_str(val), 255);
			else if (yyjson_is_num(val))
				snprintf(actual, 255, "%g", yyjson_get_num(val));
			else {
				yyjson_doc_free(record);
				return SSO_ERR_NOT_FOUND;
			}

			if (!apply_data_op(compiled->conditions[i].op, actual, compiled->conditions[i].expected)) {
				yyjson_doc_free(record);
				return SSO_ERR_NOT_FOUND;
			}
		}
		yyjson_doc_free(record);
	}

	/* 3. Field Filter Population */
	if (compiled->field_count > 0) {
		/* Free existing field_filter to prevent memory leaks from previous policy evaluations */
		if (ctx->params.data.field_filter) {
			for (size_t i = 0; i < ctx->params.data.field_filter_count; i++) {
				free(ctx->params.data.field_filter[i]);
			}
			free(ctx->params.data.field_filter);
			ctx->params.data.field_filter		= NULL;
			ctx->params.data.field_filter_count = 0;
		}

		ctx->params.data.field_filter = (char**)calloc(compiled->field_count, sizeof(char*));
		if (ctx->params.data.field_filter) {
			for (size_t i = 0; i < compiled->field_count; i++) {
				ctx->params.data.field_filter[i] = strdup(compiled->allowed_fields[i]);
			}
			ctx->params.data.field_filter_count = compiled->field_count;
		}
	}

	*result = compiled->is_allow;
	return SSO_OK;
}

static sso_error_t data_validate(permission_strategy_t* self, const char* rules_json) {
	(void)self;
	if (!rules_json)
		return SSO_ERR_INVALID_PARAM;
	yyjson_doc* doc = yyjson_read(rules_json, strlen(rules_json), 0);
	if (!doc)
		return SSO_ERR_RULE_INVALID;
	yyjson_doc_free(doc);
	return SSO_OK;
}

permission_strategy_t data_perm_strategy = {
		.type				 = PERM_STRATEGY_DATA,
		.name				 = "data",
		.init				 = data_init,
		.destroy			 = data_destroy,
		.compile_rules		 = data_compile,
		.free_compiled_rules = data_free_compiled,
		.evaluate			 = data_evaluate,
		.validate_rules		 = data_validate,
		.userdata			 = NULL,
};
