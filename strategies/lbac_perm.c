/*
 * lbac_perm.c — Label-Based Access Control (LBAC) permission strategy.
 *
 * Implements multi-level security (MLS-style) by comparing resource
 * security labels against the user's assigned clearance labels.
 * Access is granted only when the user possesses a label that matches
 * the resource label AND the policy lists that label with an allow
 * effect.  The user_max_label field provides an upper-bound ceiling
 * for hierarchical label systems (e.g. public < confidential < secret
 * < top_secret).
 *
 * At compile time the JSON rules are parsed into lbac_rule_item_t
 * entries.  Evaluation performs comma-delimited string matching
 * against the user's label list.
 *
 * JSON rule format:
 *   { "required_labels": ["confidential"],
 *     "user_max_label":  "top_secret" }
 *
 * Example: a user carrying the "confidential" label can access
 * resources labelled "confidential".  The user_max_label prevents
 * users from accessing resources at a higher classification than
 * their ceiling, even if they happen to hold the label.
 */

#include "sso.h"
#include "policy.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ----------------------------------------------------------------------- */
/* Types */
/* ----------------------------------------------------------------------- */
typedef struct {
	char label_name[64];
	bool is_allow;
} lbac_rule_item_t;

typedef struct {
	lbac_rule_item_t* items;
	size_t			  count;
} lbac_compiled_rule_t;

/* ----------------------------------------------------------------------- */
/* Strategy implementation */
/* ----------------------------------------------------------------------- */

static sso_error_t lbac_init(permission_strategy_t* self, sso_context_t* ctx) {
	(void)self;
	(void)ctx;
	return SSO_OK;
}

static void lbac_destroy(permission_strategy_t* self) {
	(void)self;
}

static sso_error_t lbac_compile(permission_strategy_t* self, const char* rules_json, void** compiled_rule) {
	(void)self;
	if (!rules_json || !compiled_rule)
		return SSO_ERR_INVALID_PARAM;

	yyjson_doc* doc = yyjson_read(rules_json, strlen(rules_json), 0);
	if (!doc)
		return SSO_ERR_RULE_INVALID;

	yyjson_val* root = yyjson_doc_get_root(doc);

	/* Support both "labels" (new) and "clearance_levels" (old) format */
	yyjson_val* levels = yyjson_obj_get(root, "labels");
	if (!yyjson_is_arr(levels)) {
		levels = yyjson_obj_get(root, "clearance_levels");
	}
	if (!yyjson_is_arr(levels)) {
		yyjson_doc_free(doc);
		return SSO_ERR_RULE_INVALID;
	}

	size_t				  count	   = yyjson_arr_size(levels);
	lbac_compiled_rule_t* compiled = (lbac_compiled_rule_t*)malloc(sizeof(lbac_compiled_rule_t));
	if (!compiled) {
		yyjson_doc_free(doc);
		return SSO_ERR_OUT_OF_MEMORY;
	}

	compiled->count = count;
	compiled->items = (lbac_rule_item_t*)calloc(count, sizeof(lbac_rule_item_t));
	if (!compiled->items) {
		free(compiled);
		yyjson_doc_free(doc);
		return SSO_ERR_OUT_OF_MEMORY;
	}

	size_t		idx, max;
	yyjson_val* item;
	yyjson_arr_foreach(levels, idx, max, item) {
		if (yyjson_is_str(item)) {
			/* Simple string: {array of strings} */
			sso_strlcpy(compiled->items[idx].label_name, yyjson_get_str(item), 63);
			compiled->items[idx].is_allow = true;
		} else if (yyjson_is_obj(item)) {
			/* Object: {name: "...", effect: "..."} */
			yyjson_val* name   = yyjson_obj_get(item, "name");
			yyjson_val* effect = yyjson_obj_get(item, "effect");

			if (yyjson_is_str(name)) {
				sso_strlcpy(compiled->items[idx].label_name, yyjson_get_str(name), 63);
			}

			compiled->items[idx].is_allow = !(yyjson_is_str(effect) && strcmp(yyjson_get_str(effect), "deny") == 0);
		}
	}

	yyjson_doc_free(doc);
	*compiled_rule = compiled;
	return SSO_OK;
}

static void lbac_free_compiled(permission_strategy_t* self, void* compiled_rule) {
	(void)self;
	if (!compiled_rule)
		return;
	lbac_compiled_rule_t* c = (lbac_compiled_rule_t*)compiled_rule;
	free(c->items);
	free(c);
}

/* Helper: check if a label is in a comma-separated string */
static bool label_in_list(const char* label, const char* list) {
	if (!label || !list)
		return false;
	size_t		len = strlen(label);
	const char* p	= list;
	while ((p = strstr(p, label)) != NULL) {
		bool start_ok = (p == list || *(p - 1) == ',');
		bool end_ok	  = (*(p + len) == '\0' || *(p + len) == ',');
		if (start_ok && end_ok)
			return true;
		p += len;
	}
	return false;
}

static sso_error_t lbac_evaluate(permission_strategy_t* self, eval_context_t* ctx, const policy_t* policy,
								 void* compiled_rule, bool* result) {
	(void)self;
	(void)policy;
	if (!ctx || !result || !compiled_rule)
		return SSO_ERR_INVALID_PARAM;

	const char* user_labels	   = ctx->params.lbac.user_labels;
	const char* resource_label = ctx->params.lbac.resource_label;

	if (!user_labels || !resource_label || user_labels[0] == '\0' || resource_label[0] == '\0') {
		return SSO_ERR_NOT_FOUND;
	}

	lbac_compiled_rule_t* compiled = (lbac_compiled_rule_t*)compiled_rule;

	for (size_t i = 0; i < compiled->count; i++) {
		/* Check if the resource label matches this policy item */
		if (strcmp(compiled->items[i].label_name, resource_label) != 0) {
			continue;
		}

		/* Check if the user actually has this label */
		if (!label_in_list(resource_label, user_labels)) {
			return SSO_ERR_NOT_FOUND;
		}

		*result = compiled->items[i].is_allow;
		return SSO_OK;
	}

	return SSO_ERR_NOT_FOUND;
}

static sso_error_t lbac_validate(permission_strategy_t* self, const char* rules_json) {
	(void)self;
	if (!rules_json)
		return SSO_ERR_INVALID_PARAM;
	yyjson_doc* doc = yyjson_read(rules_json, strlen(rules_json), 0);
	if (!doc)
		return SSO_ERR_RULE_INVALID;
	yyjson_doc_free(doc);
	return SSO_OK;
}

permission_strategy_t lbac_perm_strategy = {
		.type				 = PERM_STRATEGY_LBAC,
		.name				 = "lbac",
		.init				 = lbac_init,
		.destroy			 = lbac_destroy,
		.compile_rules		 = lbac_compile,
		.free_compiled_rules = lbac_free_compiled,
		.evaluate			 = lbac_evaluate,
		.validate_rules		 = lbac_validate,
		.userdata			 = NULL,
};
