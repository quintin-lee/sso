/*
 * abac_perm.c — ABAC (Attribute-Based Access Control) permission strategy.
 *
 * This version uses cJSON for proper parsing and pre-compilation for performance.
 */

#include "sso.h"
#include "policy.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* -----------------------------------------------------------------------
 * Pre-compiled ABAC rule structures
 * ----------------------------------------------------------------------- */

typedef enum {
    ABAC_SRC_SUBJECT,
    ABAC_SRC_RESOURCE,
    ABAC_SRC_ENVIRONMENT
} abac_source_t;

typedef struct {
    char            attr_name[64];
    abac_source_t   source;
    char            op[16];
    char            expected_value[256];
} abac_condition_t;

typedef struct {
    abac_condition_t *conditions;
    size_t            count;
    bool              is_or_logic;
    bool              is_allow_effect;
} abac_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Operator application (Numeric + String)
 * ----------------------------------------------------------------------- */
static double parse_number(const char *s) {
    if (!s || !*s) return 0.0;
    return strtod(s, NULL);
}

static bool apply_operator(const char *op, const char *actual, const char *expected) {
    if (!op || !actual || !expected) return false;

    if (strcmp(op, "eq") == 0) {
        return strcmp(actual, expected) == 0;
    }
    if (strcmp(op, "neq") == 0) {
        return strcmp(actual, expected) != 0;
    }
    if (strcmp(op, "contains") == 0) {
        return strstr(actual, expected) != NULL;
    }
    if (strcmp(op, "in") == 0) {
        char list[1024];
        sso_strlcpy(list, expected, sizeof(list));
        list[sizeof(list) - 1] = '\0';
        char *item = strtok(list, ",");
        while (item) {
            while (*item == ' ') item++;
            char *end = item + strlen(item) - 1;
            while (end > item && *end == ' ') end--;
            *(end + 1) = '\0';
            if (strcmp(actual, item) == 0) return true;
            item = strtok(NULL, ",");
        }
        return false;
    }

    double av = parse_number(actual);
    double ev = parse_number(expected);

    if (strcmp(op, "gt") == 0)  return av > ev;
    if (strcmp(op, "gte") == 0) return av >= ev;
    if (strcmp(op, "lt") == 0)  return av < ev;
    if (strcmp(op, "lte") == 0) return av <= ev;

    return false;
}

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t abac_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void abac_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t abac_compile(permission_strategy_t *self,
                                 const char *rules_json,
                                 void **compiled_rule) {
    (void)self;
    if (!rules_json || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    yyjson_doc *doc = yyjson_read(rules_json, strlen(rules_json), 0);
    if (!doc) return SSO_ERR_RULE_INVALID;

    yyjson_val *root = yyjson_doc_get_root(doc);

    yyjson_val *conditions = yyjson_obj_get(root, "conditions");
    if (!yyjson_is_arr(conditions)) {
        yyjson_doc_free(doc);
        return SSO_ERR_RULE_INVALID;
    }

    abac_compiled_rule_t *compiled = (abac_compiled_rule_t *)calloc(1, sizeof(abac_compiled_rule_t));
    if (!compiled) {
        yyjson_doc_free(doc);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    compiled->count = yyjson_arr_size(conditions);
    compiled->conditions = (abac_condition_t *)calloc(compiled->count, sizeof(abac_condition_t));
    if (!compiled->conditions) {
        free(compiled);
        yyjson_doc_free(doc);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    /* Parse logic and effect */
    yyjson_val *logic = yyjson_obj_get(root, "logic");
    compiled->is_or_logic = (yyjson_is_str(logic) && strcmp(yyjson_get_str(logic), "or") == 0);

    yyjson_val *effect = yyjson_obj_get(root, "effect");
    compiled->is_allow_effect = !(yyjson_is_str(effect) && strcmp(yyjson_get_str(effect), "deny") == 0);

    /* Parse conditions */
    size_t idx, max;
    yyjson_val *item;
    yyjson_arr_foreach(conditions, idx, max, item) {
        yyjson_val *src = yyjson_obj_get(item, "source");
        yyjson_val *attr = yyjson_obj_get(item, "attr");
        yyjson_val *op = yyjson_obj_get(item, "op");
        yyjson_val *val = yyjson_obj_get(item, "value");

        if (yyjson_is_str(attr)) {
            sso_strlcpy(compiled->conditions[idx].attr_name, yyjson_get_str(attr), 63);
        }

        if (yyjson_is_str(src)) {
            const char *src_str = yyjson_get_str(src);
            if (strcmp(src_str, "resource") == 0) compiled->conditions[idx].source = ABAC_SRC_RESOURCE;
            else if (strcmp(src_str, "environment") == 0) compiled->conditions[idx].source = ABAC_SRC_ENVIRONMENT;
            else compiled->conditions[idx].source = ABAC_SRC_SUBJECT;
        } else {
            compiled->conditions[idx].source = ABAC_SRC_SUBJECT;
        }

        if (yyjson_is_str(op)) {
            sso_strlcpy(compiled->conditions[idx].op, yyjson_get_str(op), 15);
        } else {
            strcpy(compiled->conditions[idx].op, "eq");
        }

        if (val) {
            if (yyjson_is_str(val)) {
                sso_strlcpy(compiled->conditions[idx].expected_value, yyjson_get_str(val), 255);
            } else if (yyjson_is_num(val)) {
                snprintf(compiled->conditions[idx].expected_value, 255, "%g", yyjson_get_num(val));
            }
        }
    }

    yyjson_doc_free(doc);
    *compiled_rule = compiled;
    return SSO_OK;
}

static void abac_free_compiled(permission_strategy_t *self,
                               void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    abac_compiled_rule_t *compiled = (abac_compiled_rule_t *)compiled_rule;
    free(compiled->conditions);
    free(compiled);
}

static const char *get_attr_from_yyjson(yyjson_val *root, const char *attr_name, char *buffer, size_t buf_size) {
    if (!root || !attr_name) return NULL;
    yyjson_val *item = yyjson_obj_get(root, attr_name);
    if (!item) return NULL;
    
    if (yyjson_is_str(item)) {
        sso_strlcpy(buffer, yyjson_get_str(item), buf_size);
    } else if (yyjson_is_num(item)) {
        snprintf(buffer, buf_size, "%g", yyjson_get_num(item));
    } else {
        return NULL;
    }
    buffer[buf_size - 1] = '\0';
    return buffer;
}

static sso_error_t abac_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    abac_compiled_rule_t *compiled = (abac_compiled_rule_t *)compiled_rule;
    bool any_matched = false;
    bool all_matched = true;

    yyjson_doc *subject_doc = NULL, *resource_doc = NULL, *env_doc = NULL;
    yyjson_val *subject_root = NULL, *resource_root = NULL, *env_root = NULL;

    if (ctx->params.abac.subject_attrs[0] != '\0') {
        subject_doc = yyjson_read(ctx->params.abac.subject_attrs, strlen(ctx->params.abac.subject_attrs), 0);
        if (subject_doc) subject_root = yyjson_doc_get_root(subject_doc);
    }
    if (ctx->params.abac.resource_attrs[0] != '\0') {
        resource_doc = yyjson_read(ctx->params.abac.resource_attrs, strlen(ctx->params.abac.resource_attrs), 0);
        if (resource_doc) resource_root = yyjson_doc_get_root(resource_doc);
    }
    if (ctx->environment[0] != '\0') {
        env_doc = yyjson_read(ctx->environment, strlen(ctx->environment), 0);
        if (env_doc) env_root = yyjson_doc_get_root(env_doc);
    }

    for (size_t i = 0; i < compiled->count; i++) {
        const abac_condition_t *cond = &compiled->conditions[i];
        yyjson_val *source_root = NULL;

        switch (cond->source) {
            case ABAC_SRC_RESOURCE: source_root = resource_root; break;
            case ABAC_SRC_ENVIRONMENT: source_root = env_root; break;
            default: source_root = subject_root; break;
        }

        char actual_buf[512];
        const char *actual = get_attr_from_yyjson(source_root, cond->attr_name, actual_buf, sizeof(actual_buf));
        bool matched = actual ? apply_operator(cond->op, actual, cond->expected_value) : false;

        if (compiled->is_or_logic) {
            if (matched) { any_matched = true; break; }
        } else {
            if (!matched) { all_matched = false; break; }
        }
    }

    if (subject_doc) yyjson_doc_free(subject_doc);
    if (resource_doc) yyjson_doc_free(resource_doc);
    if (env_doc) yyjson_doc_free(env_doc);

    bool conditions_met = compiled->is_or_logic ? any_matched : all_matched;
    if (conditions_met) {
        *result = compiled->is_allow_effect;
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t abac_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    yyjson_doc *doc = yyjson_read(rules_json, strlen(rules_json), 0);
    if (!doc) return SSO_ERR_RULE_INVALID;
    yyjson_doc_free(doc);
    return SSO_OK;
}

/* ========================================================================
 * Strategy vtable
 * ======================================================================== */
permission_strategy_t abac_perm_strategy = {
    .type          = PERM_STRATEGY_ABAC,
    .name          = "abac",
    .init          = abac_init,
    .destroy       = abac_destroy,
    .compile_rules = abac_compile,
    .free_compiled_rules = abac_free_compiled,
    .evaluate      = abac_evaluate,
    .validate_rules = abac_validate,
    .userdata      = NULL,
};
