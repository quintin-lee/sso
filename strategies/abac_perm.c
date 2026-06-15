/*
 * abac_perm.c — ABAC (Attribute-Based Access Control) permission strategy.
 *
 * This version uses cJSON for proper parsing and pre-compilation for performance.
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
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
        strncpy(list, expected, sizeof(list) - 1);
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

    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    const cJSON *conditions = cJSON_GetObjectItem(root, "conditions");
    if (!cJSON_IsArray(conditions)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    abac_compiled_rule_t *compiled = (abac_compiled_rule_t *)calloc(1, sizeof(abac_compiled_rule_t));
    if (!compiled) {
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    compiled->count = (size_t)cJSON_GetArraySize(conditions);
    compiled->conditions = (abac_condition_t *)calloc(compiled->count, sizeof(abac_condition_t));
    if (!compiled->conditions) {
        free(compiled);
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    /* Parse logic and effect */
    const cJSON *logic = cJSON_GetObjectItem(root, "logic");
    compiled->is_or_logic = (logic && cJSON_IsString(logic) && strcmp(logic->valuestring, "or") == 0);

    const cJSON *effect = cJSON_GetObjectItem(root, "effect");
    compiled->is_allow_effect = !(effect && cJSON_IsString(effect) && strcmp(effect->valuestring, "deny") == 0);

    /* Parse conditions */
    for (size_t i = 0; i < compiled->count; i++) {
        const cJSON *item = cJSON_GetArrayItem(conditions, (int)i);
        const cJSON *src = cJSON_GetObjectItem(item, "source");
        const cJSON *attr = cJSON_GetObjectItem(item, "attr");
        const cJSON *op = cJSON_GetObjectItem(item, "op");
        const cJSON *val = cJSON_GetObjectItem(item, "value");

        if (attr && cJSON_IsString(attr)) {
            strncpy(compiled->conditions[i].attr_name, attr->valuestring, 63);
        }

        if (src && cJSON_IsString(src)) {
            if (strcmp(src->valuestring, "resource") == 0) compiled->conditions[i].source = ABAC_SRC_RESOURCE;
            else if (strcmp(src->valuestring, "environment") == 0) compiled->conditions[i].source = ABAC_SRC_ENVIRONMENT;
            else compiled->conditions[i].source = ABAC_SRC_SUBJECT;
        } else {
            compiled->conditions[i].source = ABAC_SRC_SUBJECT;
        }

        if (op && cJSON_IsString(op)) {
            strncpy(compiled->conditions[i].op, op->valuestring, 15);
        } else {
            strcpy(compiled->conditions[i].op, "eq");
        }

        if (val) {
            if (cJSON_IsString(val)) {
                strncpy(compiled->conditions[i].expected_value, val->valuestring, 255);
            } else if (cJSON_IsNumber(val)) {
                snprintf(compiled->conditions[i].expected_value, 255, "%g", val->valuedouble);
            }
        }
    }

    cJSON_Delete(root);
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

static const char *get_attr_from_cjson(cJSON *root, const char *attr_name, char *buffer, size_t buf_size) {
    if (!root || !attr_name) return NULL;
    const cJSON *item = cJSON_GetObjectItem(root, attr_name);
    if (!item) return NULL;
    
    if (cJSON_IsString(item)) {
        strncpy(buffer, item->valuestring, buf_size - 1);
    } else if (cJSON_IsNumber(item)) {
        snprintf(buffer, buf_size, "%g", item->valuedouble);
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

    cJSON *subject_root = NULL;
    cJSON *resource_root = NULL;
    cJSON *env_root = NULL;

    if (ctx->params.abac.subject_attrs[0] != '\0') subject_root = cJSON_Parse(ctx->params.abac.subject_attrs);
    if (ctx->params.abac.resource_attrs[0] != '\0') resource_root = cJSON_Parse(ctx->params.abac.resource_attrs);
    if (ctx->environment[0] != '\0') env_root = cJSON_Parse(ctx->environment);

    for (size_t i = 0; i < compiled->count; i++) {
        const abac_condition_t *cond = &compiled->conditions[i];
        cJSON *source_root = NULL;

        switch (cond->source) {
            case ABAC_SRC_RESOURCE: source_root = resource_root; break;
            case ABAC_SRC_ENVIRONMENT: source_root = env_root; break;
            default: source_root = subject_root; break;
        }

        char actual_buf[512];
        const char *actual = get_attr_from_cjson(source_root, cond->attr_name, actual_buf, sizeof(actual_buf));
        bool matched = actual ? apply_operator(cond->op, actual, cond->expected_value) : false;

        if (compiled->is_or_logic) {
            if (matched) { any_matched = true; break; }
        } else {
            if (!matched) { all_matched = false; break; }
        }
    }

    if (subject_root) cJSON_Delete(subject_root);
    if (resource_root) cJSON_Delete(resource_root);
    if (env_root) cJSON_Delete(env_root);

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
    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;
    cJSON_Delete(root);
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
