/*
 * data_perm.c — Data-level (Row/Field) permission strategy.
 *
 * This version uses pre-compilation and cJSON for production-grade
 * record-level and field-level security.
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Pre-compiled Data rule structures
 * ----------------------------------------------------------------------- */
typedef struct {
    char    field[64];
    char    op[16];
    char    expected[256];
} data_condition_t;

typedef struct {
    char              resource_type[64];
    data_condition_t *conditions;
    size_t            cond_count;
    char            **allowed_fields;
    size_t            field_count;
    bool              is_allow;
} data_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t data_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void data_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t data_compile(permission_strategy_t *self,
                                 const char *rules_json,
                                 void **compiled_rule) {
    (void)self;
    if (!rules_json || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    data_compiled_rule_t *compiled = (data_compiled_rule_t *)calloc(1, sizeof(data_compiled_rule_t));
    if (!compiled) {
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    cJSON *res_type = cJSON_GetObjectItem(root, "resource_type");
    if (cJSON_IsString(res_type)) strncpy(compiled->resource_type, res_type->valuestring, 63);

    /* Parse record-level conditions */
    cJSON *conds = cJSON_GetObjectItem(root, "conditions");
    if (cJSON_IsArray(conds)) {
        compiled->cond_count = (size_t)cJSON_GetArraySize(conds);
        compiled->conditions = (data_condition_t *)calloc(compiled->cond_count, sizeof(data_condition_t));
        for (size_t i = 0; i < compiled->cond_count; i++) {
            cJSON *item = cJSON_GetArrayItem(conds, (int)i);
            cJSON *f = cJSON_GetObjectItem(item, "field");
            cJSON *o = cJSON_GetObjectItem(item, "op");
            cJSON *v = cJSON_GetObjectItem(item, "value");
            if (f) strncpy(compiled->conditions[i].field, f->valuestring, 63);
            if (o) strncpy(compiled->conditions[i].op, o->valuestring, 15);
            if (v) {
                if (cJSON_IsString(v)) strncpy(compiled->conditions[i].expected, v->valuestring, 255);
                else if (cJSON_IsNumber(v)) snprintf(compiled->conditions[i].expected, 255, "%g", v->valuedouble);
            }
        }
    }

    /* Parse field-level visibility */
    cJSON *fields = cJSON_GetObjectItem(root, "allowed_fields");
    if (cJSON_IsArray(fields)) {
        compiled->field_count = (size_t)cJSON_GetArraySize(fields);
        compiled->allowed_fields = (char **)calloc(compiled->field_count, sizeof(char *));
        for (size_t i = 0; i < compiled->field_count; i++) {
            cJSON *f = cJSON_GetArrayItem(fields, (int)i);
            if (cJSON_IsString(f)) compiled->allowed_fields[i] = strdup(f->valuestring);
        }
    }

    cJSON *effect = cJSON_GetObjectItem(root, "effect");
    compiled->is_allow = !(effect && cJSON_IsString(effect) && strcmp(effect->valuestring, "deny") == 0);

    cJSON_Delete(root);
    *compiled_rule = compiled;
    return SSO_OK;
}

static void data_free_compiled(permission_strategy_t *self, void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    data_compiled_rule_t *compiled = (data_compiled_rule_t *)compiled_rule;
    free(compiled->conditions);
    for (size_t i = 0; i < compiled->field_count; i++) free(compiled->allowed_fields[i]);
    free(compiled->allowed_fields);
    free(compiled);
}

static bool apply_data_op(const char *op, const char *actual, const char *expected) {
    if (strcmp(op, "eq") == 0) return strcmp(actual, expected) == 0;
    if (strcmp(op, "neq") == 0) return strcmp(actual, expected) != 0;
    /* Basic numeric ops */
    double av = strtod(actual, NULL);
    double ev = strtod(expected, NULL);
    if (strcmp(op, "gt") == 0) return av > ev;
    if (strcmp(op, "lt") == 0) return av < ev;
    return false;
}

static sso_error_t data_evaluate(permission_strategy_t *self,
                                  eval_context_t *ctx,
                                  const policy_t *policy,
                                  void *compiled_rule,
                                  bool *result) {
    (void)self; (void)policy;
    if (!ctx || !result || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    data_compiled_rule_t *compiled = (data_compiled_rule_t *)compiled_rule;

    /* 1. Resource Type Check */
    if (strcmp(ctx->params.data.resource_type, compiled->resource_type) != 0) {
        return SSO_ERR_NOT_FOUND;
    }

    /* 2. Condition Check (Record-level) */
    if (ctx->params.data.record) {
        cJSON *record = cJSON_Parse(ctx->params.data.record);
        if (!record) return SSO_ERR_RULE_INVALID;

        for (size_t i = 0; i < compiled->cond_count; i++) {
            cJSON *val = cJSON_GetObjectItem(record, compiled->conditions[i].field);
            if (!val) { cJSON_Delete(record); return SSO_ERR_NOT_FOUND; }

            char actual[256];
            if (cJSON_IsString(val)) strncpy(actual, val->valuestring, 255);
            else if (cJSON_IsNumber(val)) snprintf(actual, 255, "%g", val->valuedouble);
            else { cJSON_Delete(record); return SSO_ERR_NOT_FOUND; }

            if (!apply_data_op(compiled->conditions[i].op, actual, compiled->conditions[i].expected)) {
                cJSON_Delete(record);
                return SSO_ERR_NOT_FOUND;
            }
        }
        cJSON_Delete(record);
    }

    /* 3. Field Filter Population */
    if (compiled->field_count > 0) {
        ctx->params.data.field_filter = (char **)calloc(compiled->field_count, sizeof(char *));
        for (size_t i = 0; i < compiled->field_count; i++) {
            ctx->params.data.field_filter[i] = strdup(compiled->allowed_fields[i]);
        }
        ctx->params.data.field_filter_count = compiled->field_count;
    }

    *result = compiled->is_allow;
    return SSO_OK;
}

static sso_error_t data_validate(permission_strategy_t *self,
                                  const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;
    cJSON_Delete(root);
    return SSO_OK;
}

permission_strategy_t data_perm_strategy = {
    .type          = PERM_STRATEGY_DATA,
    .name          = "data",
    .init          = data_init,
    .destroy       = data_destroy,
    .compile_rules = data_compile,
    .free_compiled_rules = data_free_compiled,
    .evaluate      = data_evaluate,
    .validate_rules = data_validate,
    .userdata      = NULL,
};
