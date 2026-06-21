/*
 * func_perm.c — Functional permission strategy.
 *
 * This version updated to match the new strategy interface.
 */

#include "sso.h"
#include "policy.h"
#include "yyjson.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Helper: wildcard match
 * ----------------------------------------------------------------------- */
static bool wildcard_match(const char *pattern, const char *str) {
    if (!pattern || !str) return false;
    while (*pattern) {
        if (*pattern == '*') {
            while (*pattern == '*') pattern++;
            if (*pattern == '\0') return true;
            while (*str) {
                if (wildcard_match(pattern, str)) return true;
                str++;
            }
            return false;
        }
        if (*pattern != *str) return false;
        pattern++;
        str++;
    }
    return *str == '\0';
}

/* -----------------------------------------------------------------------
 * Pre-compiled Functional rule structure
 * ----------------------------------------------------------------------- */
typedef struct {
    char    code[128];
    bool    is_allow;
} func_rule_item_t;

typedef struct {
    func_rule_item_t *items;
    size_t            count;
} func_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t func_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void func_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t func_compile(permission_strategy_t *self,
                                const char *rules_json,
                                void **compiled_rule) {
    (void)self;
    if (!rules_json || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    yyjson_doc *doc = yyjson_read(rules_json, strlen(rules_json), 0);
    if (!doc) return SSO_ERR_RULE_INVALID;

    yyjson_val *root = yyjson_doc_get_root(doc);
    yyjson_val *funcs = yyjson_obj_get(root, "functions");
    if (!yyjson_is_arr(funcs)) {
        yyjson_doc_free(doc);
        return SSO_ERR_RULE_INVALID;
    }

    size_t count = yyjson_arr_size(funcs);
    func_compiled_rule_t *compiled = (func_compiled_rule_t *)malloc(sizeof(func_compiled_rule_t));
    if (!compiled) {
        yyjson_doc_free(doc);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    compiled->count = count;
    compiled->items = (func_rule_item_t *)calloc(count, sizeof(func_rule_item_t));
    if (!compiled->items) {
        free(compiled);
        yyjson_doc_free(doc);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    yyjson_val *item;
    size_t idx, max;
    yyjson_arr_foreach(funcs, idx, max, item) {
        yyjson_val *code = yyjson_obj_get(item, "code");
        yyjson_val *effect = yyjson_obj_get(item, "effect");

        if (yyjson_is_str(code)) {
            sso_strlcpy(compiled->items[idx].code, yyjson_get_str(code), 127);
        }
        if (yyjson_is_str(effect)) {
            compiled->items[idx].is_allow = (strcmp(yyjson_get_str(effect), "allow") == 0);
        } else {
            compiled->items[idx].is_allow = true; /* default to allow if not specified */
        }
    }

    yyjson_doc_free(doc);
    *compiled_rule = compiled;
    return SSO_OK;
}

static void func_free_compiled(permission_strategy_t *self,
                               void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    func_compiled_rule_t *compiled = (func_compiled_rule_t *)compiled_rule;
    free(compiled->items);
    free(compiled);
}

static sso_error_t func_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    (void)self; (void)policy;
    if (!ctx || !result || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    const char *function_code = ctx->params.functional.function_code;
    if (!function_code || function_code[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    func_compiled_rule_t *compiled = (func_compiled_rule_t *)compiled_rule;

    for (size_t i = 0; i < compiled->count; i++) {
        if (wildcard_match(compiled->items[i].code, function_code)) {
            *result = compiled->items[i].is_allow;
            return SSO_OK;
        }
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t func_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    yyjson_doc *doc = yyjson_read(rules_json, strlen(rules_json), 0);
    if (!doc) return SSO_ERR_RULE_INVALID;
    yyjson_doc_free(doc);
    return SSO_OK;
}

permission_strategy_t func_perm_strategy = {
    .type          = PERM_STRATEGY_FUNCTIONAL,
    .name          = "functional",
    .init          = func_init,
    .destroy       = func_destroy,
    .compile_rules = func_compile,
    .free_compiled_rules = func_free_compiled,
    .evaluate      = func_evaluate,
    .validate_rules = func_validate,
    .userdata      = NULL,
};
