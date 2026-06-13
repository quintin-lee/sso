/*
 * func_perm.c — Functional permission strategy.
 *
 * This version updated to match the new strategy interface.
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
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
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t func_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void func_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t func_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    (void)self; (void)compiled_rule;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *function_code = ctx->params.functional.function_code;
    if (!function_code || function_code[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    /* Fallback to JSON parsing if not compiled */
    cJSON *root = cJSON_Parse(policy->rules);
    if (!root) return SSO_ERR_RULE_INVALID;

    cJSON *funcs = cJSON_GetObjectItem(root, "functions");
    if (!cJSON_IsArray(funcs)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    bool matched = false;
    bool allowed = false;

    cJSON *item;
    cJSON_ArrayForEach(item, funcs) {
        cJSON *code = cJSON_GetObjectItem(item, "code");
        if (cJSON_IsString(code) && wildcard_match(code->valuestring, function_code)) {
            cJSON *effect = cJSON_GetObjectItem(item, "effect");
            allowed = !(effect && cJSON_IsString(effect) && strcmp(effect->valuestring, "deny") == 0);
            matched = true;
            break;
        }
    }

    cJSON_Delete(root);
    if (matched) {
        *result = allowed;
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t func_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;
    cJSON_Delete(root);
    return SSO_OK;
}

permission_strategy_t func_perm_strategy = {
    .type          = PERM_STRATEGY_FUNCTIONAL,
    .name          = "functional",
    .init          = func_init,
    .destroy       = func_destroy,
    .compile_rules = NULL, /* TODO: Implement compilation for func */
    .free_compiled_rules = NULL,
    .evaluate      = func_evaluate,
    .validate_rules = func_validate,
    .userdata      = NULL,
};
