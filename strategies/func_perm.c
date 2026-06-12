/*
 * func_perm.c — Functional permission strategy.
 *
 * Evaluates whether a user has access to a specific function/feature.
 * Rules are a JSON array of function codes with allow/deny semantics.
 *
 * Rule format (JSON):
 *   {
 *     "functions": [
 *       {"code": "user:create", "effect": "allow"},
 *       {"code": "user:delete", "effect": "deny"},
 *       {"code": "report:view", "effect": "allow"}
 *     ]
 *   }
 *
 * Evaluation:
 *   Look up the function_code from eval_context in the policy's rule list.
 *   - Found with effect "allow" → return true (matched, allowed)
 *   - Found with effect "deny"  → return true (matched, denied)
 *   - Not found                → return false (no match, skip this policy)
 *
 * The engine handles DENY-overrides at a higher level, so this strategy
 * simply reports "did the policy match the function" and if so, what the
 * policy says.  Glob-style wildcards (*) are supported: "report:*" matches
 * "report:view", "report:export", etc.
 */

#include "sso.h"
#include "policy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Minimal JSON parser — enough for our rule format.
 * In production, use a proper library (cjson, jsmn, yyjson).
 * ----------------------------------------------------------------------- */

/* Simple wildcard match: '*' matches any sequence. */
static bool wildcard_match(const char *pattern, const char *str) {
    if (!pattern || !str) return false;

    while (*pattern) {
        if (*pattern == '*') {
            /* Skip consecutive wildcards */
            while (*pattern == '*') pattern++;
            if (*pattern == '\0') return true; /* trailing wildcard matches everything */
            /* Try to match the rest of the pattern at any position in str */
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

/* Scan for a JSON string value after a key.  Very basic — assumes well-formed JSON. */
static bool find_function_effect(const char *rules, const char *function_code,
                                 policy_effect_t *effect) {
    if (!rules || !function_code || !effect) return false;

    /* Search for "code": "function_code" pattern */
    char search_pattern[256];
    snprintf(search_pattern, sizeof(search_pattern), "\"code\"%s", ":");

    const char *p = rules;
    const char *code_pos;

    while ((code_pos = strstr(p, search_pattern)) != NULL) {
        /* Move past "code": and whitespace to the value */
        const char *val = code_pos + strlen(search_pattern);
        while (*val && (*val == ' ' || *val == '\t' || *val == '\n' || *val == '"')) val++;

        /* Find end of code value */
        const char *val_end = val;
        while (*val_end && *val_end != '"') val_end++;

        /* Check if the code matches (with wildcard support) */
        size_t code_len = (size_t)(val_end - val);
        char extracted[128];
        size_t copy_len = code_len < sizeof(extracted) - 1 ? code_len : sizeof(extracted) - 1;
        strncpy(extracted, val, copy_len);
        extracted[copy_len] = '\0';

        if (wildcard_match(extracted, function_code)) {
            /* Found matching function — find its effect */
            const char *eff = strstr(code_pos + 1, "\"effect\"");
            if (!eff) continue;

            const char *eff_val = eff + strlen("\"effect\"");
            while (*eff_val && (*eff_val == ' ' || *eff_val == '\t' || *eff_val == '\n' || *eff_val == ':' || *eff_val == '"')) eff_val++;

            if (strncmp(eff_val, "allow", 5) == 0) {
                *effect = POLICY_EFFECT_ALLOW;
                return true;
            } else if (strncmp(eff_val, "deny", 4) == 0) {
                *effect = POLICY_EFFECT_DENY;
                return true;
            }
        }

        p = val_end + 1;
    }

    return false;
}

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t func_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self;
    (void)ctx;
    /* No special init needed for functional strategy */
    return SSO_OK;
}

static void func_destroy(permission_strategy_t *self) {
    (void)self;
    /* Nothing to free */
}

static sso_error_t func_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *function_code = ctx->params.functional.function_code;
    if (!function_code || function_code[0] == '\0') {
        return SSO_ERR_NOT_FOUND; /* neutral — params not for this strategy */
    }

    policy_effect_t effect;
    if (find_function_effect(policy->rules, function_code, &effect)) {
        /* Rule found — report its effect directly.
         * true  = ALLOW (engine allows access)
         * false = DENY (engine overrides to deny) */
        *result = (effect == POLICY_EFFECT_ALLOW);
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND; /* no rule matches — policy doesn't apply */
}

static sso_error_t func_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;

    /* Basic validation: must contain "functions" array */
    if (strstr(rules_json, "\"functions\"") == NULL) {
        return SSO_ERR_RULE_INVALID;
    }

    /* Check for valid JSON structure */
    if (rules_json[0] != '{') {
        return SSO_ERR_RULE_INVALID;
    }

    return SSO_OK;
}

/* ========================================================================
 * Strategy vtable — this is the singleton the engine registers.
 * ======================================================================== */
permission_strategy_t func_perm_strategy = {
    .type          = PERM_STRATEGY_FUNCTIONAL,
    .name          = "functional",
    .init          = func_init,
    .destroy       = func_destroy,
    .evaluate      = func_evaluate,
    .validate_rules = func_validate,
    .userdata      = NULL,
};
