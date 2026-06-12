/*
 * abac_perm.c — ABAC (Attribute-Based Access Control) permission strategy.
 *
 * Evaluates access based on user attributes (subject), resource attributes,
 * and environment context.  Conditions are boolean expressions evaluated
 * against attribute values from the eval_context.
 *
 * Rule format (JSON):
 *   {
 *     "conditions": [
 *       {"source": "subject",   "attr": "department", "op": "eq", "value": "engineering"},
 *       {"source": "subject",   "attr": "clearance",  "op": "gte","value": "3"},
 *       {"source": "resource",  "attr": "owner",      "op": "eq", "value": "alice"},
 *       {"source": "environment","attr": "access_hour","op": "gte","value": "9"}
 *     ],
 *     "logic": "and",
 *     "effect": "allow"
 *   }
 *
 * Evaluation:
 *   1. For each condition, extract the attribute from the matching source.
 *   2. Compare with the condition value using the specified operator.
 *   3. With "and" logic: ALL conditions must match for the policy to apply.
 *   4. With "or" logic: ANY condition matching triggers the policy.
 *   5. If conditions match → return the rule's effect.
 *   6. No match → SSO_ERR_NOT_FOUND.
 * Operators: eq, neq, gt, gte, lt, lte, contains, in (comma-separated)
 *
 * Note: Uses basic strstr-based JSON parsing — sufficient for this rule
 * format.  In production, consider a proper JSON library.
 */

#include "sso.h"
#include "policy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* -----------------------------------------------------------------------
 * Simple JSON value extraction — get the value string for a given key.
 * Returns a heap-allocated string (caller must free) or NULL if not found.
 * ----------------------------------------------------------------------- */
static char *json_extract_value(const char *json, const char *key) {
    if (!json || !key) return NULL;

    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = json;
    const char *found;

    while ((found = strstr(pos, search)) != NULL) {
        const char *val = found + strlen(search);
        /* Skip colon */
        while (*val && *val != ':') val++;
        if (*val == ':') val++;
        /* Skip whitespace */
        while (*val && (*val == ' ' || *val == '\t' || *val == '\n')) val++;

        if (*val == '"') {
            /* String value */
            val++;
            const char *vend = val;
            while (*vend && *vend != '"') vend++;
            size_t len = (size_t)(vend - val);
            char *result = (char *)malloc(len + 1);
            if (!result) return NULL;
            strncpy(result, val, len);
            result[len] = '\0';
            return result;
        } else if (*val == '-' || (*val >= '0' && *val <= '9')) {
            /* Number value */
            const char *vend = val;
            while (*vend && *vend != ',' && *vend != '}' && *vend != ']' && !isspace((unsigned char)*vend)) vend++;
            size_t len = (size_t)(vend - val);
            char *result = (char *)malloc(len + 1);
            if (!result) return NULL;
            strncpy(result, val, len);
            result[len] = '\0';
            return result;
        } else if (*val == '{' || *val == '[') {
            /* Skip nested objects/arrays — not supported for direct comparison */
            return NULL;
        }

        pos = found + 1; /* try next occurrence */
    }

    return NULL;
}

/* -----------------------------------------------------------------------
 * Attribute lookup: get attribute value from a JSON attributes string.
 * The attributes JSON is like {"department":"engineering","clearance":"5"}
 * ----------------------------------------------------------------------- */
static char *get_attribute(const char *attrs_json, const char *attr_name) {
    return json_extract_value(attrs_json, attr_name);
}

/* -----------------------------------------------------------------------
 * Numeric comparison helpers
 * ----------------------------------------------------------------------- */
static double parse_number(const char *s) {
    if (!s || !*s) return 0.0;
    return strtod(s, NULL);
}

/* -----------------------------------------------------------------------
 * Operator application
 * ----------------------------------------------------------------------- */
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
        /* expected is comma-separated list: "a,b,c" */
        char list[1024];
        strncpy(list, expected, sizeof(list) - 1);
        list[sizeof(list) - 1] = '\0';
        char *item = strtok(list, ",");
        while (item) {
            /* Trim whitespace */
            while (*item == ' ') item++;
            char *end = item + strlen(item) - 1;
            while (end > item && *end == ' ') end--;
            *(end + 1) = '\0';
            if (strcmp(actual, item) == 0) return true;
            item = strtok(NULL, ",");
        }
        return false;
    }

    /* Numeric operators — try to parse both as numbers */
    double av = parse_number(actual);
    double ev = parse_number(expected);

    /* If either is NaN, fall back to string comparison */
    if (strcmp(actual, "NaN") == 0 || strcmp(expected, "NaN") == 0) return false;

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
    (void)self;
    (void)ctx;
    return SSO_OK;
}

static void abac_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t abac_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    /* Determine logic: "and" (default) or "or" */
    const char *logic_val = strstr(policy->rules, "\"logic\"");
    bool is_or = false;
    if (logic_val) {
        const char *lv = logic_val + strlen("\"logic\"");
        while (*lv && *lv != ':') lv++;
        if (*lv == ':') lv++;
        while (*lv && (*lv == ' ' || *lv == '\t' || *lv == '\n' || *lv == '"')) lv++;
        is_or = (strncmp(lv, "or", 2) == 0);
    }

    /* Extract effect: "allow" (default) or "deny" */
    const char *eff = strstr(policy->rules, "\"effect\"");
    bool is_allow = true; /* default effect is allow if conditions match */
    if (eff) {
        const char *ev = eff + strlen("\"effect\"");
        while (*ev && (*ev == ' ' || *ev == '\t' || *ev == '\n' || *ev == ':')) ev++;
        if (*ev == '"') ev++;
        is_allow = (strncmp(ev, "allow", 5) == 0);
    }

    /* Parse conditions array */
    const char *cond_start = strstr(policy->rules, "\"conditions\"");
    if (!cond_start) return SSO_ERR_NOT_FOUND;

    const char *arr_start = strchr(cond_start, '[');
    if (!arr_start) return SSO_ERR_NOT_FOUND;

    const char *arr_end = strchr(arr_start, ']');
    if (!arr_end) return SSO_ERR_NOT_FOUND;

    /* Iterate conditions — find "attr" keys */
    const char *p = arr_start + 1;
    bool any_matched = false;
    bool all_matched = true;
    int condition_count = 0;

    while (p < arr_end) {
        /* Find the next attribute key */
        const char *attr_key = strstr(p, "\"attr\"");
        if (!attr_key || attr_key > arr_end) break;

        condition_count++;

        /* Extract attribute name */
        const char *av = attr_key + strlen("\"attr\"");
        while (*av && *av != ':') av++;
        if (*av == ':') av++;
        while (*av && (*av == ' ' || *av == '\t' || *av == '\n')) av++;
        if (*av == '"') av++;

        const char *av_end = av;
        while (*av_end && *av_end != '"') av_end++;

        size_t attr_name_len = (size_t)(av_end - av);
        char attr_name[128];
        size_t copy_n = attr_name_len < sizeof(attr_name) - 1 ? attr_name_len : sizeof(attr_name) - 1;
        strncpy(attr_name, av, copy_n);
        attr_name[copy_n] = '\0';

        /* Extract source (default: "subject") */
        char source[32] = "subject";
        const char *src_key = strstr(attr_key, "\"source\"");
        if (src_key && src_key < arr_end) {
            const char *sv = src_key + strlen("\"source\"");
            while (*sv && *sv != ':') sv++;
            if (*sv == ':') sv++;
            while (*sv && (*sv == ' ' || *sv == '\t' || *sv == '\n')) sv++;
            if (*sv == '"') sv++;
            const char *sv_end = sv;
            while (*sv_end && *sv_end != '"') sv_end++;
            size_t slen = (size_t)(sv_end - sv);
            if (slen > 0 && slen < sizeof(source)) {
                strncpy(source, sv, slen);
                source[slen] = '\0';
            }
        }

        /* Extract operator (default: "eq") */
        char op[16] = "eq";
        const char *op_key = strstr(attr_key, "\"op\"");
        if (op_key && op_key < arr_end) {
            const char *ov = op_key + strlen("\"op\"");
            while (*ov && *ov != ':') ov++;
            if (*ov == ':') ov++;
            while (*ov && (*ov == ' ' || *ov == '\t' || *ov == '\n')) ov++;
            if (*ov == '"') ov++;
            const char *ov_end = ov;
            while (*ov_end && *ov_end != '"') ov_end++;
            size_t olen = (size_t)(ov_end - ov);
            if (olen > 0 && olen < sizeof(op)) {
                strncpy(op, ov, olen);
                op[olen] = '\0';
            }
        }

        /* Extract value to compare against */
        char expected[512] = "";
        const char *val_key = strstr(attr_key, "\"value\"");
        if (val_key && val_key < arr_end) {
            const char *vv = val_key + strlen("\"value\"");
            while (*vv && *vv != ':') vv++;
            if (*vv == ':') vv++;
            while (*vv && (*vv == ' ' || *vv == '\t' || *vv == '\n')) vv++;
            if (*vv == '"') {
                vv++;
                const char *vv_end = vv;
                while (*vv_end && *vv_end != '"') vv_end++;
                size_t vlen = (size_t)(vv_end - vv);
                if (vlen < sizeof(expected)) {
                    strncpy(expected, vv, vlen);
                    expected[vlen] = '\0';
                }
            } else {
                /* Number or other value */
                const char *vv_end = vv;
                while (*vv_end && *vv_end != ',' && *vv_end != '}' && *vv_end != ']' && !isspace((unsigned char)*vv_end)) vv_end++;
                size_t vlen = (size_t)(vv_end - vv);
                if (vlen < sizeof(expected)) {
                    strncpy(expected, vv, vlen);
                    expected[vlen] = '\0';
                }
            }
        }

        /* Get actual attribute value from the right source */
        char actual[512] = "";
        const char *source_json = NULL;

        if (strcmp(source, "resource") == 0) {
            source_json = ctx->params.abac.resource_attrs;
        } else if (strcmp(source, "environment") == 0) {
            source_json = ctx->environment;
        } else {
            source_json = ctx->params.abac.subject_attrs;
        }

        if (source_json && source_json[0]) {
            char *val = get_attribute(source_json, attr_name);
            if (val) {
                strncpy(actual, val, sizeof(actual) - 1);
                actual[sizeof(actual) - 1] = '\0';
                free(val);
            }
        }

        /* Evaluate this condition */
        bool matched = (actual[0] != '\0') ? apply_operator(op, actual, expected) : false;

        if (is_or) {
            if (matched) {
                any_matched = true;
                break;
            }
        } else {
            if (!matched) {
                all_matched = false;
                /* For "and", one failure means the policy doesn't apply */
                break;
            }
        }

        /* Move past this condition */
        p = strchr(attr_key, '}');
        if (p) p++; else break;
    }

    if (condition_count == 0) return SSO_ERR_NOT_FOUND;

    bool conditions_met = is_or ? any_matched : all_matched;
    if (conditions_met) {
        *result = is_allow;
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND; /* conditions not satisfied */
}

static sso_error_t abac_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;

    if (strstr(rules_json, "\"conditions\"") == NULL) {
        return SSO_ERR_RULE_INVALID;
    }

    if (rules_json[0] != '{') return SSO_ERR_RULE_INVALID;

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
    .evaluate      = abac_evaluate,
    .validate_rules = abac_validate,
    .userdata      = NULL,
};
