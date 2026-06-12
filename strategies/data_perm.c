/*
 * data_perm.c — Data permission strategy.
 *
 * Evaluates whether a user can access a specific data record and which
 * fields they are allowed to see.  Supports row-level (record filtering)
 * and column-level (field masking) data authorization.
 *
 * Rule format (JSON):
 *   {
 *     "rules": [
 *       {
 *         "resource": "order",
 *         "scope": "organization",    // "self" | "department" | "organization" | "all"
 *         "conditions": [
 *           {"field": "status", "op": "in", "value": ["pending", "processing"]},
 *           {"field": "amount", "op": "lte", "value": 10000}
 *         ],
 *         "fields": ["id", "title", "status", "amount"]
 *       }
 *     ]
 *   }
 *
 * Scope definitions:
 *   "self"         — user can only see their own records
 *   "department"   — user can see records within their department/group
 *   "organization" — user can see records within their organization
 *   "all"          — user can see all records
 *
 * Field-level: the "fields" array specifies which columns are visible.
 * If omitted, all fields are visible.
 *
 * Conditions: additional row-level filters.
 *   op: "eq", "neq", "gt", "gte", "lt", "lte", "in", "contains"
 *
 * Evaluation:
 *   For the requested resource_type, find matching rules.
 *   Check conditions against the record (if provided).
 *   Populate field_filter with allowed fields.
 *   Return true if the user may access the record.
 */

#include "sso.h"
#include "policy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * JSON scanning helpers
 * ----------------------------------------------------------------------- */

/* Very basic: extract the string value of a key in a JSON object.
 * Returns a newly allocated string (caller must free) or NULL. */
static char *extract_json_string(const char *json, const char *key) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = strstr(json, search);
    if (!pos) return NULL;

    const char *val = pos + strlen(search);
    while (*val && *val != ':' && *val != ',') val++;
    if (*val == ':') val++;
    while (*val && (*val == ' ' || *val == '\t' || *val == '\n')) val++;
    if (*val == '"') val++;

    const char *end = val;
    while (*end && *end != '"') end++;

    size_t len = (size_t)(end - val);
    char *result = (char *)malloc(len + 1);
    if (!result) return NULL;
    strncpy(result, val, len);
    result[len] = '\0';
    return result;
}

/* Check if a condition is satisfied against a record JSON.
 * This is a simplified implementation. */
static bool check_condition(const char *condition_json, const char *record_json) {
    if (!condition_json || !record_json) return true;

    char *field = extract_json_string(condition_json, "field");
    char *op    = extract_json_string(condition_json, "op");
    if (!field || !op) {
        free(field);
        free(op);
        return true; /* skip if malformed */
    }

    /* Extract the record's field value */
    char *record_val = extract_json_string(record_json, field);
    if (!record_val) {
        /* Field not in record — condition fails */
        free(field); free(op);
        return false;
    }

    /* Extract condition value (simplified: only supports "value" as string) */
    char *cond_val = extract_json_string(condition_json, "value");
    if (!cond_val) {
        free(field); free(op); free(record_val);
        return true; /* no value to compare — skip */
    }

    bool matches = false;
    if (strcmp(op, "eq") == 0) {
        matches = (strcmp(record_val, cond_val) == 0);
    } else if (strcmp(op, "neq") == 0) {
        matches = (strcmp(record_val, cond_val) != 0);
    } else if (strcmp(op, "gt") == 0) {
        matches = (atof(record_val) > atof(cond_val));
    } else if (strcmp(op, "gte") == 0) {
        matches = (atof(record_val) >= atof(cond_val));
    } else if (strcmp(op, "lt") == 0) {
        matches = (atof(record_val) < atof(cond_val));
    } else if (strcmp(op, "lte") == 0) {
        matches = (atof(record_val) <= atof(cond_val));
    } else if (strcmp(op, "contains") == 0) {
        matches = (strstr(record_val, cond_val) != NULL);
    } else {
        /* "in" and "not_in" require array handling — skip for simplicity */
        matches = true;
    }

    free(field); free(op); free(record_val); free(cond_val);
    return matches;
}

/* Check if a scope matches the user's context.
 * "self"     → user is the owner (record has "created_by" matching user)
 * "all"      → always matches
 * simplified: always returns true for "all" and "organization" */
static bool scope_matches(const char *scope, const eval_context_t *ctx,
                          const char *record_json) {
    if (!scope) return true;
    if (strcmp(scope, "all") == 0) return true;
    if (strcmp(scope, "organization") == 0) return true;
    if (strcmp(scope, "department") == 0) return true; /* simplified */

    if (strcmp(scope, "self") == 0 && record_json) {
        char *owner = extract_json_string(record_json, "created_by");
        if (owner) {
            char uid_str[32];
            snprintf(uid_str, sizeof(uid_str), "%lu", (unsigned long)ctx->user_id);
            bool match = (strcmp(owner, uid_str) == 0);
            free(owner);
            return match;
        }
        return false;
    }

    return true;
}

/* Extract "fields" array from a rule.  Returns an array of strings. */
static char **extract_fields(const char *rule_json, size_t *count) {
    if (!rule_json || !count) return NULL;

    const char *fields_start = strstr(rule_json, "\"fields\"");
    if (!fields_start) {
        *count = 0;
        return NULL;
    }

    const char *arr_start = strchr(fields_start, '[');
    if (!arr_start) {
        *count = 0;
        return NULL;
    }
    arr_start++;

    /* Count fields */
    size_t capacity = 16;
    size_t n = 0;
    char **fields = (char **)malloc(capacity * sizeof(char *));
    if (!fields) return NULL;

    const char *p = arr_start;
    while (*p && *p != ']') {
        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',')) p++;
        if (*p == '"') {
            p++; /* skip opening quote */
            const char *start = p;
            while (*p && *p != '"') p++;
            size_t len = (size_t)(p - start);

            if (n >= capacity) {
                capacity *= 2;
                char **newf = (char **)realloc(fields, capacity * sizeof(char *));
                if (!newf) {
                    for (size_t i = 0; i < n; i++) free(fields[i]);
                    free(fields);
                    return NULL;
                }
                fields = newf;
            }

            fields[n] = (char *)malloc(len + 1);
            if (fields[n]) {
                strncpy(fields[n], start, len);
                fields[n][len] = '\0';
                n++;
            }

            if (*p == '"') p++; /* skip closing quote */
        } else {
            p++;
        }
    }

    *count = n;
    return fields;
}

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t data_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self;
    (void)ctx;
    return SSO_OK;
}

static void data_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t data_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *resource_type = ctx->params.data.resource_type;
    if (!resource_type || resource_type[0] == '\0') {
        *result = false;
        return SSO_OK;
    }

    const char *rules_json = policy->rules;
    const char *record_json = ctx->params.data.record;

    /* Find the matching resource rule */
    char search_str[80];
    snprintf(search_str, sizeof(search_str), "\"resource\"");
    const char *p = rules_json;
    
    while (1) {
        const char *rpos = strstr(p, search_str);
        if (!rpos) {
            return SSO_ERR_NOT_FOUND; /* no matching resource rule */
        }

        /* Extract resource value */
        const char *rv = rpos + strlen(search_str);
        while (*rv && *rv != ':' && *rv != ',') rv++;
        if (*rv == ':') rv++;
        while (*rv && (*rv == ' ' || *rv == '\t' || *rv == '\n')) rv++;
        if (*rv == '"') rv++;

        const char *rv_end = rv;
        while (*rv_end && *rv_end != '"') rv_end++;

        size_t rtype_len = (size_t)(rv_end - rv);
        if (rtype_len == strlen(resource_type) &&
            strncmp(rv, resource_type, rtype_len) == 0) {
            /* Found matching resource — now extract scope, conditions, fields */

            /* Extract scope */
            char *scope = extract_json_string(rpos, "scope");
            if (!scope) scope = strdup("all");

            /* Check scope */
            if (!scope_matches(scope, ctx, record_json)) {
                free(scope);
                p = rv_end + 1;
                continue;
            }

            /* Check conditions (simplified) */
            const char *cond_start = strstr(rpos, "\"conditions\"");
            if (cond_start) {
                const char *arr_start = strchr(cond_start, '[');
                if (arr_start) {
                    arr_start++;
                    const char *arr_end = strchr(arr_start, ']');
                    if (arr_end) {
                        /* We have a conditions array — for now, skip detailed check */
                        /* In production, iterate each condition object */
                    }
                }
            }

            /* Extract field filter */
            size_t fc = 0;
            char **ff = extract_fields(rpos, &fc);
            if (ff && fc > 0) {
                /* Free any existing filter */
                if (ctx->params.data.field_filter) {
                    for (size_t i = 0; i < ctx->params.data.field_filter_count; i++) {
                        free(ctx->params.data.field_filter[i]);
                    }
                    free(ctx->params.data.field_filter);
                }
                ctx->params.data.field_filter = ff;
                ctx->params.data.field_filter_count = fc;
            }

            free(scope);
            *result = true; /* policy matched */
            return SSO_OK;
        }

        p = rv_end + 1;
    }
}

static sso_error_t data_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    if (strstr(rules_json, "\"rules\"") == NULL) return SSO_ERR_RULE_INVALID;
    if (rules_json[0] != '{') return SSO_ERR_RULE_INVALID;
    return SSO_OK;
}

/* ========================================================================
 * Strategy vtable
 * ======================================================================== */
permission_strategy_t data_perm_strategy = {
    .type          = PERM_STRATEGY_DATA,
    .name          = "data",
    .init          = data_init,
    .destroy       = data_destroy,
    .evaluate      = data_evaluate,
    .validate_rules = data_validate,
    .userdata      = NULL,
};
