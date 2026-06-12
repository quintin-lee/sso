/*
 * api_perm.c — API endpoint permission strategy.
 *
 * Evaluates whether a user can access a specific HTTP endpoint.
 * Rules are a JSON array of endpoint patterns with HTTP methods.
 *
 * Rule format (JSON):
 *   {
 *     "endpoints": [
 *       {"method": "GET",    "path": "/api/v1/users",       "effect": "allow"},
 *       {"method": "GET",    "path": "/api/v1/users/*",     "effect": "allow"},
 *       {"method": "POST",   "path": "/api/v1/users",       "effect": "allow"},
 *       {"method": "DELETE", "path": "/api/v1/users/*",     "effect": "deny"},
 *       {"method": "*",      "path": "/api/v1/public/*",    "effect": "allow"}
 *     ]
 *   }
 *
 * Path matching supports:
 *   - Exact match: "/api/v1/users"
 *   - Wildcard:    "/api/v1/users/*" matches any sub-path
 *   - Parametric:  "/api/v1/users/:id" matches "/api/v1/users/42"
 *
 * Method "*" matches any HTTP method.
 *
 * Evaluation:
 *   Find the first endpoint rule that matches both method and path.
 *   - Matched with "allow" → return true
 *   - Matched with "deny"  → return true (engine handles override)
 *   - No match             → return false (policy doesn't apply)
 */

#define _GNU_SOURCE

#include "sso.h"
#include "policy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* -----------------------------------------------------------------------
 * Path matching helpers
 * ----------------------------------------------------------------------- */

/* Compare a route path pattern against an actual request path.
 * Supports:
 *   *      — matches any single path segment
 *   **     — matches any remaining path
 *   :param — matches any single path segment (parametric) */
static bool path_match(const char *pattern, const char *path) {
    if (!pattern || !path) return false;

    while (*pattern && *path) {
        if (*pattern == '*') {
            /* Double wildcard: match everything remaining */
            if (*(pattern + 1) == '*') {
                return true;
            }
            /* Single wildcard: match one segment */
            while (*path && *path != '/') path++;
            pattern++;
            /* Skip the slash in pattern if present */
            if (*pattern == '/') pattern++;
        } else if (*pattern == ':') {
            /* Parametric segment: skip pattern segment, match one path segment */
            while (*pattern && *pattern != '/') pattern++;
            while (*path && *path != '/') path++;
            /* Both should now be at '/' or '\0' */
        } else {
            if (*pattern != *path) return false;
            pattern++;
            path++;
        }
    }

    /* Allow trailing '*' in pattern */
    while (*pattern == '*') pattern++;

    return (*pattern == '\0' && *path == '\0');
}

/* Find the effect for a given method + path in the rule JSON. */
static bool find_endpoint_effect(const char *rules, const char *method,
                                 const char *path, policy_effect_t *effect) {
    if (!rules || !method || !path || !effect) return false;

    const char *p = rules;
    const char *method_key;
    char rule_method[16];
    char rule_path[256];
    char rule_effect[8];

    /* Very simple linear scan — in production use a proper JSON parser */
    while ((method_key = strstr(p, "\"method\"")) != NULL) {
        /* --- Extract method --- */
        const char *mv = method_key + strlen("\"method\"");
        while (*mv && *mv != ':') mv++;
        if (*mv == ':') mv++;
        while (*mv && (*mv == ' ' || *mv == '\t' || *mv == '\n')) mv++;
        if (*mv == '"') mv++;

        const char *mv_end = mv;
        while (*mv_end && *mv_end != '"') mv_end++;

        size_t mlen = (size_t)(mv_end - mv);
        if (mlen >= sizeof(rule_method)) mlen = sizeof(rule_method) - 1;
        strncpy(rule_method, mv, mlen);
        rule_method[mlen] = '\0';

        /* --- Extract path --- */
        const char *pv = strstr(method_key + 1, "\"path\"");
        if (!pv) break;
        pv += strlen("\"path\"");
        while (*pv && *pv != ':') pv++;
        if (*pv == ':') pv++;
        while (*pv && (*pv == ' ' || *pv == '\t' || *pv == '\n')) pv++;
        if (*pv == '"') pv++;

        const char *pv_end = pv;
        while (*pv_end && *pv_end != '"') pv_end++;

        size_t plen = (size_t)(pv_end - pv);
        if (plen >= sizeof(rule_path)) plen = sizeof(rule_path) - 1;
        strncpy(rule_path, pv, plen);
        rule_path[plen] = '\0';

        /* --- Check method match --- */
        bool method_matches = (strcmp(rule_method, "*") == 0) ||
                              (strcasecmp(rule_method, method) == 0);
        if (!method_matches) {
            p = mv_end + 1;
            continue;
        }

        /* --- Check path match --- */
        if (!path_match(rule_path, path)) {
            p = pv_end + 1;
            continue;
        }

        /* --- Extract effect --- */
        const char *ev = strstr(method_key + 1, "\"effect\"");
        if (!ev) continue;
        ev += strlen("\"effect\"");
        while (*ev && *ev != ':') ev++;
        if (*ev == ':') ev++;
        while (*ev && (*ev == ' ' || *ev == '\t' || *ev == '\n')) ev++;
        if (*ev == '"') ev++;

        if (strncmp(ev, "allow", 5) == 0) {
            *effect = POLICY_EFFECT_ALLOW;
            return true;
        } else if (strncmp(ev, "deny", 4) == 0) {
            *effect = POLICY_EFFECT_DENY;
            return true;
        }

        p = mv_end + 1;
    }

    return false;
}

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t api_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self;
    (void)ctx;
    return SSO_OK;
}

static void api_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t api_evaluate(permission_strategy_t *self,
                                eval_context_t *ctx,
                                const policy_t *policy,
                                bool *result) {
    (void)self;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *method = ctx->params.api.http_method;
    const char *path   = ctx->params.api.request_path;

    if (!method || !path || method[0] == '\0' || path[0] == '\0') {
        return SSO_ERR_NOT_FOUND; /* neutral — params not for this strategy */
    }

    policy_effect_t effect;
    if (find_endpoint_effect(policy->rules, method, path, &effect)) {
        *result = (effect == POLICY_EFFECT_ALLOW);
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND; /* no rule matches */
}

static sso_error_t api_validate(permission_strategy_t *self,
                                const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    if (strstr(rules_json, "\"endpoints\"") == NULL) return SSO_ERR_RULE_INVALID;
    if (rules_json[0] != '{') return SSO_ERR_RULE_INVALID;
    return SSO_OK;
}

/* ========================================================================
 * Strategy vtable
 * ======================================================================== */
permission_strategy_t api_perm_strategy = {
    .type          = PERM_STRATEGY_API,
    .name          = "api",
    .init          = api_init,
    .destroy       = api_destroy,
    .evaluate      = api_evaluate,
    .validate_rules = api_validate,
    .userdata      = NULL,
};
