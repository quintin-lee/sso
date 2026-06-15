/*
 * api_perm.c — API endpoint permission strategy.
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* -----------------------------------------------------------------------
 * Path matching helpers
 * ----------------------------------------------------------------------- */
static bool path_match(const char *pattern, const char *path) {
    if (!pattern || !path) return false;
    while (*pattern && *path) {
        if (*pattern == '*') {
            if (*(pattern + 1) == '*') return true;
            while (*path && *path != '/') path++;
            pattern++;
            if (*pattern == '/') pattern++;
        } else if (*pattern == ':') {
            while (*pattern && *pattern != '/') pattern++;
            while (*path && *path != '/') path++;
        } else {
            if (*pattern != *path) return false;
            pattern++;
            path++;
        }
    }
    while (*pattern == '*') pattern++;
    return (*pattern == '\0' && *path == '\0');
}

/* -----------------------------------------------------------------------
 * Pre-compiled API rule structures
 * ----------------------------------------------------------------------- */
typedef struct {
    char    method[16];
    char    path[256];
    bool    is_allow;
} api_rule_item_t;

typedef struct {
    api_rule_item_t *items;
    size_t           count;
} api_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t api_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void api_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t api_compile(permission_strategy_t *self,
                                const char *rules_json,
                                void **compiled_rule) {
    (void)self;
    if (!rules_json || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    const cJSON *endpoints = cJSON_GetObjectItem(root, "endpoints");
    if (!cJSON_IsArray(endpoints)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    api_compiled_rule_t *compiled = (api_compiled_rule_t *)calloc(1, sizeof(api_compiled_rule_t));
    if (!compiled) {
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    compiled->count = (size_t)cJSON_GetArraySize(endpoints);
    compiled->items = (api_rule_item_t *)calloc(compiled->count, sizeof(api_rule_item_t));
    if (!compiled->items) {
        free(compiled);
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < compiled->count; i++) {
        const cJSON *item = cJSON_GetArrayItem(endpoints, (int)i);
        const cJSON *method = cJSON_GetObjectItem(item, "method");
        const cJSON *path = cJSON_GetObjectItem(item, "path");
        const cJSON *effect = cJSON_GetObjectItem(item, "effect");

        if (method && cJSON_IsString(method)) strncpy(compiled->items[i].method, method->valuestring, 15);
        if (path && cJSON_IsString(path)) strncpy(compiled->items[i].path, path->valuestring, 255);
        compiled->items[i].is_allow = !(effect && cJSON_IsString(effect) && strcmp(effect->valuestring, "deny") == 0);
    }

    cJSON_Delete(root);
    *compiled_rule = compiled;
    return SSO_OK;
}

static void api_free_compiled(permission_strategy_t *self, void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    api_compiled_rule_t *compiled = (api_compiled_rule_t *)compiled_rule;
    free(compiled->items);
    free(compiled);
}

static sso_error_t api_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    const char *method = ctx->params.api.http_method;
    const char *path   = ctx->params.api.request_path;
    if (!method || !path || method[0] == '\0' || path[0] == '\0') return SSO_ERR_NOT_FOUND;

    api_compiled_rule_t *compiled = (api_compiled_rule_t *)compiled_rule;

    for (size_t i = 0; i < compiled->count; i++) {
        bool method_matches = (strcmp(compiled->items[i].method, "*") == 0) ||
                              (strcasecmp(compiled->items[i].method, method) == 0);
        if (method_matches && path_match(compiled->items[i].path, path)) {
            *result = compiled->items[i].is_allow;
            return SSO_OK;
        }
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t api_validate(permission_strategy_t *self,
                                const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;
    cJSON_Delete(root);
    return SSO_OK;
}

permission_strategy_t api_perm_strategy = {
    .type          = PERM_STRATEGY_API,
    .name          = "api",
    .init          = api_init,
    .destroy       = api_destroy,
    .compile_rules = api_compile,
    .free_compiled_rules = api_free_compiled,
    .evaluate      = api_evaluate,
    .validate_rules = api_validate,
    .userdata      = NULL,
};
