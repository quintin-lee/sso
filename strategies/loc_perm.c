/*
 * loc_perm.c — Location-based (IP/Geo) permission strategy.
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Pre-compiled Location rule structure
 * ----------------------------------------------------------------------- */
typedef struct {
    char **allowed_ips;
    size_t count;
} loc_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t loc_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void loc_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t loc_compile(permission_strategy_t *self,
                                const char *rules_json,
                                void **compiled_rule) {
    (void)self;
    if (!rules_json || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    cJSON *allowed_ips = cJSON_GetObjectItem(root, "allowed_ips");
    if (!cJSON_IsArray(allowed_ips)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    size_t count = (size_t)cJSON_GetArraySize(allowed_ips);
    loc_compiled_rule_t *compiled = (loc_compiled_rule_t *)malloc(sizeof(loc_compiled_rule_t));
    if (!compiled) {
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    compiled->count = count;
    compiled->allowed_ips = (char **)calloc(count, sizeof(char *));
    if (!compiled->allowed_ips) {
        free(compiled);
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(allowed_ips, (int)i);
        if (cJSON_IsString(item)) {
            compiled->allowed_ips[i] = strdup(item->valuestring);
        }
    }

    cJSON_Delete(root);
    *compiled_rule = compiled;
    return SSO_OK;
}

static void loc_free_compiled(permission_strategy_t *self,
                              void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    loc_compiled_rule_t *compiled = (loc_compiled_rule_t *)compiled_rule;
    if (compiled->allowed_ips) {
        for (size_t i = 0; i < compiled->count; i++) {
            if (compiled->allowed_ips[i]) free(compiled->allowed_ips[i]);
        }
        free(compiled->allowed_ips);
    }
    free(compiled);
}

static sso_error_t loc_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    (void)self; (void)policy;
    if (!ctx || !result || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    const char *ip = ctx->params.location.source_ip;
    if (!ip || ip[0] == '\0') return SSO_ERR_NOT_FOUND;

    loc_compiled_rule_t *compiled = (loc_compiled_rule_t *)compiled_rule;

    /* Production version would use CIDR matching and GeoIP lookup.
     * Simple string matching for now. */
    for (size_t i = 0; i < compiled->count; i++) {
        if (compiled->allowed_ips[i] && strcmp(compiled->allowed_ips[i], ip) == 0) {
            *result = true;
            return SSO_OK;
        }
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t loc_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;
    cJSON_Delete(root);
    return SSO_OK;
}

permission_strategy_t location_perm_strategy = {
    .type          = PERM_STRATEGY_LOCATION,
    .name          = "location",
    .init          = loc_init,
    .destroy       = loc_destroy,
    .compile_rules = loc_compile,
    .free_compiled_rules = loc_free_compiled,
    .evaluate      = loc_evaluate,
    .validate_rules = loc_validate,
    .userdata      = NULL,
};
