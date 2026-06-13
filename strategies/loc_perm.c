/*
 * loc_perm.c — Location-based (IP/Geo) permission strategy.
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static sso_error_t loc_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void loc_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t loc_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    (void)self; (void)compiled_rule;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *ip = ctx->params.location.source_ip;
    if (!ip || ip[0] == '\0') return SSO_ERR_NOT_FOUND;

    /* Production version would use CIDR matching and GeoIP lookup.
     * Simple string matching for now. */
    cJSON *root = cJSON_Parse(policy->rules);
    if (!root) return SSO_ERR_RULE_INVALID;

    cJSON *allowed_ips = cJSON_GetObjectItem(root, "allowed_ips");
    bool matched = false;
    if (cJSON_IsArray(allowed_ips)) {
        cJSON *item;
        cJSON_ArrayForEach(item, allowed_ips) {
            if (cJSON_IsString(item) && strcmp(item->valuestring, ip) == 0) {
                matched = true;
                break;
            }
        }
    }

    cJSON_Delete(root);
    if (matched) {
        *result = true;
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t loc_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    return SSO_OK;
}

permission_strategy_t location_perm_strategy = {
    .type          = PERM_STRATEGY_LOCATION,
    .name          = "location",
    .init          = loc_init,
    .destroy       = loc_destroy,
    .compile_rules = NULL,
    .free_compiled_rules = NULL,
    .evaluate      = loc_evaluate,
    .validate_rules = loc_validate,
    .userdata      = NULL,
};
