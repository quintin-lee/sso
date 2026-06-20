/*
 * loc_perm.c - Location-based (IP/Geo) permission strategy.
 *
 * Supports CIDR notation (e.g. "10.0.0.0/8"), exact IP matching,
 * and geo-country matching.
 *
 * Rule format (JSON):
 *   {
 *     "locations": [
 *       {"type": "ip_cidr", "value": "10.0.0.0/8",  "effect": "allow"},
 *       {"type": "ip_cidr", "value": "0.0.0.0/0",    "effect": "deny"},
 *       {"type": "geo",     "value": "CN",           "effect": "allow"}
 *     ]
 *   }
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* ----------------------------------------------------------------------- */
/* Types */
/* ----------------------------------------------------------------------- */
typedef enum {
    LOC_TYPE_IP_CIDR,
    LOC_TYPE_GEO,
    LOC_TYPE_EXACT
} loc_rule_type_t;

typedef struct {
    loc_rule_type_t  type;
    char             value[256];
    unsigned int     cidr_network;
    unsigned int     cidr_prefix;
    bool             is_allow;
} loc_rule_item_t;

typedef struct {
    loc_rule_item_t *items;
    size_t           count;
} loc_compiled_rule_t;

/* ----------------------------------------------------------------------- */
/* CIDR helpers */
/* ----------------------------------------------------------------------- */

static unsigned int ip_to_uint(const char *s) {
    unsigned a,b,c,d;
    if (sscanf(s, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return 0;
    return (a<<24)|(b<<16)|(c<<8)|d;
}

static bool parse_cidr(const char *str, unsigned int *net, unsigned int *pre) {
    char buf[256];
    sso_strlcpy(buf, str, 255);
    buf[255] = 0;
    char *slash = strchr(buf, '/');
    if (!slash) return false;
    *slash++ = 0;
    *net = ip_to_uint(buf);
    *pre = (unsigned int)atoi(slash);
    return true;
}

static bool ip_matches_cidr(const char *ip_str,
                            const char *cidr_str,
                            unsigned int cidr_network,
                            unsigned int cidr_prefix) {
    unsigned int ip = ip_to_uint(ip_str);
    if (ip == 0) return false;

    if (cidr_prefix > 0) {
        unsigned int mask = (cidr_prefix >= 32) ? 0xFFFFFFFFU
                          : (0xFFFFFFFFU << (32 - cidr_prefix));
        return (ip & mask) == (cidr_network & mask);
    }

    /* Fallback: parse from string */
    unsigned int net, pre;
    if (!parse_cidr(cidr_str, &net, &pre)) {
        return (strcmp(ip_str, cidr_str) == 0);
    }
    unsigned int mask = (pre >= 32) ? 0xFFFFFFFFU : (pre ? (0xFFFFFFFFU << (32U - pre)) : 0U);
    return (ip & mask) == (net & mask);
}

/* ----------------------------------------------------------------------- */
/* Strategy implementation */
/* ----------------------------------------------------------------------- */

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

    const cJSON *location_list = cJSON_GetObjectItem(root, "locations");
    if (!cJSON_IsArray(location_list)) {
        location_list = cJSON_GetObjectItem(root, "allowed_ips");
    }
    if (!cJSON_IsArray(location_list)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    size_t count = (size_t)cJSON_GetArraySize(location_list);
    loc_compiled_rule_t *compiled = (loc_compiled_rule_t *)
        malloc(sizeof(loc_compiled_rule_t));
    if (!compiled) { cJSON_Delete(root); return SSO_ERR_OUT_OF_MEMORY; }

    compiled->count = count;
    compiled->items = (loc_rule_item_t *)
        calloc(count, sizeof(loc_rule_item_t));
    if (!compiled->items) {
        free(compiled); cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        const cJSON *item = cJSON_GetArrayItem(location_list, (int)i);

        if (cJSON_IsString(item)) {
            /* Simple string format: exact IP match */
            sso_strlcpy(compiled->items[i].value,
                    item->valuestring, 255);
            compiled->items[i].type = LOC_TYPE_EXACT;
            compiled->items[i].is_allow = true;
        } else if (cJSON_IsObject(item)) {
            /* Object format: {type, value, effect} */
            cJSON *type  = cJSON_GetObjectItem(item, "type");
            const cJSON *value = cJSON_GetObjectItem(item, "value");
            const cJSON *effect = cJSON_GetObjectItem(item, "effect");

            if (value && cJSON_IsString(value))
                sso_strlcpy(compiled->items[i].value,
                        value->valuestring, 255);

            if (type && cJSON_IsString(type) &&
                strcmp(type->valuestring, "geo") == 0) {
                compiled->items[i].type = LOC_TYPE_GEO;
            } else {
                /* Default: treat as IP CIDR (or EXACT if parse fails) */
                compiled->items[i].type = LOC_TYPE_IP_CIDR;
                if (!parse_cidr(compiled->items[i].value,
                                &compiled->items[i].cidr_network,
                                &compiled->items[i].cidr_prefix)) {
                    compiled->items[i].type = LOC_TYPE_EXACT;
                }
            }

            compiled->items[i].is_allow =
                !(effect && cJSON_IsString(effect) &&
                  strcmp(effect->valuestring, "deny") == 0);
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
    loc_compiled_rule_t *c = (loc_compiled_rule_t *)compiled_rule;
    free(c->items);
    free(c);
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

    loc_compiled_rule_t *compiled =
        (loc_compiled_rule_t *)compiled_rule;

    for (size_t i = 0; i < compiled->count; i++) {
        bool matched = false;

        switch (compiled->items[i].type) {
        case LOC_TYPE_IP_CIDR:
            matched = ip_matches_cidr(ip,
                compiled->items[i].value,
                compiled->items[i].cidr_network,
                compiled->items[i].cidr_prefix);
            break;

        case LOC_TYPE_EXACT:
            matched = (strcmp(ip,
                compiled->items[i].value) == 0);
            break;

        case LOC_TYPE_GEO: {
            const char *country =
                ctx->params.location.geo_country;
            if (country && country[0] != '\0')
                matched = (strcmp(country,
                    compiled->items[i].value) == 0);
            break;
        }
        }

        if (matched) {
            *result = compiled->items[i].is_allow;
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
