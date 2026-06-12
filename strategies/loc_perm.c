/*
 * loc_perm.c — Location-Based Access Control permission strategy.
 *
 * Evaluates whether a request originates from an allowed location.
 * Rules define IP CIDR ranges with allow/deny semantics.
 *
 * Rule format (JSON):
 *   {
 *     "locations": [
 *       {"type": "ip_cidr", "value": "10.0.0.0/8",    "effect": "allow"},
 *       {"type": "ip_cidr", "value": "192.168.0.0/16", "effect": "allow"},
 *       {"type": "ip_cidr", "value": "0.0.0.0/0",      "effect": "deny"}
 *     ]
 *   }
 */

#include "sso.h"
#include "policy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* -----------------------------------------------------------------------
 * CIDR helper: check if an IP string falls within a CIDR range.
 * ----------------------------------------------------------------------- */
static bool ip_in_cidr(const char *ip_str, const char *cidr_str) {
    if (!ip_str || !cidr_str) return false;

    char cidr_copy[128];
    strncpy(cidr_copy, cidr_str, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = '\0';

    char *slash = strchr(cidr_copy, '/');
    if (!slash) {
        struct in_addr addr, net;
        if (inet_pton(AF_INET, ip_str, &addr) != 1) return false;
        if (inet_pton(AF_INET, cidr_copy, &net) != 1) return false;
        return addr.s_addr == net.s_addr;
    }

    *slash = '\0';
    const char *net_str = cidr_copy;
    int prefix = atoi(slash + 1);

    struct in_addr addr, net;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        struct in6_addr addr6, net6;
        if (inet_pton(AF_INET6, ip_str, &addr6) != 1) return false;
        if (inet_pton(AF_INET6, net_str, &net6) != 1) return false;

        if (prefix > 128) prefix = 128;
        unsigned char *a = (unsigned char *)&addr6;
        unsigned char *n = (unsigned char *)&net6;
        for (int i = 0; i < prefix / 8; i++) {
            if (a[i] != n[i]) return false;
        }
        if (prefix % 8 != 0) {
            int bits = prefix % 8;
            unsigned char mask = (unsigned char)(0xFF << (8 - bits));
            if ((a[prefix / 8] & mask) != (n[prefix / 8] & mask)) return false;
        }
        return true;
    }

    if (inet_pton(AF_INET, net_str, &net) != 1) return false;
    if (prefix <= 0) return true;
    if (prefix >= 32) return addr.s_addr == net.s_addr;

    uint32_t mask = htonl((uint32_t)(0xFFFFFFFF << (32 - prefix)));
    return (addr.s_addr & mask) == (net.s_addr & mask);
}

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
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *source_ip = ctx->params.location.source_ip;
    if (!source_ip || source_ip[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    const char *p = policy->rules;
    const char *type_key = "\"type\"";
    const char *type_pos;

    while ((type_pos = strstr(p, type_key)) != NULL) {
        const char *tv = type_pos + strlen(type_key);
        while (*tv && *tv != ':') tv++;
        if (*tv == ':') tv++;
        while (*tv && (*tv == ' ' || *tv == '\t' || *tv == '\n')) tv++;
        if (*tv == '"') tv++;

        const char *tv_end = tv;
        while (*tv_end && *tv_end != '"') tv_end++;
        size_t type_len = (size_t)(tv_end - tv);

        bool type_match = (type_len == 7 && strncmp(tv, "ip_cidr", 7) == 0);
        if (!type_match) {
            p = tv_end + 1;
            continue;
        }

        const char *value_key = "\"value\"";
        const char *vv = strstr(type_pos, value_key);
        if (!vv) { p = tv_end + 1; continue; }

        vv += strlen(value_key);
        while (*vv && *vv != ':') vv++;
        if (*vv == ':') vv++;
        while (*vv && (*vv == ' ' || *vv == '\t' || *vv == '\n')) vv++;
        if (*vv == '"') vv++;

        const char *vv_end = vv;
        while (*vv_end && *vv_end != '"') vv_end++;

        size_t value_len = (size_t)(vv_end - vv);
        char cidr_str[128];
        size_t copy_len = value_len < sizeof(cidr_str) - 1 ? value_len : sizeof(cidr_str) - 1;
        strncpy(cidr_str, vv, copy_len);
        cidr_str[copy_len] = '\0';

        const char *eff = strstr(type_pos, "\"effect\"");
        if (!eff) { p = vv_end + 1; continue; }

        const char *eff_val = eff + strlen("\"effect\"");
        while (*eff_val && (*eff_val == ' ' || *eff_val == '\t' || *eff_val == '\n'
               || *eff_val == ':')) eff_val++;
        if (*eff_val == '"') eff_val++;

        bool is_allow = (strncmp(eff_val, "allow", 5) == 0);

        if (ip_in_cidr(source_ip, cidr_str)) {
            *result = is_allow;
            return SSO_OK;
        }

        p = vv_end + 1;
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t loc_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    if (strstr(rules_json, "\"locations\"") == NULL) return SSO_ERR_RULE_INVALID;
    return SSO_OK;
}

permission_strategy_t location_perm_strategy = {
    .type          = PERM_STRATEGY_LOCATION,
    .name          = "location",
    .init          = loc_init,
    .destroy       = loc_destroy,
    .evaluate      = loc_evaluate,
    .validate_rules = loc_validate,
    .userdata      = NULL,
};
