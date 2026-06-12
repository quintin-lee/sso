/*
 * lbac_perm.c — Label-Based Access Control (LBAC) permission strategy.
 *
 * Evaluates access based on security labels assigned to users and resources.
 * This is often used for Multi-Level Security (MLS).
 *
 * Rule format (JSON):
 *   {
 *     "labels": [
 *       {"name": "TOP_SECRET", "effect": "allow"},
 *       {"name": "SECRET",     "effect": "allow"},
 *       {"name": "INTERNAL",   "effect": "allow"},
 *       {"name": "GUEST",      "effect": "deny"}
 *     ]
 *   }
 *
 * Evaluation:
 *   1. Iterates through the rules in the policy.
 *   2. If a rule's label name exists in the user's label set (comma-separated),
 *      the rule's effect is returned.
 */

#include "sso.h"
#include "policy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static bool label_exists(const char *user_labels, const char *target_label) {
    if (!user_labels || !target_label) return false;

    char labels_copy[256];
    strncpy(labels_copy, user_labels, sizeof(labels_copy) - 1);
    labels_copy[sizeof(labels_copy) - 1] = '\0';

    char *token = strtok(labels_copy, ",");
    while (token) {
        /* Trim whitespace */
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') { *end = '\0'; end--; }

        if (strcmp(token, target_label) == 0) return true;
        token = strtok(NULL, ",");
    }
    return false;
}

static sso_error_t lbac_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void lbac_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t lbac_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 bool *result) {
    (void)self;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *user_labels = ctx->params.lbac.user_labels;
    if (!user_labels || user_labels[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    const char *p = policy->rules;
    const char *name_key = "\"name\"";
    const char *name_pos;

    while ((name_pos = strstr(p, name_key)) != NULL) {
        const char *nv = name_pos + strlen(name_key);
        while (*nv && *nv != ':') nv++;
        if (*nv == ':') nv++;
        while (*nv && (*nv == ' ' || *nv == '\t' || *nv == '\n')) nv++;
        if (*nv == '"') nv++;

        const char *nv_end = nv;
        while (*nv_end && *nv_end != '"') nv_end++;
        size_t name_len = (size_t)(nv_end - nv);

        char label_name[64];
        size_t copy_len = name_len < sizeof(label_name) - 1 ? name_len : sizeof(label_name) - 1;
        strncpy(label_name, nv, copy_len);
        label_name[copy_len] = '\0';

        /* Extract effect */
        const char *eff = strstr(name_pos, "\"effect\"");
        bool is_allow = true;
        if (eff) {
            const char *eff_val = eff + strlen("\"effect\"");
            while (*eff_val && (*eff_val == ' ' || *eff_val == '\t' || *eff_val == '\n'
                   || *eff_val == ':')) eff_val++;
            if (*eff_val == '"') eff_val++;
            is_allow = (strncmp(eff_val, "allow", 5) == 0);
        }

        if (label_exists(user_labels, label_name)) {
            *result = is_allow;
            return SSO_OK;
        }

        p = nv_end + 1;
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t lbac_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    if (strstr(rules_json, "\"labels\"") == NULL) return SSO_ERR_RULE_INVALID;
    return SSO_OK;
}

permission_strategy_t lbac_perm_strategy = {
    .type          = PERM_STRATEGY_LBAC,
    .name          = "lbac",
    .init          = lbac_init,
    .destroy       = lbac_destroy,
    .evaluate      = lbac_evaluate,
    .validate_rules = lbac_validate,
    .userdata      = NULL,
};
