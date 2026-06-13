/*
 * lbac_perm.c — Lattice-Based Access Control (Labels/Clearance).
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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
                                 void *compiled_rule,
                                 bool *result) {
    (void)self; (void)compiled_rule;
    if (!ctx || !policy || !result) return SSO_ERR_INVALID_PARAM;

    const char *user_labels = ctx->params.lbac.user_labels;
    const char *resource_label = ctx->params.lbac.resource_label;

    if (!user_labels || !resource_label || user_labels[0] == '\0' || resource_label[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    /* Production optimization: use pre-compiled bitmasks for labels.
     * For now, we do a simple string containment. */
    if (strstr(user_labels, resource_label) != NULL) {
        *result = true;
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t lbac_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    return SSO_OK;
}

permission_strategy_t lbac_perm_strategy = {
    .type          = PERM_STRATEGY_LBAC,
    .name          = "lbac",
    .init          = lbac_init,
    .destroy       = lbac_destroy,
    .compile_rules = NULL,
    .free_compiled_rules = NULL,
    .evaluate      = lbac_evaluate,
    .validate_rules = lbac_validate,
    .userdata      = NULL,
};
