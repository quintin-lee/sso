/*
 * lbac_perm.c — Lattice-Based Access Control (Labels/Clearance).
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Pre-compiled LBAC rule structure
 * ----------------------------------------------------------------------- */
typedef struct {
    char **clearance_levels;
    size_t count;
} lbac_compiled_rule_t;

/* -----------------------------------------------------------------------
 * Strategy implementation
 * ----------------------------------------------------------------------- */

static sso_error_t lbac_init(permission_strategy_t *self, sso_context_t *ctx) {
    (void)self; (void)ctx;
    return SSO_OK;
}

static void lbac_destroy(permission_strategy_t *self) {
    (void)self;
}

static sso_error_t lbac_compile(permission_strategy_t *self,
                                const char *rules_json,
                                void **compiled_rule) {
    (void)self;
    if (!rules_json || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    /* A policy might define what clearances are authorized to bypass
     * or establish custom hierarchy logic.
     * For this basic implementation, we just store the parsed labels. */
    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    cJSON *levels = cJSON_GetObjectItem(root, "clearance_levels");
    if (!cJSON_IsArray(levels)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    size_t count = (size_t)cJSON_GetArraySize(levels);
    lbac_compiled_rule_t *compiled = (lbac_compiled_rule_t *)malloc(sizeof(lbac_compiled_rule_t));
    if (!compiled) {
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    compiled->count = count;
    compiled->clearance_levels = (char **)calloc(count, sizeof(char *));
    if (!compiled->clearance_levels) {
        free(compiled);
        cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(levels, (int)i);
        if (cJSON_IsString(item)) {
            compiled->clearance_levels[i] = strdup(item->valuestring);
        }
    }

    cJSON_Delete(root);
    *compiled_rule = compiled;
    return SSO_OK;
}

static void lbac_free_compiled(permission_strategy_t *self,
                               void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    lbac_compiled_rule_t *compiled = (lbac_compiled_rule_t *)compiled_rule;
    if (compiled->clearance_levels) {
        for (size_t i = 0; i < compiled->count; i++) {
            if (compiled->clearance_levels[i]) free(compiled->clearance_levels[i]);
        }
        free(compiled->clearance_levels);
    }
    free(compiled);
}

/* Helper to check if a label is in a comma-separated string */
static bool label_in_list(const char *label, const char *list) {
    if (!label || !list) return false;
    size_t label_len = strlen(label);
    const char *p = list;
    while ((p = strstr(p, label)) != NULL) {
        /* Check boundaries */
        bool start_ok = (p == list || *(p - 1) == ',');
        bool end_ok   = (*(p + label_len) == '\0' || *(p + label_len) == ',');
        if (start_ok && end_ok) return true;
        p += label_len;
    }
    return false;
}

static sso_error_t lbac_evaluate(permission_strategy_t *self,
                                 eval_context_t *ctx,
                                 const policy_t *policy,
                                 void *compiled_rule,
                                 bool *result) {
    (void)self; (void)policy;
    if (!ctx || !result || !compiled_rule) return SSO_ERR_INVALID_PARAM;

    const char *user_labels = ctx->params.lbac.user_labels;
    const char *resource_label = ctx->params.lbac.resource_label;

    if (!user_labels || !resource_label || user_labels[0] == '\0' || resource_label[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    lbac_compiled_rule_t *compiled = (lbac_compiled_rule_t *)compiled_rule;

    /* Check if the user's label list strictly contains the required resource label.
     * Note: In a full LBAC implementation (Bell-LaPadula), this would use
     * bitmasks/dominance checks configured by the compiled policy. */
    
    bool matches = false;
    for (size_t i = 0; i < compiled->count; i++) {
        if (compiled->clearance_levels[i] && strcmp(compiled->clearance_levels[i], resource_label) == 0) {
            matches = true;
            break;
        }
    }

    if (matches && label_in_list(resource_label, user_labels)) {
        *result = true;
        return SSO_OK;
    }

    return SSO_ERR_NOT_FOUND;
}

static sso_error_t lbac_validate(permission_strategy_t *self,
                                 const char *rules_json) {
    (void)self;
    if (!rules_json) return SSO_ERR_INVALID_PARAM;
    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;
    cJSON_Delete(root);
    return SSO_OK;
}

permission_strategy_t lbac_perm_strategy = {
    .type          = PERM_STRATEGY_LBAC,
    .name          = "lbac",
    .init          = lbac_init,
    .destroy       = lbac_destroy,
    .compile_rules = lbac_compile,
    .free_compiled_rules = lbac_free_compiled,
    .evaluate      = lbac_evaluate,
    .validate_rules = lbac_validate,
    .userdata      = NULL,
};
