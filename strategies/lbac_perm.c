/*
 * lbac_perm.c - Lattice-Based Access Control (Labels/Clearance).
 *
 * Supports the following JSON rule format:
 *   {
 *     "labels": [
 *       {"name": "CONFIDENTIAL", "effect": "allow"},
 *       {"name": "TOP_SECRET",   "effect": "allow"}
 *     ]
 *   }
 *
 * Evaluation: if a user's label set contains the resource label
 * AND the label is listed in the policy (with allow effect),
 * access is granted.
 */

#include "sso.h"
#include "policy.h"
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ----------------------------------------------------------------------- */
/* Types */
/* ----------------------------------------------------------------------- */
typedef struct {
    char label_name[64];
    bool is_allow;
} lbac_rule_item_t;

typedef struct {
    lbac_rule_item_t *items;
    size_t            count;
} lbac_compiled_rule_t;

/* ----------------------------------------------------------------------- */
/* Strategy implementation */
/* ----------------------------------------------------------------------- */

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

    cJSON *root = cJSON_Parse(rules_json);
    if (!root) return SSO_ERR_RULE_INVALID;

    /* Support both "labels" (new) and "clearance_levels" (old) format */
    cJSON *levels = cJSON_GetObjectItem(root, "labels");
    if (!cJSON_IsArray(levels)) {
        levels = cJSON_GetObjectItem(root, "clearance_levels");
    }
    if (!cJSON_IsArray(levels)) {
        cJSON_Delete(root);
        return SSO_ERR_RULE_INVALID;
    }

    size_t count = (size_t)cJSON_GetArraySize(levels);
    lbac_compiled_rule_t *compiled =
        (lbac_compiled_rule_t *)malloc(sizeof(lbac_compiled_rule_t));
    if (!compiled) { cJSON_Delete(root); return SSO_ERR_OUT_OF_MEMORY; }

    compiled->count = count;
    compiled->items = (lbac_rule_item_t *)
        calloc(count, sizeof(lbac_rule_item_t));
    if (!compiled->items) {
        free(compiled); cJSON_Delete(root);
        return SSO_ERR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(levels, (int)i);

        if (cJSON_IsString(item)) {
            /* Simple string: {array of strings} */
            strncpy(compiled->items[i].label_name,
                    item->valuestring, 63);
            compiled->items[i].is_allow = true;
        } else if (cJSON_IsObject(item)) {
            /* Object: {name: "...", effect: "..."} */
            cJSON *name = cJSON_GetObjectItem(item, "name");
            cJSON *effect = cJSON_GetObjectItem(item, "effect");

            if (name && cJSON_IsString(name)) {
                strncpy(compiled->items[i].label_name,
                        name->valuestring, 63);
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


static void lbac_free_compiled(permission_strategy_t *self,
                                void *compiled_rule) {
    (void)self;
    if (!compiled_rule) return;
    lbac_compiled_rule_t *c = (lbac_compiled_rule_t *)compiled_rule;
    free(c->items);
    free(c);
}

/* Helper: check if a label is in a comma-separated string */
static bool label_in_list(const char *label, const char *list) {
    if (!label || !list) return false;
    size_t len = strlen(label);
    const char *p = list;
    while ((p = strstr(p, label)) != NULL) {
        bool start_ok = (p == list || *(p - 1) == ',');
        bool end_ok = (*(p + len) == '\0' || *(p + len) == ',');
        if (start_ok && end_ok) return true;
        p += len;
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

    if (!user_labels || !resource_label ||
        user_labels[0] == '\0' || resource_label[0] == '\0') {
        return SSO_ERR_NOT_FOUND;
    }

    lbac_compiled_rule_t *compiled =
        (lbac_compiled_rule_t *)compiled_rule;

    for (size_t i = 0; i < compiled->count; i++) {
        /* Check if the resource label matches this policy item */
        if (strcmp(compiled->items[i].label_name,
                   resource_label) != 0) {
            continue;
        }

        /* Check if the user actually has this label */
        if (!label_in_list(resource_label, user_labels)) {
            return SSO_ERR_NOT_FOUND;
        }

        *result = compiled->items[i].is_allow;
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
