#include "sso.h"
#include "server.h"
#include "handlers.h"
#include "logger.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "permission.h"
#include "token.h"
#include "storage.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Helper: read a line from stdin, strip trailing newline. */
static void prompt_line(const char *msg, char *buf, size_t size) {
    printf("%s", msg);
    fflush(stdout);
    if (fgets(buf, (int)size, stdin)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[--len] = '\0';
    }
}

static void print_banner(void) {
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║     SSO Permission Strategy Configurator      ║\n");
    printf("  ║     Configure all 7 strategy types            ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n\n");
}

static void print_menu(void) {
    printf("  ┌───── Strategy Configuration ─────────────────────┐\n");
    printf("  │  1. Functional    (feature/menu permissions)     │\n");
    printf("  │  2. API           (HTTP method + path control)   │\n");
    printf("  │  3. Data          (resource/field-level access)  │\n");
    printf("  │  4. RBAC          (role membership check)        │\n");
    printf("  │  5. Location      (IP/location-based control)    │\n");
    printf("  │  6. ABAC          (attribute-based conditions)   │\n");
    printf("  │  7. LBAC          (label-based control)          │\n");
    printf("  ├───── Actions ────────────────────────────────────┤\n");
    printf("  │  8. Assign a policy to a role                    │\n");
    printf("  │  9. Test a permission check                      │\n");
    printf("  │  10. List all policies                           │\n");
    printf("  ├───── User Management ────────────────────────────┤\n");
    printf("  │  11. Create user                                 │\n");
    printf("  │  12. List all users                              │\n");
    printf("  │  13. Delete user                                 │\n");
    printf("  ├───── Role Management ────────────────────────────┤\n");
    printf("  │  14. Create role                                 │\n");
    printf("  │  15. List all roles                              │\n");
    printf("  │  16. Delete role                                 │\n");
    printf("  │  17. Assign role to user                         │\n");
    printf("  │  18. Unassign role from user                     │\n");
    printf("  ├───── Group Management ───────────────────────────┤\n");
    printf("  │  19. Create group                                │\n");
    printf("  │  20. List all groups                             │\n");
    printf("  │  21. Add user to group                           │\n");
    printf("  │  22. Remove user from group                      │\n");
    printf("  │  0. Exit                                         │\n");
    printf("  └──────────────────────────────────────────────────┘\n");
    printf("  Choice: ");
    fflush(stdout);
}

/* ------------------------------------------------------------------
 * Sub-menus for each strategy type
 * ------------------------------------------------------------------ */

static void config_functional(policy_manager_t *pmgr) {
    printf("\n  ─── Functional Permission ───\n");
    printf("  Controls feature/menu/button-level access.\n");
    printf("  Examples: \"user:create\", \"report:*\", \"admin:settings\"\n\n");

    char name[64], code[128], effect[8];
    prompt_line("  Policy name [Functional Rules]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "Functional Rules");
    prompt_line("  Function code (e.g. report:view): ", code, sizeof(code));
    if (code[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"functions\":[{\"code\":\"%s\",\"effect\":\"%s\"}]}", code, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_FUNCTIONAL, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_api(policy_manager_t *pmgr) {
    printf("\n  ─── API Endpoint Permission ───\n");
    printf("  Controls HTTP method + path access.\n");
    printf("  Supports wildcards: * matches any method/path segment.\n\n");

    char name[64], method[8], path[SSO_MAX_PATH], effect[8];
    prompt_line("  Policy name [API Rules]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "API Rules");
    prompt_line("  HTTP method (GET/POST/PUT/DELETE/*): ", method, sizeof(method));
    if (method[0] == '\0') strcpy(method, "GET");
    prompt_line("  Path (e.g. /api/v1/users/*): ", path, sizeof(path));
    if (path[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"endpoints\":[{\"method\":\"%s\",\"path\":\"%s\",\"effect\":\"%s\"}]}",
        method, path, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_API, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_data(policy_manager_t *pmgr) {
    printf("\n  ─── Data Scope Permission ───\n");
    printf("  Controls resource/field-level access with conditions.\n\n");

    char name[64], resource[64], scope[32], fields[256], effect[8];
    prompt_line("  Policy name [Data Rules]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "Data Rules");
    prompt_line("  Resource type (e.g. order, customer, report): ", resource, sizeof(resource));
    if (resource[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Scope (self/organization/all) [all]: ", scope, sizeof(scope));
    if (scope[0] == '\0') strcpy(scope, "all");
    prompt_line("  Allowed fields (comma-separated, e.g. id,name,email): ", fields, sizeof(fields));
    if (fields[0] == '\0') strcpy(fields, "id");
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    /* Build JSON fields array from comma-separated input */
    char field_list[512];
    size_t flen = 0;
    field_list[0] = '\0';
    char fields_copy[256];
    sso_strlcpy(fields_copy, fields, sizeof(fields_copy));
    fields_copy[sizeof(fields_copy) - 1] = '\0';
    char *tok = strtok(fields_copy, ",");
    while (tok) {
        while (*tok == ' ') { memmove(tok, tok+1, strlen(tok)); }
        char *endp = tok + strlen(tok) - 1;
        while (endp > tok && *endp == ' ') *endp-- = '\0';
        if (flen > 0) { strncat(field_list, ",", sizeof(field_list) - flen - 1); flen++; }
        char entry[64];
        int n = snprintf(entry, sizeof(entry), "\"%s\"", tok);
        strncat(field_list, entry, sizeof(field_list) - flen - 1);
        flen += (size_t)n;
        tok = strtok(NULL, ",");
    }

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"rules\":[{\"resource\":\"%s\",\"scope\":\"%s\",\"fields\":[%s]}],\"effect\":\"%s\"}",
        resource, scope, field_list, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_DATA, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_rbac(policy_manager_t *pmgr) {
    printf("\n  ─── RBAC Permission (Role-Based) ───\n");
    printf("  Grants access based on role membership.\n");
    printf("  The user must hold the specified role.\n\n");

    char name[64], role_name[64], effect[8];
    prompt_line("  Policy name [RBAC Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "RBAC Rule");
    prompt_line("  Role name to check (e.g. admin, editor): ", role_name, sizeof(role_name));
    if (role_name[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"roles\":[{\"name\":\"%s\",\"effect\":\"%s\"}]}", role_name, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_RBAC, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_location(policy_manager_t *pmgr) {
    printf("\n  ─── Location Permission (IP-Based) ───\n");
    printf("  Controls access based on source IP address.\n");
    printf("  Uses CIDR notation: 10.0.0.0/8, 192.168.0.0/16, etc.\n\n");

    char name[64], cidr[128], effect[8];
    prompt_line("  Policy name [Location Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "Location Rule");
    prompt_line("  CIDR range (e.g. 10.0.0.0/8): ", cidr, sizeof(cidr));
    if (cidr[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"locations\":[{\"type\":\"ip_cidr\",\"value\":\"%s\",\"effect\":\"%s\"}]}",
        cidr, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_LOCATION, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_lbac(policy_manager_t *pmgr) {
    printf("\n  ─── LBAC Permission (Label-Based) ───\n");
    printf("  Controls access based on security labels (MLS).\n");
    printf("  Examples: \"INTERNAL\", \"CONFIDENTIAL\", \"TOP_SECRET\"\n\n");

    char name[64], label[64], effect[8];
    prompt_line("  Policy name [LBAC Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "LBAC Rule");
    prompt_line("  Required label (e.g. CONFIDENTIAL): ", label, sizeof(label));
    if (label[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"labels\":[{\"name\":\"%s\",\"effect\":\"%s\"}]}", label, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_LBAC, POLICY_EFFECT_ALLOW, 55, rules, &p);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

static void config_abac(policy_manager_t *pmgr) {
    printf("\n  ─── ABAC Permission (Attribute-Based) ───\n");
    printf("  Evaluates conditions against subject/resource/environment attributes.\n");
    printf("  Operators: eq, neq, gt, gte, lt, lte, contains, in\n\n");

    char name[64], source[16], attr[64], op[16], value[128], logic[8], effect[8];
    prompt_line("  Policy name [ABAC Rule]: ", name, sizeof(name));
    if (name[0] == '\0') strcpy(name, "ABAC Rule");
    prompt_line("  Attribute source (subject/resource/environment) [subject]: ", source, sizeof(source));
    if (source[0] == '\0') strcpy(source, "subject");
    prompt_line("  Attribute name (e.g. department, clearance): ", attr, sizeof(attr));
    if (attr[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Operator (eq/neq/gt/gte/lt/lte/contains/in) [eq]: ", op, sizeof(op));
    if (op[0] == '\0') strcpy(op, "eq");
    prompt_line("  Value to compare (e.g. engineering, 3): ", value, sizeof(value));
    if (value[0] == '\0') { printf("  Skipped.\n"); return; }
    prompt_line("  Logic (and/or) [and]: ", logic, sizeof(logic));
    if (logic[0] == '\0') strcpy(logic, "and");
    prompt_line("  Effect (allow/deny) [allow]: ", effect, sizeof(effect));
    if (effect[0] == '\0') strcpy(effect, "allow");

    char rules[SSO_MAX_RULES_JSON];
    snprintf(rules, sizeof(rules),
        "{\"conditions\":[{\"source\":\"%s\",\"attr\":\"%s\",\"op\":\"%s\",\"value\":\"%s\"}],\"logic\":\"%s\",\"effect\":\"%s\"}",
        source, attr, op, value, logic, effect);

    policy_t p;
    sso_error_t err = policy_create(pmgr, name,
        PERM_STRATEGY_ABAC, POLICY_EFFECT_ALLOW, 50, rules, &p);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Policy created" : sso_strerror(err),
        (unsigned long)p.id);
}

/* ------------------------------------------------------------------
 * Action: assign policy to a role
 * ------------------------------------------------------------------ */
static void action_assign(policy_manager_t *pmgr, role_manager_t *rmgr) {
    printf("\n  ─── Assign Policy to Role ───\n");
    char pid_str[16], rid_str[16];
    prompt_line("  Policy ID: ", pid_str, sizeof(pid_str));
    if (pid_str[0] == '\0') return;
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;

    sso_id_t policy_id = (sso_id_t)atoll(pid_str);
    sso_id_t role_id = (sso_id_t)atoll(rid_str);

    /* Verify role exists */
    role_t r;
    if (role_get_by_id(rmgr, role_id, &r) != SSO_OK) {
        printf("  Role %lu not found.\n", (unsigned long)role_id);
        return;
    }

    sso_error_t err = policy_assign_to(pmgr, policy_id, POLICY_TARGET_ROLE, role_id);
    printf("  → %s\n",
        err == SSO_OK ? "Assigned" : sso_strerror(err));
    if (err == SSO_OK) {
        printf("  Policy %lu → Role \"%s\"\n", (unsigned long)policy_id, r.name);
    }
}

/* ------------------------------------------------------------------
 * Action: test a permission check
 * ------------------------------------------------------------------ */
static void action_check(sso_context_t *ctx) {
    printf("\n  ─── Test Permission Check ───\n");
    printf("  Strategy types: 1=Functional  2=API  3=Data\n");
    printf("                  4=RBAC        5=Location  6=ABAC  7=LBAC\n");
    char type_str[4], uid_str[16];
    prompt_line("  Strategy type (1-7): ", type_str, sizeof(type_str));
    if (type_str[0] == '\0') return;
    int st = atoi(type_str);
    prompt_line("  User ID [1]: ", uid_str, sizeof(uid_str));
    sso_id_t uid = uid_str[0] ? (sso_id_t)atoll(uid_str) : 1;

    bool allowed = false;
    sso_error_t err = SSO_ERR_GENERAL;

    switch (st) {
    case 1: { /* Functional */
        char code[128];
        prompt_line("  Function code (e.g. report:view): ", code, sizeof(code));
        if (code[0]) err = perm_check_function(ctx, uid, code, &allowed);
        printf("  check_function(\"%s\") → %s\n", code, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 2: { /* API */
        char method[8], path[SSO_MAX_PATH];
        prompt_line("  HTTP method: ", method, sizeof(method));
        prompt_line("  Path: ", path, sizeof(path));
        if (method[0] && path[0]) err = perm_check_api(ctx, uid, method, path, &allowed);
        printf("  check_api(\"%s %s\") → %s\n", method, path, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 3: { /* Data */
        char rtype[64], record[512];
        prompt_line("  Resource type: ", rtype, sizeof(rtype));
        prompt_line("  Record JSON (or empty): ", record, sizeof(record));
        if (rtype[0]) {
            char **fields = NULL;
            size_t fcount = 0;
            err = perm_check_data(ctx, uid, rtype,
                record[0] ? record : NULL, &allowed, &fields, &fcount);
            printf("  check_data(\"%s\") → %s", rtype, allowed ? "ALLOW" : "DENY");
            if (fields) {
                printf("  fields=[");
                for (size_t i = 0; i < fcount; i++) {
                    printf("%s%s", fields[i], i < fcount-1 ? "," : "");
                    free(fields[i]);
                }
                printf("]");
                free(fields);
            }
            printf("\n");
        }
        break;
    }
    case 4: { /* RBAC */
        char rname[64];
        prompt_line("  Role name: ", rname, sizeof(rname));
        if (rname[0]) err = perm_check_rbac(ctx, uid, rname, &allowed);
        printf("  check_rbac(\"%s\") → %s\n", rname, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 5: { /* Location */
        char ip[64];
        prompt_line("  Source IP address: ", ip, sizeof(ip));
        if (ip[0]) err = perm_check_location(ctx, uid, ip, NULL, &allowed);
        printf("  check_location(\"%s\") → %s\n", ip, allowed ? "ALLOW" : "DENY");
        break;
    }
    case 6: { /* ABAC */
        char attrs[SSO_MAX_ATTRIBUTES];
        prompt_line("  Subject attrs JSON (e.g. {\"department\":\"engineering\"}): ", attrs, sizeof(attrs));
        if (attrs[0]) err = perm_check_abac(ctx, uid, attrs, NULL, NULL, &allowed);
        printf("  check_abac() → %s\n", allowed ? "ALLOW" : "DENY");
        break;
    }
    case 7: { /* LBAC (Label-Based) */
        char u_labels[256], r_label[64];
        prompt_line("  User labels (comma-separated): ", u_labels, sizeof(u_labels));
        prompt_line("  Resource label: ", r_label, sizeof(r_label));
        if (u_labels[0] && r_label[0]) err = perm_check_lbac(ctx, uid, u_labels, r_label, &allowed);
        printf("  check_lbac(\"%s\", \"%s\") → %s\n", u_labels, r_label, allowed ? "ALLOW" : "DENY");
        break;
    }
    default:
        printf("  Invalid type.\n");
        return;
    }
    if (err != SSO_OK) {
        printf("  (engine: %s)\n", sso_strerror(err));
    }
}

/* ------------------------------------------------------------------
 * Action: list all policies
 * ------------------------------------------------------------------ */
static void action_list(policy_manager_t *pmgr) {
    printf("\n  ─── All Policies ───\n");
    for (sso_id_t i = 1; i <= 64; i++) {
        policy_t p;
        if (policy_get_by_id(pmgr, i, &p) == SSO_OK) {
            printf("  [%2lu] %-30s type=%-2d pri=%-3d status=%s  rules=%.40s\n",
                (unsigned long)p.id, p.name, p.strategy_type, p.priority,
                p.status == POLICY_STATUS_ENABLED ? "enabled" : "disabled",
                p.rules);
        }
    }
}

/* ------------------------------------------------------------------
 * Entity management actions
 * ------------------------------------------------------------------ */

static void action_create_user(user_manager_t *umgr) {
    printf("\n  ─── Create User ───\n");
    char username[SSO_MAX_USERNAME];
    char password[SSO_MAX_USERNAME];
    char email[SSO_MAX_EMAIL];
    char display_name[SSO_MAX_DISPLAY_NAME];

    prompt_line("  Username: ", username, sizeof(username));
    if (username[0] == '\0') return;
    prompt_line("  Password: ", password, sizeof(password));
    if (password[0] == '\0') return;
    prompt_line("  Email (optional): ", email, sizeof(email));
    prompt_line("  Display name (optional): ", display_name, sizeof(display_name));

    user_t u;
    sso_error_t err = user_create(umgr, username, password, email, display_name, &u);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Created" : sso_strerror(err),
        (unsigned long)u.id);
}

static void action_list_users(sso_context_t *ctx) {
    printf("\n  ─── All Users ───\n");
    user_manager_t  *umgr = (user_manager_t  *)ctx->user_mgr;
    role_manager_t  *rmgr = (role_manager_t  *)ctx->role_mgr;
    group_manager_t *gmgr = (group_manager_t *)ctx->group_mgr;

    sso_id_t ids[256];
    size_t count = 0;
    size_t total = 0;
    if (user_list(umgr, NULL, -1, 0, 256, ids, &count, &total) != SSO_OK) {
        printf("  Failed to list users.\n");
        return;
    }

    for (size_t i = 0; i < count; i++) {
        user_t u;
        if (user_get_by_id(umgr, ids[i], &u) != SSO_OK) continue;

        sso_id_t role_ids[16], group_ids[16];
        size_t rc = 0, gc = 0;
        user_get_roles(umgr, u.id, role_ids, &rc, 16);
        user_get_groups(umgr, u.id, group_ids, &gc, 16);

        printf("  [%2lu] %-12s  status=%-6s  email=%-20s",
            (unsigned long)u.id, u.username,
            u.status == USER_STATUS_ACTIVE ? "active" :
            u.status == USER_STATUS_LOCKED ? "locked" : "inactive",
            u.email);

        if (rc > 0) {
            printf("  roles=[");
            for (size_t j = 0; j < rc; j++) {
                role_t r;
                if (role_get_by_id(rmgr, role_ids[j], &r) == SSO_OK)
                    printf("%s%s", r.name, j < rc - 1 ? "," : "");
            }
            printf("]");
        }

        if (gc > 0) {
            printf("  groups=[");
            for (size_t j = 0; j < gc; j++) {
                group_t g;
                if (group_get_by_id(gmgr, group_ids[j], &g) == SSO_OK)
                    printf("%s%s", g.name, j < gc - 1 ? "," : "");
            }
            printf("]");
        }
        printf("\n");
    }
    printf("  Total: %zu user(s)\n", count);
}

static void action_delete_user(user_manager_t *umgr) {
    printf("\n  ─── Delete User ───\n");
    char uid_str[16];
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;
    sso_id_t uid = (sso_id_t)atoll(uid_str);

    user_t u;
    if (user_get_by_id(umgr, uid, &u) != SSO_OK) {
        printf("  User %lu not found.\n", (unsigned long)uid);
        return;
    }
    sso_error_t err = user_delete(umgr, uid);
    printf("  → %s\n", err == SSO_OK ? "Deleted" : sso_strerror(err));
}

static void action_create_role(role_manager_t *rmgr) {
    printf("\n  ─── Create Role ───\n");
    char name[SSO_MAX_ROLE_NAME], desc[SSO_MAX_DESCRIPTION], pid_str[16];
    prompt_line("  Role name: ", name, sizeof(name));
    if (name[0] == '\0') return;
    prompt_line("  Description (optional): ", desc, sizeof(desc));
    prompt_line("  Parent role ID (0=none): ", pid_str, sizeof(pid_str));
    sso_id_t parent_id = pid_str[0] ? (sso_id_t)atoll(pid_str) : SSO_ID_NONE;

    role_t r;
    sso_error_t err = role_create(rmgr, name, desc, parent_id, &r);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Created" : sso_strerror(err),
        (unsigned long)r.id);
}

static void action_list_roles(role_manager_t *rmgr) {
    printf("\n  ─── All Roles ───\n");
    sso_id_t ids[256];
    size_t count = 0;
    size_t total = 0;
    if (role_list(rmgr, NULL, -1, 0, 256, ids, &count, &total) != SSO_OK) {
        printf("  Failed to list roles.\n");
        return;
    }

    for (size_t i = 0; i < count; i++) {
        role_t r;
        if (role_get_by_id(rmgr, ids[i], &r) != SSO_OK) continue;
        printf("  [%2lu] %-16s  parent=%-3lu  desc=%s\n",
            (unsigned long)r.id, r.name,
            (unsigned long)r.parent_role_id,
            r.description);
    }
    printf("  Total: %zu role(s)\n", count);
}

static void action_delete_role(role_manager_t *rmgr) {
    printf("\n  ─── Delete Role ───\n");
    char rid_str[16];
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;
    sso_id_t rid = (sso_id_t)atoll(rid_str);

    role_t r;
    if (role_get_by_id(rmgr, rid, &r) != SSO_OK) {
        printf("  Role %lu not found.\n", (unsigned long)rid);
        return;
    }
    sso_error_t err = role_delete(rmgr, rid);
    printf("  → %s\n", err == SSO_OK ? "Deleted" : sso_strerror(err));
}

static void action_assign_role_to_user(role_manager_t *rmgr) {
    printf("\n  ─── Assign Role to User ───\n");
    char rid_str[16], uid_str[16];
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t rid = (sso_id_t)atoll(rid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = role_assign_to_user(rmgr, rid, uid);
    printf("  → %s\n", err == SSO_OK ? "Assigned" : sso_strerror(err));
}

static void action_unassign_role_from_user(role_manager_t *rmgr) {
    printf("\n  ─── Unassign Role from User ───\n");
    char rid_str[16], uid_str[16];
    prompt_line("  Role ID: ", rid_str, sizeof(rid_str));
    if (rid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t rid = (sso_id_t)atoll(rid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = role_unassign_from_user(rmgr, rid, uid);
    printf("  → %s\n", err == SSO_OK ? "Unassigned" : sso_strerror(err));
}

static void action_create_group(group_manager_t *gmgr) {
    printf("\n  ─── Create Group ───\n");
    char name[SSO_MAX_GROUP_NAME], desc[SSO_MAX_DESCRIPTION], pid_str[16];
    prompt_line("  Group name: ", name, sizeof(name));
    if (name[0] == '\0') return;
    prompt_line("  Description (optional): ", desc, sizeof(desc));
    prompt_line("  Parent group ID (0=none): ", pid_str, sizeof(pid_str));
    sso_id_t parent_id = pid_str[0] ? (sso_id_t)atoll(pid_str) : SSO_ID_NONE;

    group_t g;
    sso_error_t err = group_create(gmgr, name, desc, parent_id, &g);
    printf("  → %s (id=%lu)\n",
        err == SSO_OK ? "Created" : sso_strerror(err),
        (unsigned long)g.id);
}

static void action_list_groups(group_manager_t *gmgr) {
    printf("\n  ─── All Groups ───\n");
    sso_id_t ids[256];
    size_t count = 0;
    size_t total = 0;
    if (group_list(gmgr, NULL, -1, 0, 256, ids, &count, &total) != SSO_OK) {
        printf("  Failed to list groups.\n");
        return;
    }

    for (size_t i = 0; i < count; i++) {
        group_t g;
        if (group_get_by_id(gmgr, ids[i], &g) != SSO_OK) continue;
        printf("  [%2lu] %-16s  parent=%-3lu  desc=%s\n",
            (unsigned long)g.id, g.name,
            (unsigned long)g.parent_group_id,
            g.description);
    }
    printf("  Total: %zu group(s)\n", count);
}

static void action_add_user_to_group(group_manager_t *gmgr) {
    printf("\n  ─── Add User to Group ───\n");
    char gid_str[16], uid_str[16];
    prompt_line("  Group ID: ", gid_str, sizeof(gid_str));
    if (gid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t gid = (sso_id_t)atoll(gid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = group_add_user(gmgr, gid, uid);
    printf("  → %s\n", err == SSO_OK ? "Added" : sso_strerror(err));
}

static void action_remove_user_from_group(group_manager_t *gmgr) {
    printf("\n  ─── Remove User from Group ───\n");
    char gid_str[16], uid_str[16];
    prompt_line("  Group ID: ", gid_str, sizeof(gid_str));
    if (gid_str[0] == '\0') return;
    prompt_line("  User ID: ", uid_str, sizeof(uid_str));
    if (uid_str[0] == '\0') return;

    sso_id_t gid = (sso_id_t)atoll(gid_str);
    sso_id_t uid = (sso_id_t)atoll(uid_str);
    sso_error_t err = group_remove_user(gmgr, gid, uid);
    printf("  → %s\n", err == SSO_OK ? "Removed" : sso_strerror(err));
}

/* ========================================================================
 * Interactive configuration shell entry point
 * ======================================================================== */
int interactive_config(sso_config_t *cfg) {
    sso_error_t err;

    printf("=== SSO Interactive Configuration ===\n\n");

    /* Initialize */
    storage_backend_t *storage = NULL;
    err = storage_sqlite_create(&storage);
    if (err != SSO_OK) {
        LOG_ERROR("Failed to create storage: %s", sso_strerror(err));
        return 1;
    }

    sso_context_t ctx;
    err = sso_init(&ctx, storage, cfg);
    if (err != SSO_OK) {
        LOG_ERROR("Failed to init SSO: %s", sso_strerror(err));
        return 1;
    }
    printf("System initialized (db: sso_config.db)\n");

    /* Bootstrap default users, roles, groups if first run */
    {
        user_manager_t  *umgr = (user_manager_t  *)ctx.user_mgr;
        role_manager_t  *rmgr = (role_manager_t  *)ctx.role_mgr;
        group_manager_t *gmgr = (group_manager_t *)ctx.group_mgr;

        /* Check if admin exists already */
        user_t admin;
        err = user_get_by_username(umgr, "admin", &admin);
        if (err != SSO_OK) {
            printf("Bootstrapping default data...\n");

            user_t admin_user, alice_user, bob_user;
            user_create(umgr, "admin", "admin123", "admin@example.com", "Admin", &admin_user);
            user_create(umgr, "alice", "alice456", "alice@example.com", "Alice", &alice_user);
            user_create(umgr, "bob",   "bob789",   "bob@example.com",   "Bob",   &bob_user);

            role_t admin_role, editor_role, viewer_role;
            role_create(rmgr, "admin",  "Full system access",   SSO_ID_NONE, &admin_role);
            role_create(rmgr, "editor", "Can edit content",     admin_role.id, &editor_role);
            role_create(rmgr, "viewer", "Read-only access",     editor_role.id, &viewer_role);

            group_t engineering, finance;
            group_create(gmgr, "engineering", "Engineering", SSO_ID_NONE, &engineering);
            group_create(gmgr, "finance",     "Finance",     SSO_ID_NONE, &finance);

            role_assign_to_user(rmgr, admin_role.id, admin_user.id);
            role_assign_to_user(rmgr, editor_role.id, alice_user.id);
            role_assign_to_user(rmgr, viewer_role.id, bob_user.id);
            group_add_user(gmgr, engineering.id, alice_user.id);
            group_add_user(gmgr, finance.id, bob_user.id);

            printf("  Users:  admin(1), alice(2), bob(3)\n");
            printf("  Roles:  admin(1), editor(2), viewer(3)\n");
            printf("  Groups: engineering(1), finance(2)\n");
        } else {
            printf("Existing database found with admin user.\n");
        }
    }

    print_banner();

    user_manager_t  *umgr = (user_manager_t  *)ctx.user_mgr;
    role_manager_t  *rmgr = (role_manager_t  *)ctx.role_mgr;
    group_manager_t *gmgr = (group_manager_t *)ctx.group_mgr;
    policy_manager_t *pmgr = (policy_manager_t *)ctx.policy_mgr;

    char choice[16];
    int running = 1;
    while (running) {
        print_menu();
        if (!fgets(choice, sizeof(choice), stdin)) break;
        int opt = atoi(choice);

        switch (opt) {
        case 1:  config_functional(pmgr); break;
        case 2:  config_api(pmgr); break;
        case 3:  config_data(pmgr); break;
        case 4:  config_rbac(pmgr); break;
        case 5:  config_location(pmgr); break;
        case 6:  config_abac(pmgr); break;
        case 7:  config_lbac(pmgr); break;
        case 8:  action_assign(pmgr, rmgr); break;
        case 9:  action_check(&ctx); break;
        case 10: action_list(pmgr); break;
        case 11: action_create_user(umgr); break;
        case 12: action_list_users(&ctx); break;
        case 13: action_delete_user(umgr); break;
        case 14: action_create_role(rmgr); break;
        case 15: action_list_roles(rmgr); break;
        case 16: action_delete_role(rmgr); break;
        case 17: action_assign_role_to_user(rmgr); break;
        case 18: action_unassign_role_from_user(rmgr); break;
        case 19: action_create_group(gmgr); break;
        case 20: action_list_groups(gmgr); break;
        case 21: action_add_user_to_group(gmgr); break;
        case 22: action_remove_user_from_group(gmgr); break;
        case 0:  running = 0; break;
        default: printf("  Invalid option.\n"); break;
        }
        printf("\n");
    }

    printf("Exiting. Database saved to sso_config.db\n");
    printf("Reuse with --interactive (existing config) or delete sso_config.db for fresh start.\n");
    sso_destroy(&ctx);
    return 0;
}
