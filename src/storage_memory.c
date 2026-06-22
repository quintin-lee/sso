/*
 * storage_memory.c - In-memory storage backend.
 * All data is volatile - lost on destroy. Useful for testing.
 */

#include "sso.h"
#include "storage.h"
#include "user.h"
#include "role.h"
#include "group.h"
#include "policy.h"
#include "token.h"  /* for base64url_encode */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define INITIAL_CAP 64

typedef struct { void *items; size_t count, cap, esz; } da_t;
static void da_init(da_t *d, size_t sz) { memset(d,0,sizeof(*d)); d->esz=sz; }
static void da_free(da_t *d) { free(d->items); memset(d,0,sizeof(*d)); }
static sso_error_t da_add(da_t *d, const void *it) {
    if (d->count>=d->cap) {
        size_t nc = d->cap?d->cap*2:INITIAL_CAP;
        void *n = realloc(d->items, nc*d->esz);
        if (!n) return SSO_ERR_OUT_OF_MEMORY;
        d->items=n; d->cap=nc;
    }
    memcpy((char*)d->items + d->count*d->esz, it, d->esz);
    d->count++; return SSO_OK;
}
static ssize_t da_find_id(const da_t *d, size_t off, sso_id_t id) {
    for (size_t i=0;i<d->count;i++)
        if (*(const sso_id_t*)((const char*)d->items + i*d->esz + off)==id) return (ssize_t)i;
    return -1;
}
static ssize_t da_find_str(const da_t *d, size_t off, const char *s) {
    for (size_t i=0;i<d->count;i++)
        if (strcmp((const char*)d->items + i*d->esz + off, s)==0) return (ssize_t)i;
    return -1;
}
static void da_rm(da_t *d, size_t i) {
    if (i<d->count-1) memmove((char*)d->items+i*d->esz, (char*)d->items+(i+1)*d->esz, (d->count-i-1)*d->esz);
    d->count--;
}

typedef struct { sso_id_t a,b; } pair_t;
typedef struct { pair_t *p; size_t n,cap; } pl_t;
static void pl_init(pl_t *l) { memset(l,0,sizeof(*l)); }
static void pl_free(pl_t *l) { free(l->p); memset(l,0,sizeof(*l)); }
static sso_error_t pl_add(pl_t *l, sso_id_t a, sso_id_t b) {
    if (l->n>=l->cap) {
        size_t nc=l->cap?l->cap*2:INITIAL_CAP;
        pair_t *n=realloc(l->p,nc*sizeof(pair_t));
        if (!n) return SSO_ERR_OUT_OF_MEMORY;
        l->p=n; l->cap=nc;
    }
    l->p[l->n].a=a; l->p[l->n].b=b; l->n++; return SSO_OK;
}
static bool pl_rm(pl_t *l, sso_id_t a, sso_id_t b) {
    for (size_t i=0;i<l->n;i++) if (l->p[i].a==a && l->p[i].b==b) {
        if (i<l->n-1) memmove(&l->p[i],&l->p[i+1],(l->n-i-1)*sizeof(pair_t));
        l->n--; return true;
    }
    return false;
}
static size_t pl_get(const pl_t *l, sso_id_t by, int col, sso_id_t *out, size_t max) {
    size_t n=0;
    for (size_t i=0;i<l->n && n<max;i++) {
        if (col==1 && l->p[i].a==by) out[n++]=l->p[i].b;
        else if (col==2 && l->p[i].b==by) out[n++]=l->p[i].a;
    }
    return n;
}

typedef struct { sso_id_t pid; int tt; sso_id_t tid; } a3_t;
typedef struct { a3_t *p; size_t n,cap; } al_t;
static void al_init(al_t *l) { memset(l,0,sizeof(*l)); }
static void al_free(al_t *l) { free(l->p); memset(l,0,sizeof(*l)); }
static sso_error_t al_add(al_t *l, sso_id_t p, int t, sso_id_t id) {
    if (l->n>=l->cap) {
        size_t nc=l->cap?l->cap*2:INITIAL_CAP;
        a3_t *n=realloc(l->p,nc*sizeof(a3_t));
        if (!n) return SSO_ERR_OUT_OF_MEMORY;
        l->p=n; l->cap=nc;
    }
    l->p[l->n].pid=p; l->p[l->n].tt=t; l->p[l->n].tid=id; l->n++; return SSO_OK;
}

static void pl_rm_by_b(pl_t *l, sso_id_t bval) {
    for (size_t i = l->n; i > 0; i--)
        if (l->p[i-1].b == bval)
            { size_t idx = i-1; if (idx < l->n-1) memmove(&l->p[idx], &l->p[idx+1], (l->n-idx-1)*sizeof(pair_t)); l->n--; }
}

static void pl_rm_by_a(pl_t *l, sso_id_t aval) {
    for (size_t i = l->n; i > 0; i--)
        if (l->p[i-1].a == aval)
            { size_t idx = i-1; if (idx < l->n-1) memmove(&l->p[idx], &l->p[idx+1], (l->n-idx-1)*sizeof(pair_t)); l->n--; }
}

static void al_rm_by_target(al_t *l, int tt, sso_id_t tid) {
    for (size_t i = l->n; i > 0; i--)
        if (l->p[i-1].tt == tt && l->p[i-1].tid == tid)
            { size_t idx = i-1; if (idx < l->n-1) memmove(&l->p[idx], &l->p[idx+1], (l->n-idx-1)*sizeof(a3_t)); l->n--; }
}

typedef struct { char p[32]; char c[16]; sso_timestamp_t ex; } sms_t;

typedef struct {
    char jti[TOKEN_REVOCATION_STR_LEN];
    sso_timestamp_t expires_at;
} revoked_jti_t;

typedef struct {
    da_t users, roles, groups, policies;
    da_t oauth_clients;
    pl_t user_roles, user_groups, role_groups;
    al_t policy_assignments;
    sms_t *sms; size_t sms_n, sms_cap;
    oauth_auth_code_t *oauth_codes;
    size_t oauth_n, oauth_cap;
    refresh_token_t *refresh_tokens;
    size_t rt_n, rt_cap;
    revoked_jti_t *revoked_jtis;
    size_t jti_n, jti_cap;
    sso_id_t next_uid, next_rid, next_gid, next_pid, next_ocid;
} mem_priv_t;

#define P ((mem_priv_t*)self->handle)

static sso_error_t mem_open(storage_backend_t *self, const char *dsn) {
    (void)dsn; mem_priv_t *p = (mem_priv_t*)self->handle;
    da_init(&p->users,sizeof(user_t)); da_init(&p->roles,sizeof(role_t));
    da_init(&p->groups,sizeof(group_t)); da_init(&p->policies,sizeof(policy_t));
    da_init(&p->oauth_clients,sizeof(oauth_client_t));
    pl_init(&p->user_roles); pl_init(&p->user_groups); pl_init(&p->role_groups);
    al_init(&p->policy_assignments);
    p->sms=NULL; p->sms_n=0; p->sms_cap=0;
    p->oauth_codes=NULL; p->oauth_n=0; p->oauth_cap=0;
    p->refresh_tokens=NULL; p->rt_n=0; p->rt_cap=0;
    p->revoked_jtis=NULL; p->jti_n=0; p->jti_cap=0;
    p->next_uid=1; p->next_rid=1; p->next_gid=1; p->next_pid=1; p->next_ocid=1;
    return SSO_OK;
}

static sso_error_t mem_oauth_code_create(storage_backend_t *self, const oauth_auth_code_t *code) {
    mem_priv_t *p = P; if (!p || !code) return SSO_ERR_STORAGE;
    if (p->oauth_n >= p->oauth_cap) {
        size_t nc = p->oauth_cap ? p->oauth_cap * 2 : 16;
        oauth_auth_code_t *n = realloc(p->oauth_codes, nc * sizeof(oauth_auth_code_t));
        if (!n) return SSO_ERR_OUT_OF_MEMORY;
        p->oauth_codes = n; p->oauth_cap = nc;
    }
    p->oauth_codes[p->oauth_n++] = *code;
    return SSO_OK;
}

static sso_error_t mem_oauth_code_get(storage_backend_t *self, const char *code, oauth_auth_code_t *out) {
    mem_priv_t *p = P; if (!p || !code || !out) return SSO_ERR_STORAGE;
    for (size_t i = 0; i < p->oauth_n; i++) {
        if (strcmp(p->oauth_codes[i].code, code) == 0) {
            *out = p->oauth_codes[i];
            return SSO_OK;
        }
    }
    return SSO_ERR_NOT_FOUND;
}

static sso_error_t mem_oauth_code_mark_used(storage_backend_t *self, const char *code) {
    mem_priv_t *p = P; if (!p || !code) return SSO_ERR_STORAGE;
    for (size_t i = 0; i < p->oauth_n; i++) {
        if (strcmp(p->oauth_codes[i].code, code) == 0) {
            p->oauth_codes[i].used = 1;
            return SSO_OK;
        }
    }
    return SSO_ERR_NOT_FOUND;
}

static sso_error_t mem_oauth_code_cleanup(storage_backend_t *self) {
    mem_priv_t *p = P; if (!p) return SSO_ERR_STORAGE;
    sso_timestamp_t now = sso_timestamp_now();
    size_t w = 0;
    for (size_t i = 0; i < p->oauth_n; i++) {
        if (p->oauth_codes[i].used == 0 && p->oauth_codes[i].expires_at > now) {
            if (w != i) p->oauth_codes[w] = p->oauth_codes[i];
            w++;
        }
    }
    p->oauth_n = w;
    return SSO_OK;
}

static void mem_close(storage_backend_t *self) {
    mem_priv_t *p = P; if (!p) return;
    da_free(&p->users); da_free(&p->roles); da_free(&p->groups); da_free(&p->policies);
    da_free(&p->oauth_clients);
    pl_free(&p->user_roles); pl_free(&p->user_groups); pl_free(&p->role_groups);
    al_free(&p->policy_assignments); free(p->sms);
    free(p->oauth_codes); free(p->refresh_tokens); free(p->revoked_jtis);
    free(p);
    self->handle = NULL;
}

static sso_error_t mem_begin(storage_backend_t *self)   { (void)self; return SSO_OK; }
static sso_error_t mem_commit(storage_backend_t *self)  { (void)self; return SSO_OK; }
static sso_error_t mem_rollback(storage_backend_t *self){ (void)self; return SSO_OK; }

/* ===== User CRUD ===== */

static sso_error_t mem_user_create(storage_backend_t *self, user_t *u) {
    if (u->username[0] && da_find_str(&P->users,offsetof(user_t,username),u->username)>=0)
        return SSO_ERR_ALREADY_EXISTS;
    u->id = P->next_uid++; return da_add(&P->users, u);
}

#define MK_GETID(typ,arr) static sso_error_t mem_##typ##_get_by_id(storage_backend_t *self, sso_id_t id, typ##_t *o) {     ssize_t i=da_find_id(&P->arr,offsetof(typ##_t,id),id);     if (i<0) return SSO_ERR_NOT_FOUND;     memcpy(o,(const typ##_t*)P->arr.items+i,sizeof(typ##_t)); return SSO_OK; }
#define MK_GETNM(typ,arr,fld) static sso_error_t mem_##typ##_get_by_name(storage_backend_t *self, const char *n, typ##_t *o) {     ssize_t i=da_find_str(&P->arr,offsetof(typ##_t,fld),n);     if (i<0) return SSO_ERR_NOT_FOUND;     memcpy(o,(const typ##_t*)P->arr.items+i,sizeof(typ##_t)); return SSO_OK; }
#define MK_UPD(typ,arr) static sso_error_t mem_##typ##_update(storage_backend_t *self, const typ##_t *o) {     ssize_t i=da_find_id(&P->arr,offsetof(typ##_t,id),o->id);     if (i<0) return SSO_ERR_NOT_FOUND;     memcpy((typ##_t*)P->arr.items+i,o,sizeof(typ##_t)); return SSO_OK; }
#define MK_DEL(typ,arr) static sso_error_t mem_##typ##_delete(storage_backend_t *self, sso_id_t id) {     ssize_t i=da_find_id(&P->arr,offsetof(typ##_t,id),id);     if (i<0) return SSO_ERR_NOT_FOUND;     da_rm(&P->arr,(size_t)i); return SSO_OK; }
#define MK_LIST(typ,arr) static sso_error_t mem_##typ##_list(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count) { \
    size_t total = P->arr.count; \
    bool has_q = (q && q[0] != '\0'); \
    size_t match = 0; \
    for (size_t i = 0; i < total; i++) { \
        const typ##_t *o = (const typ##_t*)P->arr.items + i; \
        if (status != -1 && (int)o->status != status) continue; \
        if (has_q && !strstr(o->name, q)) continue; \
        if (match++ < (size_t)offset) continue; \
        if ((match - 1 - (size_t)offset) >= (size_t)limit) continue; \
        ids[(match - 1 - (size_t)offset)] = o->id; \
    } \
    *total_count = match; \
    *count = (match > (size_t)offset) ? ((match - (size_t)offset) > (size_t)limit ? (size_t)limit : (match - (size_t)offset)) : 0; \
    return SSO_OK; \
}

MK_GETID(user,users)
MK_GETID(role,roles) MK_GETID(group,groups) MK_GETID(policy,policies)
MK_GETNM(role,roles,name) MK_GETNM(group,groups,name) MK_GETNM(policy,policies,name)
MK_UPD(role,roles) MK_UPD(group,groups) MK_UPD(policy,policies)
MK_DEL(policy,policies)
MK_LIST(role,roles) MK_LIST(group,groups) MK_LIST(policy,policies)

static sso_error_t mem_user_get_by_name(storage_backend_t *self, const char *n, user_t *o) {
    ssize_t i=da_find_str(&P->users,offsetof(user_t,username),n);
    if (i<0) return SSO_ERR_NOT_FOUND;
    memcpy(o,(const user_t*)P->users.items+i,sizeof(user_t)); return SSO_OK;
}

static sso_error_t mem_user_get_by_phone(storage_backend_t *self, const char *p, user_t *o) {
    ssize_t i=da_find_str(&P->users,offsetof(user_t,phone),p);
    if (i<0) return SSO_ERR_NOT_FOUND;
    memcpy(o,(const user_t*)P->users.items+i,sizeof(user_t)); return SSO_OK;
}

static sso_error_t mem_user_update(storage_backend_t *self, const user_t *u) {
    ssize_t i=da_find_id(&P->users,offsetof(user_t,id),u->id);
    if (i<0) return SSO_ERR_NOT_FOUND;
    memcpy((user_t*)P->users.items+i,u,sizeof(user_t)); return SSO_OK;
}

static sso_error_t mem_user_delete(storage_backend_t *self, sso_id_t id) {
    ssize_t i=da_find_id(&P->users,offsetof(user_t,id),id);
    if (i<0) return SSO_ERR_NOT_FOUND;
    da_rm(&P->users,(size_t)i);
    pl_rm_by_b(&P->user_roles, id);
    pl_rm_by_b(&P->user_groups, id);
    al_rm_by_target(&P->policy_assignments, 0, id);
    return SSO_OK;
}

static sso_error_t mem_user_list(storage_backend_t *self, const char *q, int status, int offset, int limit, sso_id_t *ids, size_t *count, size_t *total_count) {
    size_t total = P->users.count;
    bool has_q = (q && q[0] != '\0');
    size_t match = 0;
    for (size_t i = 0; i < total; i++) {
        const user_t *u = (const user_t*)P->users.items + i;
        if (status != -1 && (int)u->status != status) continue;
        if (has_q && !strstr(u->username, q) && !strstr(u->display_name, q) && !strstr(u->email, q) && !strstr(u->phone, q)) continue;
        if (match++ < (size_t)offset) continue;
        if ((match - 1 - (size_t)offset) >= (size_t)limit) continue;
        ids[(match - 1 - (size_t)offset)] = u->id;
    }
    *total_count = match;
    *count = (match > (size_t)offset) ? ((match - (size_t)offset) > (size_t)limit ? (size_t)limit : (match - (size_t)offset)) : 0;
    return SSO_OK;
}

static sso_error_t mem_role_delete(storage_backend_t *self, sso_id_t id) {
    ssize_t i=da_find_id(&P->roles,offsetof(role_t,id),id);
    if (i<0) return SSO_ERR_NOT_FOUND;
    da_rm(&P->roles,(size_t)i);
    pl_rm_by_a(&P->user_roles, id);
    pl_rm_by_a(&P->role_groups, id);
    al_rm_by_target(&P->policy_assignments, 1, id);
    return SSO_OK;
}

static sso_error_t mem_group_delete(storage_backend_t *self, sso_id_t id) {
    ssize_t i=da_find_id(&P->groups,offsetof(group_t,id),id);
    if (i<0) return SSO_ERR_NOT_FOUND;
    da_rm(&P->groups,(size_t)i);
    pl_rm_by_a(&P->role_groups, id);
    pl_rm_by_b(&P->user_groups, id);
    al_rm_by_target(&P->policy_assignments, 2, id);
    return SSO_OK;
}

/* ===== Role/Group/Policy Create ===== */

static sso_error_t mem_role_create(storage_backend_t *self, role_t *o) {
    if (da_find_str(&P->roles,offsetof(role_t,name),o->name)>=0) return SSO_ERR_ALREADY_EXISTS;
    o->id=P->next_rid++; return da_add(&P->roles,o);
}

static sso_error_t mem_group_create(storage_backend_t *self, group_t *o) {
    if (da_find_str(&P->groups,offsetof(group_t,name),o->name)>=0) return SSO_ERR_ALREADY_EXISTS;
    o->id=P->next_gid++; return da_add(&P->groups,o);
}

static sso_error_t mem_policy_create(storage_backend_t *self, policy_t *o) {
    if (da_find_str(&P->policies,offsetof(policy_t,name),o->name)>=0) return SSO_ERR_ALREADY_EXISTS;
    o->id=P->next_pid++; return da_add(&P->policies,o);
}

/* ===== Assignments ===== */

#define ASN_ADD(NAME, TAB, A, B) static sso_error_t mem_##NAME(storage_backend_t *self, sso_id_t a, sso_id_t b) { return pl_add(&P->TAB, a, b); }

ASN_ADD(assign_role_to_user,user_roles, a,b)
ASN_ADD(assign_role_to_group,role_groups, a,b)
ASN_ADD(add_user_to_group,user_groups, b,a)

static sso_error_t mem_remove_user_from_group(storage_backend_t *self, sso_id_t g, sso_id_t u) {
    pl_rm(&P->user_groups, g, u); return SSO_OK;
}

static sso_error_t mem_unassign_role_from_user(storage_backend_t *self, sso_id_t r, sso_id_t u) {
    pl_rm(&P->user_roles, r, u); return SSO_OK;
}

static sso_error_t mem_unassign_role_from_group(storage_backend_t *self, sso_id_t r, sso_id_t g) {
    pl_rm(&P->role_groups, r, g); return SSO_OK;
}

static sso_error_t mem_get_user_roles(storage_backend_t *self, sso_id_t uid, sso_id_t *ids, size_t *c, size_t m) {
    size_t n=pl_get(&P->user_roles,uid,2,ids,m); *c=n; return n?SSO_OK:SSO_ERR_NOT_FOUND;
}
static sso_error_t mem_get_role_users(storage_backend_t *self, sso_id_t rid, sso_id_t *ids, size_t *c, size_t m) {
    size_t n=pl_get(&P->user_roles,rid,1,ids,m); *c=n; return n?SSO_OK:SSO_ERR_NOT_FOUND;
}
static sso_error_t mem_get_user_groups(storage_backend_t *self, sso_id_t uid, sso_id_t *ids, size_t *c, size_t m) {
    size_t n=pl_get(&P->user_groups,uid,2,ids,m); *c=n; return n?SSO_OK:SSO_ERR_NOT_FOUND;
}
static sso_error_t mem_get_group_users(storage_backend_t *self, sso_id_t gid, sso_id_t *ids, size_t *c, size_t m) {
    size_t n=pl_get(&P->user_groups,gid,1,ids,m); *c=n; return n?SSO_OK:SSO_ERR_NOT_FOUND;
}

/* Policy assignments */
static sso_error_t mem_assign_policy(storage_backend_t *self, sso_id_t pid, policy_target_type_t tt, sso_id_t tid) {
    return al_add(&P->policy_assignments, pid, (int)tt, tid);
}
static sso_error_t mem_unassign_policy(storage_backend_t *self, sso_id_t pid, policy_target_type_t tt, sso_id_t tid) {
    for (size_t i=0;i<P->policy_assignments.n;i++) {
        a3_t *a=&P->policy_assignments.p[i];
        if (a->pid==pid && a->tt==(int)tt && a->tid==tid) {
            if (i<P->policy_assignments.n-1) memmove(a,a+1,(P->policy_assignments.n-i-1)*sizeof(a3_t));
            P->policy_assignments.n--; break;
        }
    }
    return SSO_OK;
}
static sso_error_t mem_get_policy_targets(storage_backend_t *self, sso_id_t pid, policy_target_type_t tt, sso_id_t *ids, size_t *c, size_t m) {
    size_t n=0;
    for (size_t i=0;i<P->policy_assignments.n && n<m;i++) {
        a3_t *a=&P->policy_assignments.p[i];
        if (a->pid==pid && a->tt==(int)tt) ids[n++]=a->tid;
    }
    *c=n; return n?SSO_OK:SSO_ERR_NOT_FOUND;
}
static sso_error_t mem_get_target_policies(storage_backend_t *self, policy_target_type_t tt, sso_id_t tid, sso_id_t *ids, size_t *c, size_t m) {
    size_t n=0;
    for (size_t i=0;i<P->policy_assignments.n && n<m;i++) {
        a3_t *a=&P->policy_assignments.p[i];
        if (a->tt==(int)tt && a->tid==tid) ids[n++]=a->pid;
    }
    *c=n; return n?SSO_OK:SSO_ERR_NOT_FOUND;
}

/* ===== Hierarchy ===== */

static sso_error_t mem_role_get_parent(storage_backend_t *self, sso_id_t rid, sso_id_t *pid) {
    ssize_t i=da_find_id(&P->roles,offsetof(role_t,id),rid);
    if (i<0) return SSO_ERR_NOT_FOUND;
    *pid=((const role_t*)P->roles.items+i)->parent_role_id; return SSO_OK;
}
static sso_error_t mem_group_get_parent(storage_backend_t *self, sso_id_t gid, sso_id_t *pid) {
    ssize_t i=da_find_id(&P->groups,offsetof(group_t,id),gid);
    if (i<0) return SSO_ERR_NOT_FOUND;
    *pid=((const group_t*)P->groups.items+i)->parent_group_id; return SSO_OK;
}

static sso_error_t mem_get_user_roles_with_ancestors(storage_backend_t *self, sso_id_t uid, sso_id_t *ids, size_t *c, size_t m) {
    sso_id_t dir[64]; size_t dc=pl_get(&P->user_roles,uid,2,dir,64);
    if (!dc) { *c=0; return SSO_ERR_NOT_FOUND; }
    size_t n=0;
    for (size_t i=0;i<dc && n<m;i++) {
        sso_id_t cur=dir[i];
        role_t r_info;
        if (mem_role_get_by_id(self, cur, &r_info) != SSO_OK || r_info.status != ROLE_STATUS_ACTIVE) {
            continue;
        }
        bool dup=false; for (size_t j=0;j<n;j++) if (ids[j]==cur) { dup=true; break; }
        if (!dup) ids[n++]=cur;
        while (n<m) {
            sso_id_t par;
            if (mem_role_get_parent(self,cur,&par)!=SSO_OK || par==SSO_ID_NONE) break;
            if (mem_role_get_by_id(self, par, &r_info) != SSO_OK || r_info.status != ROLE_STATUS_ACTIVE) {
                break;
            }
            dup=false; for (size_t j=0;j<n;j++) if (ids[j]==par) { dup=true; break; }
            if (!dup) ids[n++]=par;
            cur=par;
        }
    }
    *c=n; return n?SSO_OK:SSO_ERR_NOT_FOUND;
}

/* ===== SMS ===== */

static sso_error_t mem_save_sms_code(storage_backend_t *self, const char *p, const char *c, sso_timestamp_t ex) {
    for (size_t i=0;i<P->sms_n;i++) if (strcmp(P->sms[i].p,p)==0) {
        sso_strlcpy(P->sms[i].c,c,15); P->sms[i].ex=ex; return SSO_OK;
    }
    if (P->sms_n>=P->sms_cap) {
        size_t nc=P->sms_cap?P->sms_cap*2:16;
        sms_t *n=realloc(P->sms,nc*sizeof(sms_t));
        if (!n) return SSO_ERR_OUT_OF_MEMORY;
        P->sms=n; P->sms_cap=nc;
    }
    sso_strlcpy(P->sms[P->sms_n].p,p,31); sso_strlcpy(P->sms[P->sms_n].c,c,15);
    P->sms[P->sms_n].ex=ex; P->sms_n++; return SSO_OK;
}

static sso_error_t mem_get_sms_code(storage_backend_t *self, const char *p, char *out) {
    for (size_t i=0;i<P->sms_n;i++) if (strcmp(P->sms[i].p,p)==0) {
        if (sso_timestamp_now()>P->sms[i].ex) return SSO_ERR_TOKEN_EXPIRED;
        sso_strlcpy(out,P->sms[i].c,15); out[15]=0; return SSO_OK;
    }
    return SSO_ERR_NOT_FOUND;
}

static sso_error_t mem_delete_sms_code(storage_backend_t *self, const char *p) {
    for (size_t i=0;i<P->sms_n;i++) if (strcmp(P->sms[i].p,p)==0) {
        if (i<P->sms_n-1) memmove(&P->sms[i],&P->sms[i+1],(P->sms_n-i-1)*sizeof(sms_t));
        P->sms_n--; return SSO_OK;
    }
    return SSO_OK;
}

/* ===== OAuth Clients ===== */

static sso_error_t mem_oauth_client_create(storage_backend_t *self, oauth_client_t *c) {
    if (da_find_str(&P->oauth_clients, offsetof(oauth_client_t, client_id), c->client_id) >= 0)
        return SSO_ERR_ALREADY_EXISTS;
    c->id = P->next_ocid++;
    if (c->created_at == 0) c->created_at = sso_timestamp_now();
    if (c->updated_at == 0) c->updated_at = c->created_at;
    return da_add(&P->oauth_clients, c);
}

static sso_error_t mem_oauth_client_get(storage_backend_t *self, const char *client_id, oauth_client_t *c) {
    ssize_t i = da_find_str(&P->oauth_clients, offsetof(oauth_client_t, client_id), client_id);
    if (i < 0) return SSO_ERR_NOT_FOUND;
    memcpy(c, (const oauth_client_t*)P->oauth_clients.items + i, sizeof(oauth_client_t));
    return SSO_OK;
}

static sso_error_t mem_oauth_client_update(storage_backend_t *self, const oauth_client_t *c) {
    ssize_t i = da_find_id(&P->oauth_clients, offsetof(oauth_client_t, id), c->id);
    if (i < 0) return SSO_ERR_NOT_FOUND;
    memcpy((oauth_client_t*)P->oauth_clients.items + i, c, sizeof(oauth_client_t));
    return SSO_OK;
}

static sso_error_t mem_oauth_client_delete(storage_backend_t *self, const char *client_id) {
    ssize_t i = da_find_str(&P->oauth_clients, offsetof(oauth_client_t, client_id), client_id);
    if (i < 0) return SSO_ERR_NOT_FOUND;
    da_rm(&P->oauth_clients, (size_t)i);
    return SSO_OK;
}

static sso_error_t mem_oauth_client_list(storage_backend_t *self, int offset, int limit, oauth_client_t *clients, size_t *count, size_t max) {
    size_t total = P->oauth_clients.count;
    size_t match = 0;
    size_t n = 0;
    for (size_t i = 0; i < total; i++) {
        if (match++ < (size_t)offset) continue;
        if (n >= (size_t)limit || n >= max) break;
        clients[n++] = *((const oauth_client_t*)P->oauth_clients.items + i);
    }
    if (count) *count = n;
    return SSO_OK;
}

static sso_error_t mem_rt_create(storage_backend_t *self, const refresh_token_t *rt) {
    mem_priv_t *p = P; if (!p || !rt) return SSO_ERR_STORAGE;
    if (p->rt_n >= p->rt_cap) {
        size_t nc = p->rt_cap ? p->rt_cap * 2 : 16;
        refresh_token_t *n = realloc(p->refresh_tokens, nc * sizeof(refresh_token_t));
        if (!n) return SSO_ERR_OUT_OF_MEMORY;
        p->refresh_tokens = n; p->rt_cap = nc;
    }
    p->refresh_tokens[p->rt_n++] = *rt;
    return SSO_OK;
}

static sso_error_t mem_rt_get(storage_backend_t *self, const char *h, refresh_token_t *rt) {
    mem_priv_t *p = P; if (!p || !h || !rt) return SSO_ERR_STORAGE;
    for (size_t i = 0; i < p->rt_n; i++) {
        if (strcmp(p->refresh_tokens[i].token_hash, h) == 0) {
            *rt = p->refresh_tokens[i];
            return SSO_OK;
        }
    }
    return SSO_ERR_NOT_FOUND;
}

static sso_error_t mem_rt_revoke(storage_backend_t *self, const char *h) {
    mem_priv_t *p = (mem_priv_t*)self->handle; if (!p || !h) return SSO_ERR_STORAGE;
    for (size_t i = 0; i < p->rt_n; i++) {
        if (strcmp(p->refresh_tokens[i].token_hash, h) == 0) {
            p->refresh_tokens[i].revoked = 1;
            return SSO_OK;
        }
    }
    return SSO_ERR_NOT_FOUND;
}

static sso_error_t mem_rt_revoke_family(storage_backend_t *self, sso_id_t user_id, const char *client_id) {
    mem_priv_t *p = (mem_priv_t*)self->handle; if (!p || !client_id) return SSO_ERR_STORAGE;
    for (size_t i = 0; i < p->rt_n; i++) {
        if (p->refresh_tokens[i].user_id == user_id && strcmp(p->refresh_tokens[i].client_id, client_id) == 0) {
            p->refresh_tokens[i].revoked = 1;
        }
    }
    return SSO_OK;
}

static sso_error_t mem_jti_revoke(storage_backend_t *self, const char *jti, sso_timestamp_t expires_at) {
    mem_priv_t *p = (mem_priv_t*)self->handle;
    if (!p || !jti) return SSO_ERR_STORAGE;
    for (size_t i = 0; i < p->jti_n; i++) {
        if (strcmp(p->revoked_jtis[i].jti, jti) == 0) {
            p->revoked_jtis[i].expires_at = expires_at;
            return SSO_OK;
        }
    }
    if (p->jti_n >= p->jti_cap) {
        size_t nc = p->jti_cap ? p->jti_cap * 2 : 16;
        revoked_jti_t *n = realloc(p->revoked_jtis, nc * sizeof(revoked_jti_t));
        if (!n) return SSO_ERR_OUT_OF_MEMORY;
        p->revoked_jtis = n; p->jti_cap = nc;
    }
    sso_strlcpy(p->revoked_jtis[p->jti_n].jti, jti, TOKEN_REVOCATION_STR_LEN);
    p->revoked_jtis[p->jti_n].jti[TOKEN_REVOCATION_STR_LEN - 1] = '\0';
    p->revoked_jtis[p->jti_n].expires_at = expires_at;
    p->jti_n++;
    return SSO_OK;
}

static bool mem_jti_is_revoked(storage_backend_t *self, const char *jti) {
    mem_priv_t *p = (mem_priv_t*)self->handle;
    if (!p || !jti) return false;
    sso_timestamp_t now = sso_timestamp_now();
    for (size_t i = 0; i < p->jti_n; i++) {
        if (strcmp(p->revoked_jtis[i].jti, jti) == 0) {
            if (p->revoked_jtis[i].expires_at > now) {
                return true;
            }
        }
    }
    return false;
}

#undef P

/* ===== Constructor ===== */

sso_error_t storage_memory_create(storage_backend_t **backend) {
    if (!backend) return SSO_ERR_INVALID_PARAM;
    *backend = (storage_backend_t*)calloc(1,sizeof(storage_backend_t));
    if (!*backend) return SSO_ERR_OUT_OF_MEMORY;
    mem_priv_t *priv = (mem_priv_t*)calloc(1,sizeof(mem_priv_t));
    if (!priv) { free(*backend); *backend=NULL; return SSO_ERR_OUT_OF_MEMORY; }

    sso_strlcpy((*backend)->name,"memory",sizeof((*backend)->name));
    (*backend)->open=mem_open; (*backend)->close=mem_close;
    (*backend)->begin=mem_begin; (*backend)->commit=mem_commit; (*backend)->rollback=mem_rollback;

    /* User */
    (*backend)->user_create=mem_user_create; (*backend)->user_get_by_id=mem_user_get_by_id;
    (*backend)->user_get_by_name=mem_user_get_by_name; (*backend)->user_get_by_phone=mem_user_get_by_phone;
    (*backend)->user_update=mem_user_update; (*backend)->user_delete=mem_user_delete;
    (*backend)->user_list=mem_user_list;

    /* SMS */
    (*backend)->save_sms_code=mem_save_sms_code; (*backend)->get_sms_code=mem_get_sms_code;
    (*backend)->delete_sms_code=mem_delete_sms_code;

    /* Role */
    (*backend)->role_create=mem_role_create; (*backend)->role_get_by_id=mem_role_get_by_id;
    (*backend)->role_get_by_name=mem_role_get_by_name; (*backend)->role_update=mem_role_update;
    (*backend)->role_delete=mem_role_delete; (*backend)->role_list=mem_role_list;

    /* Group */
    (*backend)->group_create=mem_group_create; (*backend)->group_get_by_id=mem_group_get_by_id;
    (*backend)->group_get_by_name=mem_group_get_by_name; (*backend)->group_update=mem_group_update;
    (*backend)->group_delete=mem_group_delete; (*backend)->group_list=mem_group_list;

    /* Policy */
    (*backend)->policy_create=mem_policy_create; (*backend)->policy_get_by_id=mem_policy_get_by_id;
    (*backend)->policy_get_by_name=mem_policy_get_by_name; (*backend)->policy_update=mem_policy_update;
    (*backend)->policy_delete=mem_policy_delete; (*backend)->policy_list=mem_policy_list;

    /* Assignments */
    (*backend)->assign_role_to_user=mem_assign_role_to_user;
    (*backend)->unassign_role_from_user=mem_unassign_role_from_user;
    (*backend)->get_user_roles=mem_get_user_roles;
    (*backend)->get_role_users=mem_get_role_users;
    (*backend)->assign_role_to_group=mem_assign_role_to_group;
    (*backend)->unassign_role_from_group=mem_unassign_role_from_group;
    (*backend)->add_user_to_group=mem_add_user_to_group;
    (*backend)->remove_user_from_group=mem_remove_user_from_group;
    (*backend)->get_user_groups=mem_get_user_groups;
    (*backend)->get_group_users=mem_get_group_users;
    (*backend)->assign_policy=mem_assign_policy;
    (*backend)->unassign_policy=mem_unassign_policy;
    (*backend)->get_policy_targets=mem_get_policy_targets;
    (*backend)->get_target_policies=mem_get_target_policies;

    /* Hierarchy */
    (*backend)->role_get_parent=mem_role_get_parent;
    (*backend)->group_get_parent=mem_group_get_parent;
    (*backend)->get_user_roles_with_ancestors=mem_get_user_roles_with_ancestors;

    /* OAuth */
    (*backend)->oauth_code_create=mem_oauth_code_create;
    (*backend)->oauth_code_get=mem_oauth_code_get;
    (*backend)->oauth_code_mark_used=mem_oauth_code_mark_used;
    (*backend)->oauth_code_cleanup=mem_oauth_code_cleanup;

    (*backend)->oauth_client_create    = mem_oauth_client_create;
    (*backend)->oauth_client_get       = mem_oauth_client_get;
    (*backend)->oauth_client_update    = mem_oauth_client_update;
    (*backend)->oauth_client_delete    = mem_oauth_client_delete;
    (*backend)->oauth_client_list      = mem_oauth_client_list;

    (*backend)->refresh_token_create = mem_rt_create;
    (*backend)->refresh_token_get    = mem_rt_get;
    (*backend)->refresh_token_revoke = mem_rt_revoke;
    (*backend)->refresh_token_revoke_family = mem_rt_revoke_family;
    (*backend)->jti_revoke           = mem_jti_revoke;
    (*backend)->jti_is_revoked       = mem_jti_is_revoked;

    (*backend)->handle = priv;
    return SSO_OK;
}
