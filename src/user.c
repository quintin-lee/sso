/*
 * user.c — User manager implementation.
 *
 * Delegates all CRUD to the storage backend.  Password hashing uses
 * libsodium crypto_pwhash_str (argon2id) — the current recommended
 * password hashing algorithm (memory-hard, resistant to GPU/ASIC
 * brute-force attacks).
 */

#include "sso.h"
#include "user.h"
#include "config.h"
#include "storage.h"
#include "permission.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>

struct user_manager {
    sso_context_t  *ctx;
    unsigned long   hash_opslimit;   /* argon2id OPSLIMIT */
    unsigned long   hash_memlimit;   /* argon2id MEMLIMIT */
};

/* -----------------------------------------------------------------------
 * Internal: hash password with argon2id via libsodium.
 *
 * The output is a self-contained ASCII string of the form:
 *   $argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>
 * No separate salt storage is needed — salt and parameters are embedded.
 * ----------------------------------------------------------------------- */
static void hash_password(const char *password, char *out_hash, size_t out_len,
                          unsigned long opslimit, unsigned long memlimit) {
    if (out_len < crypto_pwhash_STRBYTES) {
        if (out_len > 0) out_hash[0] = '\0';
        return;
    }
    if (crypto_pwhash_str(out_hash, password, strlen(password),
                          opslimit, memlimit) != 0) {
        if (out_len > 0) out_hash[0] = '\0';
    }
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */
sso_error_t user_manager_create(user_manager_t **mgr, sso_context_t *ctx) {
    if (!mgr || !ctx) return SSO_ERR_INVALID_PARAM;
    *mgr = (user_manager_t *)calloc(1, sizeof(user_manager_t));
    if (!*mgr) return SSO_ERR_OUT_OF_MEMORY;
    (*mgr)->ctx = ctx;

    /* Initialise hash params from config if available, else use moderate defaults */
    sso_config_t *cfg = (sso_config_t *)sso_get_config(ctx);
    if (cfg) {
        (*mgr)->hash_opslimit = cfg->password_opslimit ? cfg->password_opslimit : crypto_pwhash_OPSLIMIT_MODERATE;
        (*mgr)->hash_memlimit = cfg->password_memlimit ? cfg->password_memlimit : crypto_pwhash_MEMLIMIT_MODERATE;
    } else {
        (*mgr)->hash_opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
        (*mgr)->hash_memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
    }
    return SSO_OK;
}

void user_manager_set_hash_params(user_manager_t *mgr,
                                  unsigned long opslimit,
                                  unsigned long memlimit) {
    if (!mgr) return;
    mgr->hash_opslimit = opslimit;
    mgr->hash_memlimit = memlimit;
}

void user_manager_destroy(user_manager_t *mgr) {
    free(mgr);
}

/* ========================================================================
 * CRUD
 * ======================================================================== */
sso_error_t user_create(user_manager_t *mgr, const char *username,
                        const char *password, const char *email,
                        const char *display_name, user_t *out) {
    if (!mgr || !username || !password) return SSO_ERR_INVALID_PARAM;

    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_create) return SSO_ERR_NOT_IMPLEMENTED;

    user_t user;
    memset(&user, 0, sizeof(user));

    strncpy(user.username, username, SSO_MAX_USERNAME - 1);
    if (email)    strncpy(user.email, email, SSO_MAX_EMAIL - 1);
    if (display_name) strncpy(user.display_name, display_name, SSO_MAX_DISPLAY_NAME - 1);
    user.status = USER_STATUS_ACTIVE;
    user.created_at = sso_timestamp_now();
    user.updated_at = user.created_at;

    /* Hash password with argon2id */
    hash_password(password, user.password_hash, sizeof(user.password_hash),
                  mgr->hash_opslimit, mgr->hash_memlimit);

    sso_error_t err = sb->user_create(sb, &user);
    if (err == SSO_OK && out) {
        *out = user;
    }
    return err;
}

sso_error_t user_create_by_phone(user_manager_t *mgr, const char *phone, user_t *out) {
    if (!mgr || !phone) return SSO_ERR_INVALID_PARAM;

    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_create) return SSO_ERR_NOT_IMPLEMENTED;

    user_t user;
    memset(&user, 0, sizeof(user));

    strncpy(user.phone, phone, SSO_MAX_PHONE - 1);
    /* For SMS users, we don't have a password. Set username to phone for uniqueness if needed,
     * or leave it blank based on DB schema support. Let's set it to phone. */
    strncpy(user.username, phone, SSO_MAX_USERNAME - 1);
    user.status = USER_STATUS_ACTIVE;
    user.created_at = sso_timestamp_now();
    user.updated_at = user.created_at;

    sso_error_t err = sb->user_create(sb, &user);
    if (err == SSO_OK && out) {
        *out = user;
    }
    return err;
}

sso_error_t user_get_by_id(user_manager_t *mgr, sso_id_t id, user_t *out) {
    if (!mgr || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_get_by_id) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->user_get_by_id(sb, id, out);
}

sso_error_t user_get_by_username(user_manager_t *mgr, const char *username, user_t *out) {
    if (!mgr || !username || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_get_by_name) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->user_get_by_name(sb, username, out);
}

sso_error_t user_get_by_phone(user_manager_t *mgr, const char *phone, user_t *out) {
    if (!mgr || !phone || !out) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_get_by_phone) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->user_get_by_phone(sb, phone, out);
}

sso_error_t user_update(user_manager_t *mgr, const user_t *user) {
    if (!mgr || !user) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_update) return SSO_ERR_NOT_IMPLEMENTED;

    /* Update timestamp */
    user_t updated = *user;
    updated.updated_at = sso_timestamp_now();
    sso_error_t err = sb->user_update(sb, &updated);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_user((permission_engine_t *)mgr->ctx->perm_engine, user->id);
    }
    return err;
}

sso_error_t user_delete(user_manager_t *mgr, sso_id_t id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_delete) return SSO_ERR_NOT_IMPLEMENTED;
    sso_error_t err = sb->user_delete(sb, id);
    if (err == SSO_OK) {
        perm_engine_cache_invalidate_user((permission_engine_t *)mgr->ctx->perm_engine, id);
    }
    return err;
}

sso_error_t user_list(user_manager_t *mgr, const char *q, int status,
                      int offset, int limit,
                      sso_id_t *ids, size_t *count, size_t *total_count) {
    if (!mgr || !ids || !count || !total_count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_list) return SSO_ERR_NOT_IMPLEMENTED;

    return sb->user_list(sb, q, status, offset, limit, ids, count, total_count);
}

/* ========================================================================
 * Authentication
 * ======================================================================== */
sso_error_t user_authenticate(user_manager_t *mgr, const char *username,
                              const char *password, user_t *out) {
    if (!mgr || !username || !password || !out) return SSO_ERR_INVALID_PARAM;

    user_t stored;
    sso_error_t err = user_get_by_username(mgr, username, &stored);
    if (err != SSO_OK) return SSO_ERR_AUTH_FAILED;

    if (stored.status != USER_STATUS_ACTIVE) return SSO_ERR_AUTH_FAILED;

    /* Verify password against stored argon2id hash */
    if (crypto_pwhash_str_verify(stored.password_hash, password,
                                  strlen(password)) != 0) {
        return SSO_ERR_AUTH_FAILED;
    }

    *out = stored;
    return SSO_OK;
}

sso_error_t user_set_password(user_manager_t *mgr, sso_id_t user_id,
                              const char *new_password) {
    if (!mgr || !new_password) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id(mgr, user_id, &user);
    if (err != SSO_OK) return err;

    hash_password(new_password, user.password_hash, sizeof(user.password_hash),
                  mgr->hash_opslimit, mgr->hash_memlimit);

    return user_update(mgr, &user);
}

sso_error_t user_set_status(user_manager_t *mgr, sso_id_t user_id,
                            user_status_t status) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;

    user_t user;
    sso_error_t err = user_get_by_id(mgr, user_id, &user);
    if (err != SSO_OK) return err;

    user.status = status;
    return user_update(mgr, &user);
}

/* ========================================================================
 * Role & Group queries
 * ======================================================================== */
sso_error_t user_get_roles(user_manager_t *mgr, sso_id_t user_id,
                           sso_id_t *role_ids, size_t *count, size_t max) {
    if (!mgr || !role_ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_user_roles) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->get_user_roles(sb, user_id, role_ids, count, max);
}

sso_error_t user_get_groups(user_manager_t *mgr, sso_id_t user_id,
                            sso_id_t *group_ids, size_t *count, size_t max) {
    if (!mgr || !group_ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->get_user_groups) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->get_user_groups(sb, user_id, group_ids, count, max);
}
