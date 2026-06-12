/*
 * user.c — User manager implementation.
 *
 * Delegates all CRUD to the storage backend.  Password hashing uses
 * SHA-256 with a salt (in production, use bcrypt/argon2).
 */

#include "sso.h"
#include "user.h"
#include "storage.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Simple SHA-256 + salt "hash" — REPLACE with bcrypt/argon2 in production */
#include <openssl/sha.h>

#define SALT_LEN 16

struct user_manager {
    sso_context_t *ctx;
};

/* -----------------------------------------------------------------------
 * Internal: hash password with a random salt
 * ----------------------------------------------------------------------- */
static void hash_password(const char *password, const unsigned char *salt,
                          char *out_hash, size_t out_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, salt, SALT_LEN);
    SHA256_Update(&sha, password, strlen(password));
    SHA256_Final(hash, &sha);

    /* Encode as hex: salt + hash */
    char *p = out_hash;
    for (int i = 0; i < SALT_LEN && p < out_hash + out_len - 3; i++) {
        p += snprintf(p, out_len - (size_t)(p - out_hash), "%02x", salt[i]);
    }
    for (int i = 0; i < SHA256_DIGEST_LENGTH && p < out_hash + out_len - 3; i++) {
        p += snprintf(p, out_len - (size_t)(p - out_hash), "%02x", hash[i]);
    }
}

static void generate_salt(unsigned char *salt) {
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        size_t r = fread(salt, 1, SALT_LEN, f);
        (void)r;
        fclose(f);
    } else {
        /* Fallback — not cryptographically secure */
        for (int i = 0; i < SALT_LEN; i++) {
            salt[i] = (unsigned char)(rand() & 0xFF);
        }
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
    return SSO_OK;
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

    /* Hash password */
    unsigned char salt[SALT_LEN];
    generate_salt(salt);
    hash_password(password, salt, user.password_hash, sizeof(user.password_hash));

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

sso_error_t user_update(user_manager_t *mgr, const user_t *user) {
    if (!mgr || !user) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_update) return SSO_ERR_NOT_IMPLEMENTED;

    /* Update timestamp */
    user_t updated = *user;
    updated.updated_at = sso_timestamp_now();
    return sb->user_update(sb, &updated);
}

sso_error_t user_delete(user_manager_t *mgr, sso_id_t id) {
    if (!mgr) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_delete) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->user_delete(sb, id);
}

sso_error_t user_list(user_manager_t *mgr, sso_id_t *ids, size_t *count, size_t max) {
    if (!mgr || !ids || !count) return SSO_ERR_INVALID_PARAM;
    storage_backend_t *sb = (storage_backend_t *)mgr->ctx->storage_backend;
    if (!sb || !sb->user_list) return SSO_ERR_NOT_IMPLEMENTED;
    return sb->user_list(sb, ids, count, max);
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

    /* Extract salt from stored hash (first 32 hex chars = 16 bytes) */
    unsigned char salt[SALT_LEN];
    for (int i = 0; i < SALT_LEN; i++) {
        unsigned int byte;
        sscanf(&stored.password_hash[i * 2], "%02x", &byte);
        salt[i] = (unsigned char)byte;
    }

    /* Hash input password with same salt */
    char computed_hash[SSO_MAX_PASSWORD_HASH];
    hash_password(password, salt, computed_hash, sizeof(computed_hash));

    if (strcmp(computed_hash, stored.password_hash) != 0) {
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

    unsigned char salt[SALT_LEN];
    generate_salt(salt);
    hash_password(new_password, salt, user.password_hash, sizeof(user.password_hash));

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
