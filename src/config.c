/*
 * config.c — SSO configuration implementation.
 */

#include "config.h"
#include "logger.h"
#include "toml.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sso_config_default(sso_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));

    /* [server] defaults */
    strcpy(cfg->host, "0.0.0.0");
    cfg->port = 8080;
    cfg->thread_pool_size = 8;
    cfg->queue_size = 1024;
    cfg->request_timeout_ms = 10000;
    cfg->max_body_size = 1048576;

    /* [database] defaults */
    strcpy(cfg->path, "sso_server.db");
    cfg->use_memory = false;

    /* [security] defaults */
    cfg->token_ttl_ms = 3600000; /* 1 hour */
    cfg->password_opslimit = 3;    /* crypto_pwhash_OPSLIMIT_MODERATE */
    cfg->password_memlimit = 268435456UL; /* crypto_pwhash_MEMLIMIT_MODERATE (256MB) */
    cfg->tls_enabled = false;
    cfg->tls_cert_file[0] = '\0';
    cfg->tls_key_file[0] = '\0';
    
    /* [ratelimit] defaults */
    cfg->max_ips = 10000;
}

static void get_string(toml_table_t *table, const char *key, char *dest, size_t dest_size) {
    toml_datum_t d = toml_string_in(table, key);
    if (d.ok) {
        strncpy(dest, d.u.s, dest_size - 1);
        dest[dest_size - 1] = '\0';
        free(d.u.s);
    }
}

static void get_int(toml_table_t *table, const char *key, int *dest) {
    toml_datum_t d = toml_int_in(table, key);
    if (d.ok) {
        *dest = (int)d.u.i;
    }
}

static void get_long(toml_table_t *table, const char *key, long *dest) {
    toml_datum_t d = toml_int_in(table, key);
    if (d.ok) {
        *dest = (long)d.u.i;
    }
}

static void get_bool(toml_table_t *table, const char *key, bool *dest) {
    toml_datum_t d = toml_bool_in(table, key);
    if (d.ok) {
        *dest = (bool)d.u.b;
    }
}

sso_error_t sso_config_load(const char *filename, sso_config_t *cfg) {
    if (!filename || !cfg) return SSO_ERR_INVALID_PARAM;

    FILE *fp = fopen(filename, "r");
    if (!fp) return SSO_ERR_NOT_FOUND;

    char errbuf[200];
    toml_table_t *root = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    if (!root) {
        LOG_ERROR("[config] TOML parse error: %s", errbuf);
        return SSO_ERR_INIT;
    }

    /* [server] */
    toml_table_t *server = toml_table_in(root, "server");
    if (server) {
        get_string(server, "host", cfg->host, sizeof(cfg->host));
        get_int(server, "port", &cfg->port);
        get_int(server, "thread_pool_size", &cfg->thread_pool_size);
        get_int(server, "queue_size", &cfg->queue_size);
        get_int(server, "request_timeout_ms", &cfg->request_timeout_ms);
        get_long(server, "max_body_size", &cfg->max_body_size);
    }

    /* [database] */
    toml_table_t *db = toml_table_in(root, "database");
    if (db) {
        get_string(db, "path", cfg->path, sizeof(cfg->path));
        get_bool(db, "use_memory", &cfg->use_memory);
    }

    /* [security] */
    toml_table_t *sec = toml_table_in(root, "security");
    if (sec) {
        get_string(sec, "token_secret", cfg->token_secret, sizeof(cfg->token_secret));
        get_string(sec, "private_key", cfg->private_key_pem, sizeof(cfg->private_key_pem));
        get_string(sec, "public_key", cfg->public_key_pem, sizeof(cfg->public_key_pem));
        get_string(sec, "admin_password", cfg->admin_password, sizeof(cfg->admin_password));
        get_long(sec, "token_ttl_ms", &cfg->token_ttl_ms);
        { unsigned long v; toml_datum_t d = toml_int_in(sec, "password_opslimit"); if (d.ok) { v = (unsigned long)d.u.i; cfg->password_opslimit = v; } }
        { unsigned long v; toml_datum_t d = toml_int_in(sec, "password_memlimit"); if (d.ok) { v = (unsigned long)d.u.i; cfg->password_memlimit = v; } }
        get_bool(sec, "tls_enabled", &cfg->tls_enabled);
        get_string(sec, "tls_cert_file", cfg->tls_cert_file, sizeof(cfg->tls_cert_file));
        get_string(sec, "tls_key_file", cfg->tls_key_file, sizeof(cfg->tls_key_file));
    }

    /* [sms] */
    toml_table_t *sms = toml_table_in(root, "sms");
    if (sms) {
        get_string(sms, "gateway_url", cfg->sms_gateway_url, sizeof(cfg->sms_gateway_url));
        get_string(sms, "api_key", cfg->sms_api_key, sizeof(cfg->sms_api_key));
    }

    /* [oauth] */
    toml_table_t *oauth = toml_table_in(root, "oauth");
    if (oauth) {
        get_string(oauth, "client_id", cfg->oauth_client_id, sizeof(cfg->oauth_client_id));
        get_string(oauth, "client_secret", cfg->oauth_client_secret, sizeof(cfg->oauth_client_secret));
        get_string(oauth, "redirect_uris", cfg->oauth_redirect_uris, sizeof(cfg->oauth_redirect_uris));
        get_string(oauth, "issuer", cfg->oauth_issuer, sizeof(cfg->oauth_issuer));
        get_long(oauth, "auth_code_ttl_ms", &cfg->oauth_auth_code_ttl_ms);
    }

    /* [logging] */
    toml_table_t *logging = toml_table_in(root, "logging");
    if (logging) {
        get_int(logging, "level", &cfg->log_level);
        if (cfg->log_level < LOG_DEBUG) cfg->log_level = LOG_DEBUG;
        if (cfg->log_level > LOG_ERROR) cfg->log_level = LOG_ERROR;
    }

    /* [ratelimit] */
    toml_table_t *rl = toml_table_in(root, "ratelimit");
    if (rl) {
        get_int(rl, "max_ips", &cfg->max_ips);
    }

    toml_free(root);
    return SSO_OK;
}

void sso_config_apply_env(sso_config_t *cfg) {
    if (!cfg) return;

    char *val;
    if ((val = getenv("SSO_HOST"))) strncpy(cfg->host, val, sizeof(cfg->host)-1);
    if ((val = getenv("SSO_PORT"))) cfg->port = atoi(val);
    if ((val = getenv("SSO_TOKEN_SECRET"))) strncpy(cfg->token_secret, val, sizeof(cfg->token_secret)-1);
    if ((val = getenv("SSO_PRIVATE_KEY"))) strncpy(cfg->private_key_pem, val, sizeof(cfg->private_key_pem)-1);
    if ((val = getenv("SSO_PUBLIC_KEY"))) strncpy(cfg->public_key_pem, val, sizeof(cfg->public_key_pem)-1);
    if ((val = getenv("SSO_ADMIN_PASSWORD"))) strncpy(cfg->admin_password, val, sizeof(cfg->admin_password)-1);
    if ((val = getenv("SSO_SMS_GATEWAY_URL"))) strncpy(cfg->sms_gateway_url, val, sizeof(cfg->sms_gateway_url)-1);
    if ((val = getenv("SSO_SMS_API_KEY"))) strncpy(cfg->sms_api_key, val, sizeof(cfg->sms_api_key)-1);
    { char *ev = getenv("SSO_PASSWORD_OPSLIMIT"); if (ev) cfg->password_opslimit = (unsigned long)atol(ev); }
    { char *ev = getenv("SSO_PASSWORD_MEMLIMIT"); if (ev) cfg->password_memlimit = (unsigned long)atol(ev); }
    { char *ev = getenv("SSO_LOG_LEVEL"); if (ev) { cfg->log_level = atoi(ev); if (cfg->log_level < LOG_DEBUG) cfg->log_level = LOG_DEBUG; if (cfg->log_level > LOG_ERROR) cfg->log_level = LOG_ERROR; } }
    if ((val = getenv("SSO_REQUEST_TIMEOUT_MS"))) cfg->request_timeout_ms = atoi(val);
    if ((val = getenv("SSO_MAX_BODY_SIZE"))) cfg->max_body_size = atol(val);
    if ((val = getenv("SSO_TLS_ENABLED"))) cfg->tls_enabled = (strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0);
    if ((val = getenv("SSO_TLS_CERT_FILE"))) strncpy(cfg->tls_cert_file, val, sizeof(cfg->tls_cert_file)-1);
    if ((val = getenv("SSO_TLS_KEY_FILE"))) strncpy(cfg->tls_key_file, val, sizeof(cfg->tls_key_file)-1);
    if ((val = getenv("SSO_OAUTH_CLIENT_ID"))) strncpy(cfg->oauth_client_id, val, sizeof(cfg->oauth_client_id)-1);
    if ((val = getenv("SSO_OAUTH_CLIENT_SECRET"))) strncpy(cfg->oauth_client_secret, val, sizeof(cfg->oauth_client_secret)-1);
    if ((val = getenv("SSO_OAUTH_REDIRECT_URIS"))) strncpy(cfg->oauth_redirect_uris, val, sizeof(cfg->oauth_redirect_uris)-1);
    if ((val = getenv("SSO_OAUTH_ISSUER"))) strncpy(cfg->oauth_issuer, val, sizeof(cfg->oauth_issuer)-1);
    { char *ev = getenv("SSO_OAUTH_AUTH_CODE_TTL_MS"); if (ev) cfg->oauth_auth_code_ttl_ms = atol(ev); }
}
