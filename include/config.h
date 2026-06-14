/*
 * config.h — SSO system configuration management.
 */

#ifndef SSO_CONFIG_H
#define SSO_CONFIG_H

#include "sso.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* [server] */
    char     host[128];
    int      port;
    int      thread_pool_size;
    int      queue_size;

    /* [database] */
    char     path[256];
    bool     use_memory;

    /* [security] */
    char     token_secret[128];
    char     private_key_pem[4096];
    char     public_key_pem[4096];
    char     admin_password[128];
    long     token_ttl_ms;

    /* [sms] */
    char     sms_gateway_url[256];
    char     sms_api_key[128];

    /* [ratelimit] */
    int      max_ips;
} sso_config_t;

/* Initialize config with default values. */
void sso_config_default(sso_config_t *cfg);

/* Load config from a TOML file. Overrides defaults.
 * Returns SSO_OK on success, or an error code. */
sso_error_t sso_config_load(const char *filename, sso_config_t *cfg);

/* Apply environment variable overrides to the config. */
void sso_config_apply_env(sso_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* SSO_CONFIG_H */
