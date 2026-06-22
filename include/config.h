/*
 * config.h — SSO system configuration management.
 *
 * Provides a unified configuration model loaded from three sources
 * (in priority order): environment variables > TOML config file > built-in defaults.
 * All runtime behaviour (server bind address, token TTL, rate limits, etc.)
 * is driven by this struct.
 */

#ifndef SSO_CONFIG_H
#define SSO_CONFIG_H

#include "sso.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct sso_config_t
 * @brief Aggregated runtime configuration for the SSO system.
 *
 * Populated by sso_config_default(), then sso_config_load() overlays values
 * from sso.toml, and finally sso_config_apply_env() applies environment
 * variable overrides (SSO_HOST, SSO_PORT, etc.).
 */
typedef struct {
	/* -------- [server] -------- */
	char host[128];			 /**< Bind address (default: "0.0.0.0") */
	int	 port;				 /**< HTTP listen port (default: 8080) */
	int	 thread_pool_size;	 /**< Worker thread count for libmicrohttpd */
	int	 queue_size;		 /**< Maximum pending connections in backlog */
	int	 request_timeout_ms; /**< Per-request timeout in milliseconds */
	long max_body_size;		 /**< Maximum request body size in bytes */

	/* -------- [database] -------- */
	char path[256];					 /**< SQLite database file path */
	bool use_memory;				 /**< If true, uses volatile in-memory storage */
	char database_type[16];			 /**< Backend discriminator: "sqlite" | "postgres" */
	char database_url[SSO_MAX_PATH]; /**< PostgreSQL connection URI */

	/* -------- [security] -------- */
	char		  token_secret[128];	 /**< HMAC-SHA256 signing key for HS256 tokens */
	char		  private_key_pem[4096]; /**< RSA private key PEM for RS256 tokens */
	char		  public_key_pem[4096];	 /**< RSA public key PEM for RS256 tokens */
	char		  admin_password[128];	 /**< Bootstrap admin password (cleared after init) */
	long		  token_ttl_ms;			 /**< Default token lifetime in milliseconds */
	unsigned long password_opslimit;	 /**< Argon2id CPU cost (3 = moderate, 4 = sensitive) */
	unsigned long password_memlimit;	 /**< Argon2id memory cost in bytes (default 256 MiB) */
	bool		  tls_enabled;			 /**< Enable HTTPS via TLS */
	char		  tls_cert_file[512];	 /**< Path to TLS certificate PEM file */
	char		  tls_key_file[512];	 /**< Path to TLS private key PEM file */

	/* -------- [sms] -------- */
	char sms_gateway_url[256]; /**< SMS provider HTTP endpoint (NULL = mock mode) */
	char sms_api_key[128];	   /**< SMS provider API key */

	/* -------- [logging] -------- */
	int	 log_level;			  /**< 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR */
	int	 log_format;		  /**< 0=text (default), 1=JSON (ELK-friendly) */
	char audit_log_path[256]; /**< File path for structured permission audit log */

	/* -------- [oauth] -------- */
	char oauth_client_id[64];	   /**< Default OAuth 2.0 client ID */
	char oauth_client_secret[128]; /**< Default OAuth 2.0 client secret */
	char oauth_redirect_uris[512]; /**< Comma-separated allowed redirect URIs */
	char oauth_issuer[256];		   /**< OIDC issuer URL (default: http://localhost:8080) */
	long oauth_auth_code_ttl_ms;   /**< Authorization code TTL in milliseconds */

	/* -------- [ratelimit] -------- */
	int max_ips; /**< Maximum number of tracked IP addresses in the rate limiter */

	/* -------- [password_policy] -------- */
	password_policy_t password_policy; /**< Min/max length, character requirements, expiry */

	/* -------- [raft] -------- */
	bool raft_enabled;
	int	 raft_node_id;
	struct {
		int	 id;
		char url[256];
	} raft_nodes[16];
	int raft_node_count;
} sso_config_t;

/* Initialize config with default values. */
void sso_config_default(sso_config_t* cfg);

/* Load config from a TOML file. Overrides defaults.
 * Returns SSO_OK on success, or an error code. */
sso_error_t sso_config_load(const char* filename, sso_config_t* cfg);

/* Apply environment variable overrides to the config. */
void sso_config_apply_env(sso_config_t* cfg);

#ifdef __cplusplus
}
#endif

#endif /* SSO_CONFIG_H */
