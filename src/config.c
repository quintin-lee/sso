/*
 * config.c — SSO configuration implementation.
 */

#include "config.h"
#include "logger.h"
#include "toml.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sso_config_default(sso_config_t* cfg) {
	if (!cfg)
		return;
	memset(cfg, 0, sizeof(*cfg));

	/* [server] defaults */
	memcpy(cfg->host, "0.0.0.0", 8);
	cfg->port				= 8080;
	cfg->thread_pool_size	= 8;
	cfg->queue_size			= 1024;
	cfg->request_timeout_ms = 10000;
	cfg->max_body_size		= 1048576;

	/* [database] defaults */
	memcpy(cfg->path, "sso_server.db", 14);
	cfg->use_memory = false;
	sso_strlcpy(cfg->database_type, "sqlite", sizeof(cfg->database_type) - 1);
	sso_strlcpy(cfg->database_url, "sso_server.db", sizeof(cfg->database_url) - 1);

	/* [security] defaults */
	cfg->token_ttl_ms	   = 3600000;	  /* 1 hour */
	cfg->password_opslimit = 3;			  /* crypto_pwhash_OPSLIMIT_MODERATE */
	cfg->password_memlimit = 268435456UL; /* crypto_pwhash_MEMLIMIT_MODERATE (256MB) */
	cfg->tls_enabled	   = false;
	cfg->tls_cert_file[0]  = '\0';
	cfg->tls_key_file[0]   = '\0';

	/* [logging] defaults */
	cfg->log_format = 0; /* text */
	memcpy(cfg->audit_log_path, "audit.log", 10);
	cfg->audit_log_max_size_mb	= 10; /* default 10MB */
	cfg->audit_log_max_backups	= 5;  /* default 5 backups */
	cfg->audit_log_rotate_daily = false;
	memset(cfg->audit_log_secret, 0, sizeof(cfg->audit_log_secret));

	/* [ratelimit] defaults */
	cfg->max_ips = 10000;

	/* [password_policy] defaults — PASSWORD_POLICY_DEFAULT */
	cfg->password_policy = (password_policy_t)PASSWORD_POLICY_DEFAULT;
}

static void get_string(toml_table_t* table, const char* key, char* dest, size_t dest_size) {
	toml_datum_t d = toml_string_in(table, key);
	if (d.ok) {
		sso_strlcpy(dest, d.u.s, dest_size);
		dest[dest_size - 1] = '\0';
		free(d.u.s);
	}
}

/* Read a value that may be a TOML string OR an array of strings.
 * Array elements are joined with single spaces.  Used for fields like
 * [oauth].redirect_uris where both forms are valid:
 *   redirect_uris = "http://a.com"           (string, single URI)
 *   redirect_uris = ["http://a.com", ...]     (array, multiple URIs) */
static void get_string_array(toml_table_t* table, const char* key, char* dest, size_t dest_size) {
	toml_datum_t d = toml_string_in(table, key);
	if (d.ok) {
		sso_strlcpy(dest, d.u.s, dest_size);
		dest[dest_size - 1] = '\0';
		free(d.u.s);
		return;
	}

	toml_array_t* arr = toml_array_in(table, key);
	if (!arr)
		return;

	size_t pos	 = 0;
	int	   nelem = toml_array_nelem(arr);
	for (int i = 0; i < nelem; i++) {
		toml_datum_t elem = toml_string_at(arr, i);
		if (!elem.ok) {
			free(elem.u.s);
			continue;
		}
		if (pos > 0 && pos < dest_size - 1) {
			dest[pos++] = ' ';
		}
		size_t remaining = dest_size - pos;
		size_t slen		 = strlen(elem.u.s);
		if (slen >= remaining)
			slen = remaining - 1;
		memcpy(dest + pos, elem.u.s, slen);
		pos += slen;
		free(elem.u.s);
	}
	dest[pos] = '\0';
}

static void get_int(toml_table_t* table, const char* key, int* dest) {
	toml_datum_t d = toml_int_in(table, key);
	if (d.ok) {
		*dest = (int)d.u.i;
	}
}

static void get_long(toml_table_t* table, const char* key, long* dest) {
	toml_datum_t d = toml_int_in(table, key);
	if (d.ok) {
		*dest = (long)d.u.i;
	}
}

static void get_bool(toml_table_t* table, const char* key, bool* dest) {
	toml_datum_t d = toml_bool_in(table, key);
	if (d.ok) {
		*dest = (bool)d.u.b;
	}
}

sso_error_t sso_config_load(const char* filename, sso_config_t* cfg) {
	if (!filename || !cfg)
		return SSO_ERR_INVALID_PARAM;

	FILE* fp = fopen(filename, "r");
	if (!fp)
		return SSO_ERR_NOT_FOUND;

	char		  errbuf[200];
	toml_table_t* root = toml_parse_file(fp, errbuf, sizeof(errbuf));
	fclose(fp);

	if (!root) {
		LOG_ERROR("[config] TOML parse error: %s", errbuf);
		return SSO_ERR_INIT;
	}

	/* [server] */
	toml_table_t* server = toml_table_in(root, "server");
	if (server) {
		get_string(server, "host", cfg->host, sizeof(cfg->host));
		get_int(server, "port", &cfg->port);
		get_int(server, "thread_pool_size", &cfg->thread_pool_size);
		get_int(server, "queue_size", &cfg->queue_size);
		get_int(server, "request_timeout_ms", &cfg->request_timeout_ms);
		get_long(server, "max_body_size", &cfg->max_body_size);
	}

	/* [database] */
	toml_table_t* db = toml_table_in(root, "database");
	if (db) {
		bool path_provided = toml_key_exists(db, "path");
		bool url_provided  = toml_key_exists(db, "url");

		get_string(db, "path", cfg->path, sizeof(cfg->path));
		get_bool(db, "use_memory", &cfg->use_memory);
		get_string(db, "type", cfg->database_type, sizeof(cfg->database_type));
		get_string(db, "url", cfg->database_url, sizeof(cfg->database_url));

		/* Legacy fallback: if url is NOT provided but path IS provided, use path as url */
		if (!url_provided && path_provided) {
			sso_strlcpy(cfg->database_url, cfg->path, sizeof(cfg->database_url));
			cfg->database_url[sizeof(cfg->database_url) - 1] = '\0';
		}
	}

	/* [security] */
	toml_table_t* sec = toml_table_in(root, "security");
	if (sec) {
		get_string(sec, "token_secret", cfg->token_secret, sizeof(cfg->token_secret));
		get_string(sec, "private_key", cfg->private_key_pem, sizeof(cfg->private_key_pem));
		get_string(sec, "public_key", cfg->public_key_pem, sizeof(cfg->public_key_pem));
		get_string(sec, "admin_password", cfg->admin_password, sizeof(cfg->admin_password));
		get_long(sec, "token_ttl_ms", &cfg->token_ttl_ms);
		{
			toml_datum_t d = toml_int_in(sec, "password_opslimit");
			if (d.ok) {
				unsigned long v		   = (unsigned long)d.u.i;
				cfg->password_opslimit = v;
			}
		}
		{
			toml_datum_t d = toml_int_in(sec, "password_memlimit");
			if (d.ok) {
				unsigned long v		   = (unsigned long)d.u.i;
				cfg->password_memlimit = v;
			}
		}
		get_bool(sec, "tls_enabled", &cfg->tls_enabled);
		get_string(sec, "tls_cert_file", cfg->tls_cert_file, sizeof(cfg->tls_cert_file));
		get_string(sec, "tls_key_file", cfg->tls_key_file, sizeof(cfg->tls_key_file));
	}

	/* [sms] */
	toml_table_t* sms = toml_table_in(root, "sms");
	if (sms) {
		get_string(sms, "gateway_url", cfg->sms_gateway_url, sizeof(cfg->sms_gateway_url));
		get_string(sms, "api_key", cfg->sms_api_key, sizeof(cfg->sms_api_key));
	}

	/* [oauth] */
	toml_table_t* oauth = toml_table_in(root, "oauth");
	if (oauth) {
		get_string(oauth, "client_id", cfg->oauth_client_id, sizeof(cfg->oauth_client_id));
		get_string(oauth, "client_secret", cfg->oauth_client_secret, sizeof(cfg->oauth_client_secret));
		get_string_array(oauth, "redirect_uris", cfg->oauth_redirect_uris, sizeof(cfg->oauth_redirect_uris));
		get_string(oauth, "issuer", cfg->oauth_issuer, sizeof(cfg->oauth_issuer));
		get_long(oauth, "auth_code_ttl_ms", &cfg->oauth_auth_code_ttl_ms);
	}

	/* [logging] */
	toml_table_t* logging = toml_table_in(root, "logging");
	if (logging) {
		get_int(logging, "level", &cfg->log_level);
		if (cfg->log_level < LOG_DEBUG)
			cfg->log_level = LOG_DEBUG;
		if (cfg->log_level > LOG_ERROR)
			cfg->log_level = LOG_ERROR;
		get_string(logging, "audit_log_path", cfg->audit_log_path, sizeof(cfg->audit_log_path));
		get_int(logging, "audit_log_max_size_mb", &cfg->audit_log_max_size_mb);
		get_int(logging, "audit_log_max_backups", &cfg->audit_log_max_backups);
		get_bool(logging, "audit_log_rotate_daily", &cfg->audit_log_rotate_daily);
		get_string(logging, "audit_log_secret", cfg->audit_log_secret, sizeof(cfg->audit_log_secret));
	}

	/* [ratelimit] */
	toml_table_t* rl = toml_table_in(root, "ratelimit");
	if (rl) {
		get_int(rl, "max_ips", &cfg->max_ips);
	}

	/* [password_policy] */
	toml_table_t* pp = toml_table_in(root, "password_policy");
	if (pp) {
		get_int(pp, "min_length", &cfg->password_policy.min_length);
		get_int(pp, "max_length", &cfg->password_policy.max_length);
		get_bool(pp, "require_upper", &cfg->password_policy.require_upper);
		get_bool(pp, "require_lower", &cfg->password_policy.require_lower);
		get_bool(pp, "require_digit", &cfg->password_policy.require_digit);
		get_bool(pp, "require_special", &cfg->password_policy.require_special);
		get_int(pp, "expiry_days", &cfg->password_policy.expiry_days);
		get_int(pp, "history_count", &cfg->password_policy.history_count);
	}

	/* Parse [raft] section */
	toml_table_t* raft_table = toml_table_in(root, "raft");
	if (raft_table) {
		toml_datum_t d_enabled = toml_bool_in(raft_table, "enabled");
		if (d_enabled.ok)
			cfg->raft_enabled = d_enabled.u.b;

		toml_datum_t d_id = toml_int_in(raft_table, "node_id");
		if (d_id.ok)
			cfg->raft_node_id = (int)d_id.u.i;

		toml_array_t* nodes_arr = toml_array_in(raft_table, "nodes");
		if (nodes_arr) {
			int n = toml_array_nelem(nodes_arr);
			for (int i = 0; i < n && i < 16; i++) {
				toml_table_t* nt = toml_table_at(nodes_arr, i);
				if (nt) {
					toml_datum_t n_id  = toml_int_in(nt, "id");
					toml_datum_t n_url = toml_string_in(nt, "url");
					if (n_id.ok && n_url.ok) {
						cfg->raft_nodes[cfg->raft_node_count].id = (int)n_id.u.i;
						strncpy(cfg->raft_nodes[cfg->raft_node_count].url, n_url.u.s,
								sizeof(cfg->raft_nodes[0].url) - 1);
						cfg->raft_node_count++;
						free(n_url.u.s);
					}
				}
			}
		}
	}

	toml_free(root);
	return SSO_OK;
}

void sso_config_apply_env(sso_config_t* cfg) {
	if (!cfg)
		return;

	char* val;
#define SSO_STRNCPY_DST(dst, src)                                                                                      \
	do {                                                                                                               \
		sso_strlcpy((dst), (src), sizeof(dst) - 1);                                                                    \
		(dst)[sizeof(dst) - 1] = '\0';                                                                                 \
	} while (0)
	if ((val = getenv("SSO_HOST")))
		SSO_STRNCPY_DST(cfg->host, val);
	if ((val = getenv("SSO_PORT")))
		cfg->port = atoi(val);
	if ((val = getenv("SSO_DATABASE_TYPE")))
		SSO_STRNCPY_DST(cfg->database_type, val);
	if ((val = getenv("SSO_DATABASE_URL")))
		SSO_STRNCPY_DST(cfg->database_url, val);
	if ((val = getenv("SSO_TOKEN_SECRET")))
		SSO_STRNCPY_DST(cfg->token_secret, val);
	if ((val = getenv("SSO_PRIVATE_KEY")))
		SSO_STRNCPY_DST(cfg->private_key_pem, val);
	if ((val = getenv("SSO_PUBLIC_KEY")))
		SSO_STRNCPY_DST(cfg->public_key_pem, val);
	if ((val = getenv("SSO_ADMIN_PASSWORD")))
		SSO_STRNCPY_DST(cfg->admin_password, val);
	if ((val = getenv("SSO_SMS_GATEWAY_URL")))
		SSO_STRNCPY_DST(cfg->sms_gateway_url, val);
	if ((val = getenv("SSO_SMS_API_KEY")))
		SSO_STRNCPY_DST(cfg->sms_api_key, val);
	{
		const char* ev = getenv("SSO_PASSWORD_OPSLIMIT");
		if (ev)
			cfg->password_opslimit = (unsigned long)atol(ev);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_MEMLIMIT");
		if (ev)
			cfg->password_memlimit = (unsigned long)atol(ev);
	}
	{
		const char* ev = getenv("SSO_LOG_LEVEL");
		if (ev) {
			cfg->log_level = atoi(ev);
			if (cfg->log_level < LOG_DEBUG)
				cfg->log_level = LOG_DEBUG;
			if (cfg->log_level > LOG_ERROR)
				cfg->log_level = LOG_ERROR;
		}
	}
	{
		const char* ev = getenv("SSO_LOG_FORMAT");
		if (ev)
			cfg->log_format = atoi(ev);
	}
	if ((val = getenv("SSO_AUDIT_LOG_PATH")))
		SSO_STRNCPY_DST(cfg->audit_log_path, val);
	if ((val = getenv("SSO_REQUEST_TIMEOUT_MS")))
		cfg->request_timeout_ms = atoi(val);
	if ((val = getenv("SSO_MAX_BODY_SIZE")))
		cfg->max_body_size = atol(val);
	if ((val = getenv("SSO_TLS_ENABLED")))
		cfg->tls_enabled = (strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0);
	if ((val = getenv("SSO_TLS_CERT_FILE")))
		SSO_STRNCPY_DST(cfg->tls_cert_file, val);
	if ((val = getenv("SSO_TLS_KEY_FILE")))
		SSO_STRNCPY_DST(cfg->tls_key_file, val);
	if ((val = getenv("SSO_OAUTH_CLIENT_ID")))
		SSO_STRNCPY_DST(cfg->oauth_client_id, val);
	if ((val = getenv("SSO_OAUTH_CLIENT_SECRET")))
		SSO_STRNCPY_DST(cfg->oauth_client_secret, val);
	if ((val = getenv("SSO_OAUTH_REDIRECT_URIS")))
		SSO_STRNCPY_DST(cfg->oauth_redirect_uris, val);
	if ((val = getenv("SSO_OAUTH_ISSUER")))
		SSO_STRNCPY_DST(cfg->oauth_issuer, val);
	{
		char* ev = getenv("SSO_OAUTH_AUTH_CODE_TTL_MS");
		if (ev)
			cfg->oauth_auth_code_ttl_ms = atol(ev);
	}

	/* [password_policy] environment overrides */
	{
		const char* ev = getenv("SSO_PASSWORD_MIN_LENGTH");
		if (ev)
			cfg->password_policy.min_length = atoi(ev);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_MAX_LENGTH");
		if (ev)
			cfg->password_policy.max_length = atoi(ev);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_REQUIRE_UPPER");
		if (ev)
			cfg->password_policy.require_upper = (strcmp(ev, "1") == 0 || strcasecmp(ev, "true") == 0);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_REQUIRE_LOWER");
		if (ev)
			cfg->password_policy.require_lower = (strcmp(ev, "1") == 0 || strcasecmp(ev, "true") == 0);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_REQUIRE_DIGIT");
		if (ev)
			cfg->password_policy.require_digit = (strcmp(ev, "1") == 0 || strcasecmp(ev, "true") == 0);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_REQUIRE_SPECIAL");
		if (ev)
			cfg->password_policy.require_special = (strcmp(ev, "1") == 0 || strcasecmp(ev, "true") == 0);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_EXPIRY_DAYS");
		if (ev)
			cfg->password_policy.expiry_days = atoi(ev);
	}
	{
		const char* ev = getenv("SSO_PASSWORD_HISTORY_COUNT");
		if (ev)
			cfg->password_policy.history_count = atoi(ev);
	}
#undef SSO_STRNCPY_DST
}
