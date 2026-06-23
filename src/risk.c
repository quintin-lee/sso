/*
 * risk.c — Login risk assessment engine.
 *
 * Evaluates login requests for suspicious activity using a set of
 * heuristic checks: failed-attempt rate per IP, known-device tracking
 * via user-agent hash, and impossible-travel detection between
 * geographically distant logins within a short time window.  Results
 * may trigger MFA challenges or account lockout.
 */

#include "risk.h"
#include "logger.h"
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <math.h>

#define CACHE_SETS 1024
#define CACHE_WAYS 4
#define FAIL_WINDOW_SEC 900		  // 15 minutes
#define IMPOSSIBLE_TRAVEL_SEC 300 // 5 minutes

typedef struct {
	char			ip[46]; /* IPv6 max length */
	int				failed_count;
	sso_timestamp_t last_fail_ms;
} risk_ip_record_t;

typedef struct {
	sso_id_t		user_id;
	char			last_success_ip[46];
	uint32_t		last_success_ua_hash;
	sso_timestamp_t last_success_ms;
} risk_user_record_t;

static risk_ip_record_t	  g_ip_records[CACHE_SETS][CACHE_WAYS];
static risk_user_record_t g_user_records[CACHE_SETS][CACHE_WAYS];
static pthread_mutex_t	  g_risk_lock = PTHREAD_MUTEX_INITIALIZER;

/* AI / ML Anomaly Detection (EMA + Z-Score) State */
static double		   g_global_login_velocity_ema = 1.0;
static double		   g_global_login_velocity_var = 0.1;
static sso_timestamp_t g_last_login_ms			   = 0;

static uint32_t simple_hash(const char* str) {
	if (!str)
		return 0;
	uint32_t hash = 5381;
	int		 c;
	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;
	return hash;
}

static int is_same_subnet_ipv4(const char* ip1, const char* ip2) {
	if (!ip1 || !ip2)
		return 0;
	const char* dot1 = strrchr(ip1, '.');
	const char* dot2 = strrchr(ip2, '.');
	if (dot1 && dot2 && (dot1 - ip1 == dot2 - ip2)) {
		return (strncmp(ip1, ip2, dot1 - ip1) == 0);
	}
	return 0;
}

int risk_evaluate_login(sso_id_t user_id, const char* ip, const char* user_agent) {
	if (!ip)
		return RISK_SCORE_LOW;

	int				score	= RISK_SCORE_LOW;
	sso_timestamp_t now		= sso_timestamp_now();
	uint32_t		ua_hash = simple_hash(user_agent);

	pthread_mutex_lock(&g_risk_lock);

	/* --- AI Anomaly Scoring (Z-Score of login velocity) --- */
	if (g_last_login_ms > 0) {
		double delta_s = (now - g_last_login_ms) / 1000.0;
		if (delta_s < 0.001)
			delta_s = 0.001; // max velocity cap
		double velocity = 1.0 / delta_s;

		// Update EMA
		double alpha = 0.05;
		double diff	 = velocity - g_global_login_velocity_ema;
		g_global_login_velocity_ema += alpha * diff;
		g_global_login_velocity_var = (1.0 - alpha) * (g_global_login_velocity_var + alpha * diff * diff);

		double stddev = sqrt(g_global_login_velocity_var);
		if (stddev > 0.01) {
			double z_score = (velocity - g_global_login_velocity_ema) / stddev;
			if (z_score > 3.0) {
				score += (int)(z_score * 5); // Anomalous spike in velocity (Botnet attack)
				LOG_WARN("[risk] AI Anomaly detected: Z-Score = %.2f (Velocity spike)", z_score);
			}
		}
	}
	g_last_login_ms = now;
	/* ------------------------------------------------------- */

	/* 1. Check IP failure history */
	uint32_t ip_set = simple_hash(ip) % CACHE_SETS;
	for (int w = 0; w < CACHE_WAYS; w++) {
		if (g_ip_records[ip_set][w].ip[0] &&
			strncmp(g_ip_records[ip_set][w].ip, ip, sizeof(g_ip_records[0][0].ip)) == 0) {
			if (now - g_ip_records[ip_set][w].last_fail_ms < FAIL_WINDOW_SEC * 1000) {
				if (g_ip_records[ip_set][w].failed_count >= 10)
					score += 100;
				else if (g_ip_records[ip_set][w].failed_count >= 5)
					score += 60;
				else if (g_ip_records[ip_set][w].failed_count >= 3)
					score += 30;
			}
			break;
		}
	}

	/* 2. Check User History */
	uint32_t user_set = user_id % CACHE_SETS;
	for (int w = 0; w < CACHE_WAYS; w++) {
		if (g_user_records[user_set][w].user_id == user_id) {
			risk_user_record_t* rec = &g_user_records[user_set][w];

			/* User-Agent Check */
			if (rec->last_success_ua_hash != ua_hash) {
				score += 20;
			}

			/* IP Check */
			if (strncmp(rec->last_success_ip, ip, sizeof(rec->last_success_ip)) != 0) {
				if (is_same_subnet_ipv4(rec->last_success_ip, ip)) {
					score += 10; /* Same subnet, minor risk */
				} else {
					score += 30; /* Different IP entirely */

					/* Impossible travel check */
					if (now - rec->last_success_ms < IMPOSSIBLE_TRAVEL_SEC * 1000) {
						score += 40;
						LOG_WARN("[risk] Impossible travel detected for user %lld from %s to %s", (long long)user_id,
								 rec->last_success_ip, ip);
					}
				}
			}
			break;
		}
	}

	pthread_mutex_unlock(&g_risk_lock);

	if (score > 100)
		score = 100;

	if (score >= RISK_SCORE_HIGH) {
		LOG_WARN("[risk] High risk login attempt detected: user_id=%lld, ip=%s, ua=%s, score=%d", (long long)user_id,
				 ip, user_agent ? user_agent : "null", score);
	}
	return score;
}

void risk_record_login_attempt(sso_id_t user_id, const char* ip, int success) {
	if (!ip)
		return;

	sso_timestamp_t now = sso_timestamp_now();
	pthread_mutex_lock(&g_risk_lock);

	/* Update IP Records */
	uint32_t		ip_set		   = simple_hash(ip) % CACHE_SETS;
	int				ip_w		   = -1;
	int				oldest_ip_w	   = 0;
	sso_timestamp_t oldest_ip_time = now;

	for (int w = 0; w < CACHE_WAYS; w++) {
		if (g_ip_records[ip_set][w].ip[0] &&
			strncmp(g_ip_records[ip_set][w].ip, ip, sizeof(g_ip_records[0][0].ip)) == 0) {
			ip_w = w;
			break;
		}
		if (!g_ip_records[ip_set][w].ip[0]) {
			ip_w = w; /* empty slot */
		}
		if (g_ip_records[ip_set][w].last_fail_ms < oldest_ip_time) {
			oldest_ip_time = g_ip_records[ip_set][w].last_fail_ms;
			oldest_ip_w	   = w;
		}
	}

	if (ip_w == -1)
		ip_w = oldest_ip_w; /* Evict LRU */

	if (success) {
		/* Clear fail count on success */
		if (strncmp(g_ip_records[ip_set][ip_w].ip, ip, sizeof(g_ip_records[0][0].ip)) == 0) {
			g_ip_records[ip_set][ip_w].failed_count = 0;
		}

		/* Update User Records */
		uint32_t		user_set		= user_id % CACHE_SETS;
		int				usr_w			= -1;
		int				oldest_usr_w	= 0;
		sso_timestamp_t oldest_usr_time = now;

		for (int w = 0; w < CACHE_WAYS; w++) {
			if (g_user_records[user_set][w].user_id == user_id) {
				usr_w = w;
				break;
			}
			if (g_user_records[user_set][w].user_id == 0) {
				usr_w = w; /* empty slot */
			}
			if (g_user_records[user_set][w].last_success_ms < oldest_usr_time) {
				oldest_usr_time = g_user_records[user_set][w].last_success_ms;
				oldest_usr_w	= w;
			}
		}

		if (usr_w == -1)
			usr_w = oldest_usr_w;

		g_user_records[user_set][usr_w].user_id = user_id;
		sso_strlcpy(g_user_records[user_set][usr_w].last_success_ip, ip, sizeof(g_user_records[0][0].last_success_ip));
		g_user_records[user_set][usr_w].last_success_ua_hash = 0; /* Will fix this next */
		g_user_records[user_set][usr_w].last_success_ms		 = now;

	} else {
		/* Record failure */
		if (strncmp(g_ip_records[ip_set][ip_w].ip, ip, sizeof(g_ip_records[0][0].ip)) != 0) {
			sso_strlcpy(g_ip_records[ip_set][ip_w].ip, ip, sizeof(g_ip_records[0][0].ip));
			g_ip_records[ip_set][ip_w].failed_count = 1;
		} else {
			if (now - g_ip_records[ip_set][ip_w].last_fail_ms > FAIL_WINDOW_SEC * 1000) {
				g_ip_records[ip_set][ip_w].failed_count = 1;
			} else {
				g_ip_records[ip_set][ip_w].failed_count++;
			}
		}
		g_ip_records[ip_set][ip_w].last_fail_ms = now;
	}

	pthread_mutex_unlock(&g_risk_lock);
}

void risk_record_login_success_with_ua(sso_id_t user_id, const char* ip, const char* user_agent) {
	if (!ip)
		return;
	sso_timestamp_t now		= sso_timestamp_now();
	uint32_t		ua_hash = simple_hash(user_agent);

	pthread_mutex_lock(&g_risk_lock);
	uint32_t		user_set		= user_id % CACHE_SETS;
	int				usr_w			= -1;
	int				oldest_usr_w	= 0;
	sso_timestamp_t oldest_usr_time = now;

	for (int w = 0; w < CACHE_WAYS; w++) {
		if (g_user_records[user_set][w].user_id == user_id) {
			usr_w = w;
			break;
		}
		if (g_user_records[user_set][w].user_id == 0) {
			usr_w = w;
		}
		if (g_user_records[user_set][w].last_success_ms < oldest_usr_time) {
			oldest_usr_time = g_user_records[user_set][w].last_success_ms;
			oldest_usr_w	= w;
		}
	}

	if (usr_w == -1)
		usr_w = oldest_usr_w;

	g_user_records[user_set][usr_w].user_id = user_id;
	sso_strlcpy(g_user_records[user_set][usr_w].last_success_ip, ip, sizeof(g_user_records[0][0].last_success_ip));
	g_user_records[user_set][usr_w].last_success_ua_hash = ua_hash;
	g_user_records[user_set][usr_w].last_success_ms		 = now;

	pthread_mutex_unlock(&g_risk_lock);
}
