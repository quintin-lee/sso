#include "risk.h"
#include "logger.h"
#include <string.h>
#include <pthread.h>

#define MAX_TRACKED_IPS 1024
#define FAIL_WINDOW_SEC 900 // 15 minutes

typedef struct {
    char ip[46]; /* IPv6 max length */
    int failed_count;
    sso_timestamp_t last_fail_ms;
} risk_ip_record_t;

typedef struct {
    sso_id_t user_id;
    char last_success_ip[46];
} risk_user_record_t;

static risk_ip_record_t g_ip_records[MAX_TRACKED_IPS];
static risk_user_record_t g_user_records[MAX_TRACKED_IPS];
static pthread_mutex_t g_risk_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t simple_hash(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash;
}

int risk_evaluate_login(sso_id_t user_id, const char *ip, const char *user_agent) {
    (void)user_agent; /* Reserved for future fingerprinting */
    if (!ip) return RISK_SCORE_LOW;

    int score = RISK_SCORE_LOW;
    sso_timestamp_t now = sso_timestamp_now();

    pthread_mutex_lock(&g_risk_lock);

    /* 1. Check IP failure history */
    uint32_t ip_idx = simple_hash(ip) % MAX_TRACKED_IPS;
    if (strncmp(g_ip_records[ip_idx].ip, ip, sizeof(g_ip_records[0].ip)) == 0) {
        if (now - g_ip_records[ip_idx].last_fail_ms < FAIL_WINDOW_SEC * 1000) {
            if (g_ip_records[ip_idx].failed_count >= 5) {
                score += 60; /* Very high risk, likely brute force */
            } else if (g_ip_records[ip_idx].failed_count >= 2) {
                score += 30; /* Elevated risk */
            }
        }
    }

    /* 2. Check unfamiliar IP for the user */
    uint32_t user_idx = user_id % MAX_TRACKED_IPS;
    if (g_user_records[user_idx].user_id == user_id) {
        if (strncmp(g_user_records[user_idx].last_success_ip, ip, sizeof(g_user_records[0].last_success_ip)) != 0) {
            score += 40; /* Different from last successful login IP */
        }
    }

    pthread_mutex_unlock(&g_risk_lock);

    if (score > 100) score = 100;
    
    if (score >= RISK_SCORE_HIGH) {
        LOG_WARN("[risk] High risk login attempt detected: user_id=%lld, ip=%s, score=%d", (long long)user_id, ip, score);
    }
    return score;
}

void risk_record_login_attempt(sso_id_t user_id, const char *ip, int success) {
    if (!ip) return;

    sso_timestamp_t now = sso_timestamp_now();
    uint32_t ip_idx = simple_hash(ip) % MAX_TRACKED_IPS;
    uint32_t user_idx = user_id % MAX_TRACKED_IPS;

    pthread_mutex_lock(&g_risk_lock);

    if (success) {
        /* Record successful IP for the user */
        g_user_records[user_idx].user_id = user_id;
        sso_strlcpy(g_user_records[user_idx].last_success_ip, ip, sizeof(g_user_records[0].last_success_ip));
        g_user_records[user_idx].last_success_ip[sizeof(g_user_records[0].last_success_ip) - 1] = '\0';
        
        /* Clear failure history on successful login */
        if (strncmp(g_ip_records[ip_idx].ip, ip, sizeof(g_ip_records[0].ip)) == 0) {
            g_ip_records[ip_idx].failed_count = 0;
        }
    } else {
        /* Record failure for the IP */
        if (strncmp(g_ip_records[ip_idx].ip, ip, sizeof(g_ip_records[0].ip)) != 0) {
            sso_strlcpy(g_ip_records[ip_idx].ip, ip, sizeof(g_ip_records[0].ip));
            g_ip_records[ip_idx].ip[sizeof(g_ip_records[0].ip) - 1] = '\0';
            g_ip_records[ip_idx].failed_count = 1;
        } else {
            if (now - g_ip_records[ip_idx].last_fail_ms > FAIL_WINDOW_SEC * 1000) {
                g_ip_records[ip_idx].failed_count = 1; /* reset window */
            } else {
                g_ip_records[ip_idx].failed_count++;
            }
        }
        g_ip_records[ip_idx].last_fail_ms = now;
    }

    pthread_mutex_unlock(&g_risk_lock);
}
