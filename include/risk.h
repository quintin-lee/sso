/*
 * risk.h — Login risk assessment engine.
 *
 * Evaluates login attempts based on historical patterns:
 *   - Known IP vs new IP (geo-anomaly detection)
 *   - Failed attempt rate from this IP / for this user
 *   - Known device (User-Agent fingerprint) vs unknown device
 *
 * Returns a risk score 0–100 used to trigger MFA challenges or
 * block the login attempt entirely.
 */

#ifndef SSO_RISK_H
#define SSO_RISK_H

#include "sso.h"

/** Risk score thresholds for decision-making. */
#define RISK_SCORE_LOW      0   /**< Low risk: proceed without challenge. */
#define RISK_SCORE_MEDIUM   40  /**< Medium risk: prompt for MFA. */
#define RISK_SCORE_HIGH     80  /**< High risk: block or require admin approval. */

/**
 * @brief Evaluate the risk level of a login attempt.
 * @param user_id    The target user account.
 * @param ip         Source IP address of the request.
 * @param user_agent User-Agent header from the HTTP request.
 * @return Risk score 0–100 (0 = safe, 100 = extremely risky).
 */
int risk_evaluate_login(sso_id_t user_id, const char *ip, const char *user_agent);

/**
 * @brief Record a login attempt outcome for the risk engine to learn from.
 * @param user_id  The target user.
 * @param ip       Source IP address.
 * @param success  1 if authentication succeeded, 0 if it failed.
 */
void risk_record_login_attempt(sso_id_t user_id, const char *ip, int success);

/**
 * @brief Record a successful login along with device fingerprint.
 * Builds the user's known-device profile for future risk assessment.
 * @param user_id    The authenticated user.
 * @param ip         Source IP address.
 * @param user_agent User-Agent string from the successful login.
 */
void risk_record_login_success_with_ua(sso_id_t user_id, const char *ip, const char *user_agent);

#endif /* SSO_RISK_H */
