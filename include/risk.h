#ifndef SSO_RISK_H
#define SSO_RISK_H

#include "sso.h"

/* Risk score thresholds */
#define RISK_SCORE_LOW      0
#define RISK_SCORE_MEDIUM   40
#define RISK_SCORE_HIGH     80

/* 
 * Evaluates the login risk for a given user, IP, and User-Agent.
 * Returns a risk score from 0 to 100.
 */
int risk_evaluate_login(sso_id_t user_id, const char *ip, const char *user_agent);

/* 
 * Records a login attempt outcome for the risk engine to learn from.
 * success: 1 if authentication succeeded, 0 if failed (e.g. wrong password).
 */
void risk_record_login_attempt(sso_id_t user_id, const char *ip, int success);

/* 
 * Records a successful login attempt along with the User-Agent 
 * to build the user's device fingerprint history.
 */
void risk_record_login_success_with_ua(sso_id_t user_id, const char *ip, const char *user_agent);

#endif /* SSO_RISK_H */
