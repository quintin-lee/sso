# MFA and Refresh Tokens Design

## Objective
Enhance the SSO system by replacing stateless JWT refresh tokens with secure, opaque, database-backed refresh tokens, and implement a robust TOTP-based Multi-Factor Authentication (MFA) flow.

## 1. Database & Storage Architecture

### Refresh Tokens Table
Refresh tokens will be opaque, cryptographically secure random strings. We will store their SHA-256 hash in the database to prevent token compromise in the event of a database leak.

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    client_id TEXT,
    expires_at INTEGER NOT NULL,
    issued_at INTEGER NOT NULL,
    revoked INTEGER DEFAULT 0
);
```

### User Table Modifications
MFA configurations are core security properties. The `users` table will be updated with:
- `mfa_enabled INTEGER DEFAULT 0`
- `mfa_secret TEXT DEFAULT ''` (Base32 encoded TOTP secret)

### Storage Interface (`storage.h`)
The `storage_backend_t` will be extended with:
- `storage_refresh_token_create`
- `storage_refresh_token_get`
- `storage_refresh_token_revoke`

## 2. Token Issuance & Management

- **Access Tokens:** Remain as stateless JWTs (HS256 or RS256).
- **Refresh Tokens:** A 32-byte random string, hex or base64url encoded.
  - When `token_issue` is called, alongside the JWT, it generates this opaque string, hashes it, stores the record in `refresh_tokens`, and returns the raw string to the client.
- **Revocation:** `POST /api/v1/oauth/revoke` will be updated. If the provided token is a refresh token, it will set `revoked = 1` in the database.

## 3. MFA (TOTP) API & Flow

### Setup Endpoints
*(Requires an active Access Token without MFA restrictions)*
1. `POST /api/v1/auth/mfa/setup`:
   - Generates a random 20-byte secret, encodes it to Base32.
   - Returns `{"secret": "BASE32...", "uri": "otpauth://totp/SSO:user?secret=..."}`.
2. `POST /api/v1/auth/mfa/enable`:
   - Accepts `{"secret": "...", "code": "123456"}`.
   - Validates the 6-digit TOTP code using OpenSSL HMAC-SHA1.
   - If valid, updates the user's `mfa_secret` and sets `mfa_enabled = 1`.

### Two-Step Login Flow
When hitting `POST /api/v1/auth/login` or `POST /api/v1/oauth/token` (password grant):
1. **Initial Verification:**
   - Server verifies username and password.
   - If `mfa_enabled == 1`, the server halts token issuance.
   - Generates a short-lived (e.g., 5 min) JWT containing a special claim: `"mfa_pending": true`.
   - Returns HTTP `401 Unauthorized` (or `403 Forbidden`) with body:
     `{"error": "mfa_required", "mfa_token": "<SHORT_LIVED_JWT>"}`

2. **MFA Verification (`POST /api/v1/auth/mfa/verify`):**
   - Client prompts user for the 6-digit code.
   - Client sends `{"mfa_token": "...", "code": "123456"}`.
   - Server verifies the `mfa_token` signature and checks the `"mfa_pending"` claim.
   - Server extracts `user_id`, loads the user's `mfa_secret`, and validates the TOTP code.
   - If successful, generates and returns the final Access Token (without the `mfa_pending` claim) and a new opaque Refresh Token.

## 4. Dependencies
- Base32 encoding/decoding helper will be added.
- OpenSSL's HMAC (`<openssl/hmac.h>`) will be used for the TOTP HMAC-SHA1 algorithm.
- SQLite migration logic will handle adding the new columns and tables.