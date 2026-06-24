# SSO System — API Reference Documentation

> **Version**: 1.1.0 | **Protocol**: HTTP/1.1 | **Format**: JSON | **Auth**: Bearer JWT Token

Base URL: `http://<host>:8080`

---

## Table of Contents

1. [Authentication](#1-authentication)
2. [Error Handling](#2-error-handling)
3. [Public Pages](#3-public-pages)
4. [Authentication API](#4-authentication-api)
5. [Permission Check API](#5-permission-check-api)
6. [User Management (Admin)](#6-user-management-admin)
7. [Role Management (Admin)](#7-role-management-admin)
8. [Group Management (Admin)](#8-group-management-admin)
9. [Policy Management (Admin)](#9-policy-management-admin)
10. [OAuth Client Management](#10-oauth-client-management)
11. [Audit & Admin](#11-audit--admin)
12. [OAuth 2.0 / OpenID Connect](#12-oauth-20--openid-connect)
13. [WebAuthn (Passkeys)](#13-webauthn-passkeys)
14. [Multi-Factor Authentication (MFA)](#14-multi-factor-authentication-mfa)
15. [Monitoring](#15-monitoring)
16. [Token & Header Reference](#16-token--header-reference)
17. [Error Codes](#17-error-codes)
18. [cURL Examples](#18-curl-examples)

---

## 1. Authentication

### Token-Based Auth (Default)

Most administrative and permission-check endpoints require a **Bearer JWT token** obtained via login.

**Request Header:**

```
Authorization: Bearer <token>
```

**Token Response Headers:**

After successful login or token refresh, the server returns tokens via custom response headers:

| Header | Description |
|--------|-------------|
| `X-SSO-Access-Token` | JWT access token (15 min default) |
| `X-SSO-Refresh-Token` | Refresh token (7 days default) |

> **Important**: Tokens are delivered in response headers, **not** in the JSON body. Your client must read these headers after login/refresh.

### Token Rotation

The access token can be silently rotated during `GET /api/v1/auth/verify`. If more than half the TTL has passed, the response header `X-SSO-Access-Token` contains a fresh token. Clients should watch for this header and update their stored token.

### DPoP (Demonstration of Proof-of-Possession)

When the client sends a `DPoP` HTTP header, the server binds the token to the client's JWK Thumbprint. Subsequent requests must prove possession of the corresponding private key. This provides sender-constrained access tokens.

- DPoP-bound tokens use `token_type: "DPoP"` instead of `"Bearer"`
- DPoP Proof is sent as the `DPoP` HTTP header
- All authenticated endpoints validate DPoP when the token is bound

### Cookie Auth

For browser-based flows, the server may set a cookie:

```
Set-Cookie: sso_token=<token>; Path=/; HttpOnly; SameSite=Lax
```

### Response Headers (All Responses)

| Header | Description |
|--------|-------------|
| `X-Request-Id` | Unique trace ID for distributed tracing |
| `X-SSO-User` | Current authenticated username |
| `X-SSO-Email` | Current authenticated user email |

---

## 2. Error Handling

All error responses follow a consistent JSON format:

```json
{
  "error": "Human-readable error message"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad Request — missing/invalid parameters |
| `401` | Unauthorized — missing or invalid token |
| `403` | Forbidden — account disabled |
| `404` | Not Found |
| `409` | Conflict — resource already exists |
| `429` | Rate Limit Exceeded |
| `500` | Internal Server Error |

---

## 3. Public Pages

### GET `/`

Serves the embedded HTML login page.

- **Auth**: None
- **Response**: `text/html` — Login page

### GET `/login`

Alias for `/`.

- **Auth**: None
- **Response**: `text/html` — Login page

### GET `/admin`

Serves the embedded admin management page (Vue.js SPA).

- **Auth**: None (the page itself handles auth via JS)
- **Response**: `text/html` — Admin SPA

---

## 4. Authentication API

### POST `/api/v1/auth/register`

Register a new user account.

- **Auth**: None
- **Rate Limit**: N/A

**Request Body:**

```json
{
  "username": "johndoe",
  "password": "SecureP@ss1",
  "email": "john@example.com",
  "display_name": "John Doe"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | ✅ | Unique username (max 64 chars) |
| `password` | string | ✅ | Min 8 chars, must include uppercase, lowercase, digit, special character |
| `email` | string | ❌ | Email address |
| `display_name` | string | ❌ | Display name (defaults to username) |

**Response `200`:**

```json
{
  "user_id": 42,
  "username": "johndoe",
  "created": true
}
```

**Error `409`:** Username already exists.

---

### POST `/api/v1/auth/login`

Password-based login.

- **Auth**: None
- **Rate Limit**: 5 requests/min/IP

**Request Body:**

```json
{
  "username": "johndoe",
  "password": "SecureP@ss1"
}
```

**Response `200` (Standard Login):**

Tokens are returned in **response headers**:

```
X-SSO-Access-Token: <jwt_token>
X-SSO-Refresh-Token: <refresh_token>
```

**JSON Body:**

```json
{
  "expires_in": 900000,
  "user_id": 42,
  "username": "johndoe",
  "display_name": "John Doe"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `expires_in` | number | Token TTL in milliseconds |
| `user_id` | number | User ID |
| `username` | string | Username |
| `display_name` | string | Display name |

**Response `200` (MFA Required):**

```json
{
  "mfa_required": true,
  "mfa_token": "<short-lived-mfa-token>"
}
```

When MFA is required, the client must proceed to `POST /api/v1/auth/mfa/verify` (see [MFA section](#14-multi-factor-authentication-mfa)).

---

### POST `/api/v1/auth/send_sms`

Send an SMS verification code to a phone number.

- **Auth**: None
- **Rate Limit**: 1 request/min/IP

**Request Body:**

```json
{
  "phone": "+8613800138000"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `phone` | string | ✅ | Phone number |

**Response `200`:**

```json
{
  "status": "sent"
}
```

---

### POST `/api/v1/auth/login_by_sms`

Login using SMS verification code. If the phone number is not registered, an account is auto-created.

- **Auth**: None
- **Rate Limit**: 5 requests/min/IP (IP-level) + 3 requests/min/phone (phone-level)

**Request Body:**

```json
{
  "phone": "+8613800138000",
  "code": "123456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `phone` | string | ✅ | Phone number |
| `code` | string | ✅ | 6-digit SMS code |

**Response `200`:**

```json
{
  "token": "<jwt_token>",
  "user_id": 42,
  "username": "user_13800138000",
  "phone": "+8613800138000"
}
```

---

### GET `/api/v1/auth/verify`

Validate a token. Also triggers silent token rotation when >50% of TTL has passed.

- **Auth**: Bearer token (or via query param)
- **Alternate**: `POST /api/v1/auth/verify` (same behavior)

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | ❌ | Token string (also accepted in JSON body for POST) |

**Response `200`:**

```json
{
  "valid": true,
  "user_id": 42,
  "username": "johndoe",
  "email": "john@example.com",
  "display_name": "John Doe",
  "expires_at": 1712345678000
}
```

**Silent Rotation Header (when triggered):**

```
X-SSO-Access-Token: <new_jwt_token>
```

---

### POST `/api/v1/auth/refresh`

Refresh the access token using a refresh token.

- **Auth**: Bearer token (optional — token from body is used)

**Request Body:**

```json
{
  "refresh_token": "<refresh_token_string>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | ✅ | Refresh token obtained from login |

**Response `200`:**

```
Headers:
  X-SSO-Access-Token: <new_access_token>
  X-SSO-Refresh-Token: <new_refresh_token>

Body:
{
  "status": "refreshed"
}
```

The frontend interceptor uses this flow automatically on `401` responses (see [Token & Header Reference](#16-token--header-reference)).

---

### POST `/api/v1/auth/logout`

Revoke the current token.

- **Auth**: Bearer token required

**Response `200`:**

```json
{
  "logged_out": true
}
```

---

### POST `/api/v1/auth/logout_all`

Revoke all tokens for the current user (all sessions).

- **Auth**: Bearer token required

**Response `200`:**

```json
{
  "logged_out_all": true
}
```

---

### POST `/api/v1/auth/password`

Change password for the current authenticated user.

- **Auth**: Bearer token required

**Request Body:**

```json
{
  "password": "NewSecureP@ss1"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `password` | string | ✅ | New password (8+ chars, must include uppercase, lowercase, digit, special) |

**Response `200`:**

```json
{
  "updated": true
}
```

---

### GET `/api/v1/auth/me`

Get the current authenticated user's basic profile.

- **Auth**: Bearer token required

**Response `200`:**

```json
{
  "id": 42,
  "username": "johndoe",
  "email": "john@example.com",
  "display_name": "John Doe",
  "token_jti": "abc123..."
}
```

---

### GET `/api/v1/auth/certs`

Get RSA public keys in PEM format for token verification (RS256 mode only).

- **Auth**: None

**Response `200`:**

```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "alg": "RS256"
}
```

**Error `404`:** Server not in RS256 mode (i.e., using HS256).

---

### GET `/api/v1/auth/jwks`

JWKS (JSON Web Key Set) endpoint — RFC 7517.

- **Auth**: None

Returns all populated key slots. When dual-key rotation is active, both keys are exposed so clients can verify tokens signed before rotation.

**Response `200`:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "sso-key-1",
      "n": "...",
      "e": "AQAB",
      "alg": "RS256"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "sso-key-2",
      "n": "...",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}
```

---

### POST `/api/v1/auth/rotate-keys`

Rotate signing keys with zero-downtime. New tokens are signed with the fresh key; tokens signed before rotation remain verifiable until they expire.

- **Auth**: Bearer token required (admin)

**Request Body:** (either HMAC or RSA payload)

```json
{
  "secret": "64-hex-char-new-secret"
}
```

or

```json
{
  "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**Response `200`:**

```json
{
  "rotated": true,
  "active_kid": "sso-key-2",
  "standby_kid": "sso-key-1"
}
```

---

### GET `/api/v1/auth/userinfo`

OIDC UserInfo endpoint — returns standard OIDC claims.

- **Auth**: Bearer token required

**Response `200`:**

```json
{
  "sub": "42",
  "name": "John Doe",
  "preferred_username": "johndoe",
  "email": "john@example.com"
}
```

---

### GET `/api/v1/auth/session-check`

Nginx `auth_request` endpoint. Validates the Bearer token and returns user identity via response headers. Designed for nginx's `auth_request` directive.

- **Auth**: Bearer token (expected from nginx `proxy_set_header`)

**Response `200`:**

```
Headers:
  X-SSO-User: johndoe
  X-SSO-Email: john@example.com
  X-SSO-User-Id: 42

Body:
{
  "active": true,
  "user_id": 42,
  "username": "johndoe",
  "email": "john@example.com"
}
```

---

## 5. Permission Check API

All permission check endpoints require authentication (Bearer token).

Each endpoint evaluates a specific strategy and returns `{"allowed": true/false}`.

### POST `/api/v1/check`

Unified permission check — evaluates across all strategies.

**Request Body:**

```json
{
  "user_id": 42,
  "function_code": "order:create",
  "api_method": "POST",
  "api_path": "/api/orders",
  "resource_type": "order",
  "record": "{\"amount\": 1000}",
  "role_name": "admin",
  "source_ip": "192.168.1.1",
  "geo_country": "CN",
  "lbac_user_labels": "confidential,finance",
  "lbac_resource_label": "confidential",
  "abac_subject_attrs": "{\"department\":\"engineering\",\"level\":\"senior\"}",
  "abac_resource_attrs": "{\"classification\":\"internal\",\"region\":\"us\"}",
  "abac_action": "read",
  "environment": "{\"time\":\"09:00-18:00\",\"location\":\"office\"}"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | number | ❌ | Target user ID (defaults to auth user) |
| `function_code` | string | ❌ | Functional permission code (e.g., `"order:create"`) |
| `api_method` | string | ❌ | HTTP method for API strategy |
| `api_path` | string | ❌ | Request path for API strategy |
| `resource_type` | string | ❌ | Resource type (e.g., `"order"`, `"customer"`) |
| `record` | string | ❌ | JSON string of record for data scope evaluation |
| `role_name` | string | ❌ | Role name for RBAC check |
| `source_ip` | string | ❌ | Source IP for location check |
| `geo_country` | string | ❌ | ISO country code for location check |
| `lbac_user_labels` | string | ❌ | Comma-separated user labels for LBAC |
| `lbac_resource_label` | string | ❌ | Resource label for LBAC |
| `abac_subject_attrs` | string | ❌ | JSON attributes of the subject for ABAC |
| `abac_resource_attrs` | string | ❌ | JSON attributes of the resource for ABAC |
| `abac_action` | string | ❌ | Action being performed for ABAC |
| `environment` | string | ❌ | JSON environment attributes |

**Response `200`:**

```json
{
  "allowed": true,
  "allowed_fields": ["field1", "field2"],
  "trace": "Policy 'order-access' (ALLOW) via RBAC strategy\n  → role 'admin' matched\n  → ALLOW decision propagated"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | Whether access is permitted |
| `allowed_fields` | string[] | Allowed fields (data scope strategy only) |
| `trace` | string | Evaluation trace for debugging |

---

### POST `/api/v1/check/functional`

Check a functional permission (menu/button/feature access).

**Request Body:**

```json
{
  "user_id": 42,
  "function_code": "order:create"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | number | ❌ | Defaults to authenticated user |
| `function_code` | string | ✅ | Function code to check (supports wildcards) |

**Response `200`:**

```json
{
  "allowed": true,
  "user_id": 42,
  "function": "order:create"
}
```

---

### POST `/api/v1/check/api`

Check API endpoint access (HTTP method + path matching).

**Request Body:**

```json
{
  "method": "POST",
  "path": "/api/orders",
  "user_id": 42
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | ✅ | HTTP method (`GET`, `POST`, `PUT`, `DELETE`, etc.) |
| `path` | string | ✅ | API path (supports `*`, `**`, `:param` wildcards) |
| `user_id` | number | ❌ | Defaults to authenticated user |

**Response `200`:**

```json
{
  "allowed": true,
  "user_id": 42
}
```

---

### POST `/api/v1/check/data`

Check data scope access (row/field-level filtering).

**Request Body:**

```json
{
  "resource_type": "order",
  "record": "{\"amount\": 1000, \"region\": \"us\"}",
  "user_id": 42
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resource_type` | string | ✅ | Type of resource to access |
| `record` | string | ❌ | JSON string of the record being accessed |
| `user_id` | number | ❌ | Defaults to authenticated user |

**Response `200`:**

```json
{
  "allowed": true,
  "user_id": 42,
  "fields": ["name", "email", "amount"]
}
```

When access is allowed to a subset of fields, `fields` contains the whitelist.

---

### POST `/api/v1/check/rbac`

Check role membership.

**Request Body:**

```json
{
  "role_name": "admin",
  "user_id": 42
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `role_name` | string | ✅ | Role name to check |
| `user_id` | number | ❌ | Defaults to authenticated user |

**Response `200`:**

```json
{
  "allowed": true,
  "user_id": 42,
  "role": "admin"
}
```

Supports recursive role hierarchy — ancestor roles are inherited.

---

### POST `/api/v1/check/location`

Check IP/geo-based access.

**Request Body:**

```json
{
  "source_ip": "192.168.1.100",
  "geo_country": "CN",
  "user_id": 42
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_ip` | string | ✅ | Source IP address |
| `geo_country` | string | ❌ | ISO country code |
| `user_id` | number | ❌ | Defaults to authenticated user |

**Response `200`:**

```json
{
  "allowed": true,
  "user_id": 42,
  "source_ip": "192.168.1.100"
}
```

---

### POST `/api/v1/check/lbac`

Check label-based access control (MLS-style clearance).

**Request Body:**

```json
{
  "user_labels": "confidential,finance",
  "resource_label": "confidential",
  "user_id": 42
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_labels` | string | ✅ | Comma-separated user security labels |
| `resource_label` | string | ✅ | Required label for the resource |
| `user_id` | number | ❌ | Defaults to authenticated user |

**Response `200`:**

```json
{
  "allowed": true,
  "user_id": 42,
  "user_labels": "confidential,finance",
  "resource_label": "confidential"
}
```

---

### POST `/api/v1/check/abac`

Check attribute-based access control.

**Request Body:**

```json
{
  "subject_attrs": "{\"department\":\"engineering\",\"level\":\"senior\"}",
  "resource_attrs": "{\"classification\":\"internal\",\"region\":\"us\"}",
  "action": "read",
  "user_id": 42
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subject_attrs` | string | ❌ | JSON attributes of the requesting subject |
| `resource_attrs` | string | ❌ | JSON attributes of the target resource |
| `action` | string | ❌ | Action being performed (e.g., `"read"`, `"write"`) |
| `user_id` | number | ❌ | Defaults to authenticated user |

**Response `200`:**

```json
{
  "allowed": true,
  "user_id": 42
}
```

---

## 6. User Management (Admin)

All user management endpoints require authentication (Bearer token) with appropriate permissions.

### GET `/api/v1/users`

List users with pagination and search.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | `1` | Page number (1-indexed) |
| `limit` | int | `20` | Items per page (max: 100) |
| `q` | string | — | Search query (matches username/email/display name) |
| `status` | int | — | Filter by status (0=inactive, 1=active, 2=locked) |

**Response `200`:**

```json
{
  "total": 100,
  "page": 1,
  "limit": 20,
  "items": [
    {
      "id": 42,
      "username": "johndoe",
      "email": "john@example.com",
      "display_name": "John Doe",
      "phone": "+8613800138000",
      "status": 1,
      "roles": [
        { "id": 1, "name": "admin" },
        { "id": 2, "name": "editor" }
      ],
      "groups": [
        { "id": 1, "name": "engineering" }
      ],
      "created_at": 1712345678000
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | number | User ID |
| `username` | string | Username |
| `email` | string | Email address |
| `display_name` | string | Display name |
| `phone` | string | Phone number |
| `status` | number | `0`=inactive, `1`=active, `2`=locked |
| `roles` | object[] | Assigned roles (id + name) |
| `groups` | object[] | Group memberships (id + name) |
| `created_at` | number | Unix timestamp in ms |

---

### POST `/api/v1/users`

Create a new user.

**Request Body:**

```json
{
  "username": "johndoe",
  "password": "SecureP@ss1",
  "email": "john@example.com",
  "display_name": "John Doe"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | ✅ | Unique username |
| `password` | string | ✅ | Password meeting policy requirements |
| `email` | string | ❌ | Email address |
| `display_name` | string | ❌ | Display name |

**Response `200`:**

```json
{
  "user_id": 42,
  "username": "johndoe",
  "created": true
}
```

---

### GET `/api/v1/users/{id}`

Get a single user by ID.

**Response `200`:**

```json
{
  "id": 42,
  "username": "johndoe",
  "email": "john@example.com",
  "display_name": "John Doe",
  "phone": "+8613800138000",
  "status": 1,
  "roles": [{ "id": 1, "name": "admin" }],
  "groups": [{ "id": 1, "name": "engineering" }],
  "created_at": 1712345678000
}
```

---

### PUT `/api/v1/users/{id}`

Update a user's fields.

**Request Body:**

```json
{
  "email": "newemail@example.com",
  "display_name": "John Updated",
  "status": 1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `email` | string | New email |
| `display_name` | string | New display name |
| `status` | int | `0`=inactive, `1`=active, `2`=locked |

**Response `200`:**

```json
{
  "updated": true
}
```

---

### DELETE `/api/v1/users/{id}`

Delete a user by ID.

**Response `200`:**

```json
{
  "deleted": true
}
```

---

### GET `/api/v1/users/{id}/policies`

Get all policies directly assigned to a user.

**Response `200`:**

```json
{
  "policies": [
    { "id": 1, "name": "order-admin" },
    { "id": 2, "name": "api-access" }
  ]
}
```

---

## 7. Role Management (Admin)

### GET `/api/v1/roles`

List roles with pagination.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | `1` | Page number |
| `limit` | int | `20` | Items per page (max: 100) |
| `q` | string | — | Search query |
| `status` | int | — | Filter by status |

**Response `200`:**

```json
{
  "total": 10,
  "page": 1,
  "limit": 20,
  "items": [
    {
      "id": 1,
      "name": "admin",
      "description": "System administrator",
      "parent_role_id": 0,
      "parent_name": "",
      "status": 1,
      "created_at": 1712345678000
    }
  ]
}
```

---

### POST `/api/v1/roles`

Create a new role.

**Request Body:**

```json
{
  "name": "editor",
  "description": "Content editor",
  "parent_role_id": 1,
  "status": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✅ | Unique role name |
| `description` | string | ❌ | Role description |
| `parent_role_id` | int | ❌ | Parent role ID for hierarchy (0 = no parent) |
| `status` | int | ❌ | `0`=inactive, `1`=active |

**Response `200`:**

```json
{
  "role_id": 5,
  "name": "editor",
  "created": true
}
```

---

### PUT `/api/v1/roles/{id}`

Update a role.

**Request Body:**

```json
{
  "name": "senior-editor",
  "description": "Senior content editor",
  "parent_role_id": 1,
  "status": 1
}
```

**Response `200`:**

```json
{
  "updated": true
}
```

---

### DELETE `/api/v1/roles/{id}`

Delete a role.

**Response `200`:**

```json
{
  "deleted": true
}
```

---

### POST `/api/v1/roles/{id}/assign`

Assign a role to a user or group.

**Request Body:**

```json
{
  "user_id": 42
}
```

Or to a group:

```json
{
  "group_id": 3
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | int | one-of | User to assign the role to |
| `group_id` | int | one-of | Group to assign the role to |

**Response `200`:**

```json
{
  "assigned": true
}
```

---

### POST `/api/v1/roles/{id}/unassign`

Unassign a role from a user or group.

**Request Body:**

```json
{
  "user_id": 42
}
```

**Response `200`:**

```json
{
  "unassigned": true
}
```

---

## 8. Group Management (Admin)

### GET `/api/v1/groups`

List groups with pagination.

**Query Parameters:** Same pagination as users/roles.

**Response `200`:**

```json
{
  "total": 5,
  "page": 1,
  "limit": 20,
  "items": [
    {
      "id": 1,
      "name": "engineering",
      "description": "Engineering department",
      "parent_group_id": 0,
      "parent_name": "",
      "status": 1,
      "created_at": 1712345678000
    }
  ]
}
```

---

### POST `/api/v1/groups`

Create a group.

**Request Body:**

```json
{
  "name": "engineering",
  "description": "Engineering department",
  "parent_group_id": 0,
  "status": 1
}
```

**Response `200`:**

```json
{
  "id": 1,
  "name": "engineering",
  "created": true
}
```

---

### PUT `/api/v1/groups/{id}`

Update a group.

**Response `200`:**

```json
{
  "updated": true
}
```

---

### DELETE `/api/v1/groups/{id}`

Delete a group.

**Response `200`:**

```json
{
  "deleted": true
}
```

---

### POST `/api/v1/groups/{id}/members`

Add a user to a group.

**Request Body:**

```json
{
  "user_id": 42
}
```

**Response `200`:**

```json
{
  "added": true
}
```

---

### DELETE `/api/v1/groups/{id}/members/{user_id}`

Remove a user from a group.

**Response `200`:**

```json
{
  "removed": true
}
```

---

## 9. Policy Management (Admin)

### GET `/api/v1/policies`

List policies with pagination.

**Response `200`:**

```json
{
  "total": 20,
  "page": 1,
  "limit": 20,
  "items": [
    {
      "id": 1,
      "name": "order-admin-access",
      "strategy_type": 2,
      "strategy_name": "API Endpoint",
      "effect": 1,
      "priority": 100,
      "status": 1,
      "rules": "{\"methods\":[\"GET\",\"POST\"],\"paths\":[\"/api/orders/**\"]}",
      "created_at": 1712345678000
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | number | Policy ID |
| `name` | string | Policy name |
| `strategy_type` | number | `1`=functional, `2`=api, `3`=data, `4`=rbac, `5`=location, `6`=abac, `7`=lbac |
| `strategy_name` | string | Human-readable strategy name |
| `effect` | number | `0`=DENY, `1`=ALLOW |
| `priority` | number | Evaluation priority (higher = evaluated first) |
| `status` | number | `0`=disabled, `1`=enabled |
| `rules` | string | JSON rules (format depends on strategy type) |
| `created_at` | number | Unix timestamp in ms |

---

### POST `/api/v1/policies`

Create a new policy.

**Request Body:**

```json
{
  "name": "order-admin-access",
  "description": "Full access to order management",
  "strategy_type": 2,
  "rules": {
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "paths": ["/api/orders/**"]
  },
  "effect": 1,
  "priority": 100,
  "enabled": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✅ | Unique policy name |
| `description` | string | ❌ | Policy description |
| `strategy_type` | string/int | ✅ | Strategy type: `"functional"`, `"api"`, `"data"`, `"rbac"`, `"location"`, `"lbac"`, `"abac"` (or numeric: 1-7) |
| `rules` | object | ✅ | Strategy-specific rules JSON |
| `effect` | int | ❌ | `1`=ALLOW (default), `0`=DENY |
| `priority` | int | ❌ | Priority (default: 50) |
| `enabled` | bool | ❌ | Whether policy is active (default: true) |

**Response `200`:**

```json
{
  "policy_id": 10,
  "name": "order-admin-access",
  "created": true
}
```

---

### PUT `/api/v1/policies/{id}`

Update a policy.

**Request Body:**

```json
{
  "name": "order-full-access",
  "rules": {
    "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
    "paths": ["/api/orders/**", "/api/inventory/**"]
  },
  "effect": 1,
  "priority": 200,
  "status": 1
}
```

**Response `200`:**

```json
{
  "updated": true
}
```

---

### DELETE `/api/v1/policies/{id}`

Delete a policy.

**Response `200`:**

```json
{
  "deleted": true
}
```

---

### POST `/api/v1/policies/{id}/assign`

Assign a policy to a user, role, or group.

**Request Body:**

```json
{
  "target_type": "user",
  "target_id": 42
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target_type` | string/int | ✅ | `"user"` (0), `"role"` (1), or `"group"` (2) |
| `target_id` | int | ✅ | ID of the target resource |

**Response `200`:**

```json
{
  "assigned": true
}
```

---

### POST `/api/v1/policies/{id}/unassign`

Unassign a policy from a user, role, or group.

**Request Body:**

```json
{
  "target_type": 0,
  "target_id": 42
}
```

**Response `200`:**

```json
{
  "unassigned": true
}
```

---

### GET `/api/v1/policies/{id}/targets`

Get all targets (users, roles, groups) assigned to a policy.

**Response `200`:**

```json
{
  "user_ids": [42, 43],
  "role_ids": [1, 2],
  "group_ids": [3]
}
```

---

## 10. OAuth Client Management

### GET `/api/v1/clients`

List OAuth 2.0 clients with pagination.

**Response `200`:**

```json
{
  "total": 5,
  "page": 1,
  "limit": 10,
  "items": [
    {
      "id": 1,
      "client_id": "my-app",
      "redirect_uris": "https://app.example.com/callback",
      "app_name": "My App",
      "app_description": "My OAuth application",
      "app_logo_url": "https://example.com/logo.png",
      "allowed_scopes": "openid profile email",
      "allowed_grant_types": "authorization_code",
      "token_ttl_ms": 3600000,
      "status": 1,
      "created_at": 1712345678000,
      "updated_at": 1712345678000
    }
  ]
}
```

---

### POST `/api/v1/clients`

Create an OAuth client.

**Request Body:**

```json
{
  "client_id": "my-app",
  "client_secret": "client-secret-value",
  "redirect_uris": "https://app.example.com/callback",
  "app_name": "My App",
  "app_description": "My OAuth application description",
  "app_logo_url": "https://example.com/logo.png",
  "allowed_scopes": "openid profile email",
  "allowed_grant_types": "authorization_code",
  "token_ttl_ms": 3600000,
  "status": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | ✅ | Unique client identifier |
| `client_secret` | string | ✅ | Client secret (hashed with Argon2id before storage) |
| `redirect_uris` | string | ✅ | Comma-separated allowed redirect URIs |
| `app_name` | string | ❌ | Application display name |
| `app_description` | string | ❌ | Application description |
| `app_logo_url` | string | ❌ | Application logo URL |
| `allowed_scopes` | string | ❌ | Space-separated allowed scopes |
| `allowed_grant_types` | string | ❌ | Space-separated allowed grant types |
| `token_ttl_ms` | int | ❌ | Token TTL in ms (default: 3600000) |
| `status` | int | ❌ | `0`=inactive, `1`=active |

---

### PUT `/api/v1/clients/{client_id}`

Update an OAuth client.

---

### DELETE `/api/v1/clients/{client_id}`

Delete an OAuth client.

---

## 11. Audit & Admin

### GET `/api/v1/audit/logs`

List audit log entries.

- **Auth**: Bearer token required

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `user_id` | int | — | Filter by user ID |
| `limit` | int | `100` | Max entries (max: 1000) |
| `offset` | int | `0` | Entry offset |

**Response `200`:**

Returns a JSON array of audit log entries:

```json
[
  {
    "timestamp_ms": 1712345678000,
    "user_id": 42,
    "decision": "ALLOW",
    "duration_ms": 0.05,
    "cache_hit": true,
    "trace": "Policy evaluation trace..."
  }
]
```

---

### GET `/api/v1/admin/status`

Get system admin status overview.

- **Auth**: Bearer token required

**Response `200`:**

```json
{
  "service": "sso",
  "version": "1.0.0",
  "users": 150,
  "uptime_ms": 86400000
}
```

---

## 12. OAuth 2.0 / OpenID Connect

### GET `/.well-known/openid-configuration`

OIDC Discovery Document.

- **Auth**: None

**Response `200`:**

```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/api/v1/oauth/authorize",
  "token_endpoint": "http://localhost:8080/api/v1/oauth/token",
  "userinfo_endpoint": "http://localhost:8080/api/v1/auth/userinfo",
  "jwks_uri": "http://localhost:8080/api/v1/auth/jwks",
  "revocation_endpoint": "http://localhost:8080/api/v1/oauth/revoke",
  "introspection_endpoint": "http://localhost:8080/api/v1/oauth/introspect",
  "end_session_endpoint": "http://localhost:8080/api/v1/oauth/end-session",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "HS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

---

### GET `/api/v1/oauth/authorize`

OAuth 2.0 Authorization Endpoint. Initiates the authorization code flow.

- **Auth**: Bearer token required (user must be logged in)

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `response_type` | string | ✅ | Must be `"code"` |
| `client_id` | string | ✅ | Registered client ID |
| `redirect_uri` | string | ❌ | Redirect URI after authorization |
| `scope` | string | ❌ | Requested scopes (space-separated) |
| `state` | string | ❌ | Opaque state value for CSRF protection |
| `code_challenge` | string | ❌ | PKCE code challenge (S256) |
| `code_challenge_method` | string | ❌ | `"S256"` or `"plain"` |

**Response `302`:** Redirect to `redirect_uri?code=<auth_code>&state=<state>`

---

### POST `/api/v1/oauth/token`

OAuth 2.0 Token Endpoint. Exchanges authorization code for tokens, or refreshes tokens.

- **Auth**: None (client credentials authenticate via body)

**Request Body** (`application/x-www-form-urlencoded` or JSON):

```json
{
  "grant_type": "authorization_code",
  "code": "<auth_code>",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "my-app",
  "client_secret": "my-secret",
  "code_verifier": "<pkce_verifier>"
}
```

For refresh token grant:

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "<refresh_token>",
  "client_id": "my-app",
  "client_secret": "my-secret"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `grant_type` | string | ✅ | `"authorization_code"`, `"refresh_token"`, or `"client_credentials"` |
| `code` | string | for auth_code | Authorization code from authorize endpoint |
| `redirect_uri` | string | ❌ | Must match authorize request |
| `client_id` | string | ❌ | Client identifier |
| `client_secret` | string | ❌ | Client secret |
| `code_verifier` | string | ❌ | PKCE code verifier |
| `refresh_token` | string | for refresh | Refresh token |
| `scope` | string | ❌ | Requested scopes |

**Response `200`:**

```json
{
  "access_token": "<jwt_access_token>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<refresh_token>",
  "id_token": "<jwt_id_token>",
  "scope": "openid profile email"
}
```

---

### POST `/api/v1/oauth/introspect`

Token Introspection (RFC 7662).

- **Auth**: Bearer token required

**Request Body** (`application/x-www-form-urlencoded` or JSON):

```json
{
  "token": "<token_to_introspect>"
}
```

**Response `200` (active):**

```json
{
  "active": true,
  "jti": "token-jti",
  "sub": 42,
  "iat": 1712345678,
  "exp": 1712432078,
  "token_type": "Bearer",
  "scope": "openid profile"
}
```

**Response `200` (inactive/expired):**

```json
{
  "active": false
}
```

---

### POST `/api/v1/oauth/revoke`

Token Revocation (RFC 7009).

- **Auth**: Bearer token required

**Request Body** (`application/x-www-form-urlencoded` or JSON):

```json
{
  "token": "<token_to_revoke>"
}
```

**Response `200`:**

```json
{}
```

---

### GET `/api/v1/oauth/end-session`

OIDC End Session Endpoint. Logs the user out of the session.

- **Auth**: None

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id_token_hint` | string | ❌ | ID token for the session to end |

**Response:** Redirect or completion.

---

## 13. WebAuthn (Passkeys)

### POST `/api/v1/auth/webauthn/register/challenge`

Get a WebAuthn registration challenge.

- **Auth**: Bearer token required

**Response `200`:**

```json
{
  "challenge": "<base64url_challenge>",
  "challenge_sig": "<hmac_signature_of_challenge>",
  "user_id": 42,
  "username": "johndoe"
}
```

---

### POST `/api/v1/auth/webauthn/register`

Complete WebAuthn credential registration.

- **Auth**: Bearer token required

**Request Body:**

```json
{
  "challenge": "<challenge_from_register_challenge>",
  "challenge_sig": "<signature_from_register_challenge>",
  "attestation_object": "<base64url_attestation_object>",
  "client_data_json": "<base64url_client_data_json>"
}
```

**Response `200`:**

```json
{
  "message": "WebAuthn credentials registered successfully"
}
```

---

### POST `/api/v1/auth/webauthn/login/challenge`

Get a WebAuthn authentication challenge.

- **Auth**: None

**Request Body:**

```json
{
  "username": "johndoe"
}
```

**Response `200`:**

```json
{
  "challenge": "<base64url_challenge>",
  "challenge_sig": "<hmac_signature_of_challenge>",
  "credential_id": "<stored_credential_id>"
}
```

---

### POST `/api/v1/auth/webauthn/login`

Complete WebAuthn authentication.

- **Auth**: None

**Request Body:**

```json
{
  "username": "johndoe",
  "challenge": "<challenge_from_login_challenge>",
  "challenge_sig": "<signature_from_login_challenge>",
  "authenticator_data": "<base64url_authenticator_data>",
  "client_data_json": "<base64url_client_data_json>",
  "signature": "<base64url_signature>"
}
```

**Response `200`:**

```json
{
  "access_token": "<jwt_access_token>",
  "refresh_token": "<jwt_refresh_token>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Note:** If DPoP proof was sent with the login challenge, `token_type` will be `"DPoP"` instead of `"Bearer"`.

---

## 14. Multi-Factor Authentication (MFA)

### POST `/api/v1/auth/mfa/setup`

Generate a TOTP secret for MFA setup.

- **Auth**: Bearer token required

**Response `200`:**

```json
{
  "secret": "JBSWY3DPEHPK3PXP"
}
```

The `secret` is a base32-encoded string to be used with any authenticator app (Google Authenticator, Authy, etc.).

---

### POST `/api/v1/auth/mfa/enable`

Enable MFA by verifying the TOTP secret with a code.

- **Auth**: Bearer token required

**Request Body:**

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "code": "123456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `secret` | string | ✅ | TOTP secret from `/mfa/setup` |
| `code` | string | ✅ | 6-digit TOTP code from authenticator app |

**Response `200`:**

```json
{
  "enabled": true
}
```

---

### POST `/api/v1/auth/mfa/verify`

Verify an MFA TOTP code during login (after receiving `mfa_required: true` from `/auth/login`).

- **Auth**: None (uses the short-lived MFA token)

**Request Body:**

```json
{
  "mfa_token": "<mfa_token_from_login>",
  "code": "123456"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mfa_token` | string | ✅ | Short-lived MFA token from login response |
| `code` | string | ✅ | 6-digit TOTP code |

**Response `200`:**

Same as login — tokens in response headers:

```
X-SSO-Access-Token: <jwt_access_token>
X-SSO-Refresh-Token: <jwt_refresh_token>
```

**JSON Body:**

```json
{
  "expires_in": 900000,
  "user_id": 42,
  "username": "johndoe",
  "display_name": "John Doe"
}
```

---

## 15. Monitoring

### GET `/api/v1/health`

Health check / liveness probe.

- **Auth**: None
- **Content-Type**: `application/json`

**Response `200`:**

```json
{
  "status": "ok",
  "service": "sso",
  "version": "1.1.0",
  "checks": {
    "database": {
      "status": "ready"
    }
  }
}
```

---

### GET `/metrics`

Prometheus metrics endpoint.

- **Auth**: None
- **Content-Type**: `text/plain; version=0.0.4`

**Metrics exposed:**

| Metric | Type | Description |
|--------|------|-------------|
| `sso_active_connections` | Gauge | Active HTTP connections |
| `sso_mfa_verifications_total` | Counter | MFA verification attempts (by result) |
| `sso_jwt_tokens_total` | Counter | JWT tokens issued/revoked |
| `sso_db_queries_total` | Counter | Database query counts (read/write) |
| `sso_db_query_duration_seconds_total` | Counter | Cumulative DB query duration |
| `sso_db_query_duration_seconds_avg` | Gauge | Average DB query duration |
| `sso_arena_allocated_blocks_total` | Gauge | Arena memory allocator blocks |
| Permission engine metrics | Various | Cache hit rates, eval counts, duration |

---

## 16. Token & Header Reference

### Token Types

| Token | TTL | Description |
|-------|-----|-------------|
| Access Token | 15 min (configurable) | JWT for API authentication |
| Refresh Token | 7 days | Long-lived token for refreshing access |
| MFA Token | 5 min | Short-lived token for MFA verification flow |

### Custom Response Headers

| Header | Endpoints | Description |
|--------|-----------|-------------|
| `X-SSO-Access-Token` | `/login`, `/refresh`, `/mfa/verify`, `/verify` | New JWT access token (for token rotation) |
| `X-SSO-Refresh-Token` | `/login`, `/refresh`, `/mfa/verify` | New refresh token |
| `X-SSO-User` | `/me`, `/verify`, `/session-check` | Authenticated username |
| `X-SSO-Email` | `/verify`, `/session-check` | Authenticated user email |
| `X-SSO-User-Id` | `/session-check` | Authenticated user ID |
| `X-Request-Id` | All | Unique trace ID for distributed tracing |

### Request Headers

| Header | Endpoints | Description |
|--------|-----------|-------------|
| `Authorization: Bearer <token>` | All protected endpoints | JWT access token |
| `DPoP` | All (if bound) | DPoP proof (sender-constrained tokens) |
| `X-Request-Id` | All | Client-provided trace ID |

### Token Claims

The JWT access token contains:

| Claim | Description |
|-------|-------------|
| `sub` | User ID |
| `username` | Username |
| `jti` | Token unique ID (for revocation) |
| `iat` | Issued-at timestamp |
| `exp` | Expiration timestamp |
| `roles` | Array of role IDs |
| `groups` | Array of group IDs |
| `scope` | Token scope |
| `jkt` | JWK Thumbprint (for DPoP-bound tokens) |
| `nonce` | Session nonce (for "logout all sessions" support) |

---

## 17. Error Codes

| Code | Name | Description |
|------|------|-------------|
| `-1` | SSO_ERR_GENERAL | General internal error |
| `-2` | SSO_ERR_NOT_FOUND | Resource not found |
| `-3` | SSO_ERR_ALREADY_EXISTS | Resource already exists |
| `-4` | SSO_ERR_INVALID_PARAM | Invalid parameter |
| `-5` | SSO_ERR_NO_PERMISSION | No permission |
| `-6` | SSO_ERR_AUTH_FAILED | Authentication failed |
| `-7` | SSO_ERR_TOKEN_EXPIRED | Token has expired |
| `-8` | SSO_ERR_TOKEN_INVALID | Token is invalid |
| `-15` | SSO_ERR_RATE_LIMIT | Rate limit exceeded |

---

## 18. cURL Examples

### Login

```bash
curl -s -D - -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_password"}'
```

Extract the token from `X-SSO-Access-Token` response header:

```bash
TOKEN=$(curl -s -D - -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_password"}' \
  | grep -i x-sso-access-token | awk '{print $2}' | tr -d '\r')
```

### Get Current User

```bash
curl -s http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### List Users (Admin)

```bash
curl -s "http://localhost:8080/api/v1/users?page=1&limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

### Check Permission (Functional)

```bash
curl -s -X POST http://localhost:8080/api/v1/check/functional \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"function_code": "order:create"}'
```

### Check Permission (API)

```bash
curl -s -X POST http://localhost:8080/api/v1/check/api \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"method": "POST", "path": "/api/orders"}'
```

### Create User (Admin)

```bash
curl -s -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "newuser", "password": "SecureP@ss1", "email": "new@example.com"}'
```

### Assign Role

```bash
curl -s -X POST http://localhost:8080/api/v1/roles/1/assign \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 42}'
```

### Unified Permission Check

```bash
curl -s -X POST http://localhost:8080/api/v1/check \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "function_code": "report:view",
    "resource_type": "report",
    "role_name": "analyst",
    "source_ip": "10.0.0.1"
  }'
```

### OAuth Token Exchange

```bash
curl -s -X POST http://localhost:8080/api/v1/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "<auth_code>",
    "client_id": "my-app",
    "client_secret": "my-secret"
  }'
```

### Health Check

```bash
curl -s http://localhost:8080/api/v1/health
```

### Prometheus Metrics

```bash
curl -s http://localhost:8080/metrics
```

---

> **Tip**: For the admin management UI, open `http://localhost:8080/admin` in a browser. The Vue.js SPA handles authentication flow automatically, including token refresh on 401 responses.
