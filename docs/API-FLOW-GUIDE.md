# Spring Authorization Server - Complete API Flow Guide

> Step-by-step guide: Initial call kahan se start hoga, successive calls ka flow kaise chalega, har call ka request/response kya hoga.

---

## Table of Contents

1. [Server Info](#1-server-info)
2. [Discovery - Sabse pehla call](#2-discovery---sabse-pehla-call)
3. [Flow 1: Web Application (Authorization Code Grant)](#3-flow-1-web-application---authorization-code-grant)
4. [Flow 2: Single Page Application (Authorization Code + PKCE)](#4-flow-2-single-page-application---authorization-code--pkce)
5. [Flow 3: Service-to-Service (Client Credentials Grant)](#5-flow-3-service-to-service---client-credentials-grant)
6. [Flow 4: Refresh Token se naya Access Token lena](#6-flow-4-refresh-token-se-naya-access-token-lena)
7. [Flow 5: Token Introspection (Token valid hai ya nahi?)](#7-flow-5-token-introspection)
8. [Flow 6: Token Revocation (Token cancel karna)](#8-flow-6-token-revocation)
9. [Flow 7: UserInfo Endpoint (User ki info lena)](#9-flow-7-userinfo-endpoint)
10. [Flow 8: Client Registration (Naya client register karna)](#10-flow-8-client-registration---management-api)
11. [Flow 9: Key Rotation (JWT signing key rotate karna)](#11-flow-9-key-rotation---management-api)
12. [Pre-configured Clients](#12-pre-configured-clients)
13. [JWT Token Structure](#13-jwt-token-structure)
14. [Complete Sequence Diagrams](#14-complete-sequence-diagrams)

---

## 1. Server Info

| Property         | Value                               |
|------------------|-------------------------------------|
| **Base URL**     | `http://localhost:9000`             |
| **Issuer**       | `https://authserver.company.com`    |
| **Database**     | H2 In-Memory                       |
| **Test Users**   | `user/password` (ROLE_USER), `admin/admin` (ROLE_USER, ROLE_ADMIN) |

---

## 2. Discovery - Sabse Pehla Call

> Koi bhi client sabse pehle discovery endpoint call karega taaki usse pata chale ki authorization server ke endpoints kahan hai.

### Call 1: OpenID Connect Discovery

```
GET http://localhost:9000/.well-known/openid-configuration
```

**Response:**
```json
{
  "issuer": "https://authserver.company.com",
  "authorization_endpoint": "http://localhost:9000/oauth2/authorize",
  "token_endpoint": "http://localhost:9000/oauth2/token",
  "jwks_uri": "http://localhost:9000/oauth2/jwks",
  "revocation_endpoint": "http://localhost:9000/oauth2/revoke",
  "introspection_endpoint": "http://localhost:9000/oauth2/introspect",
  "userinfo_endpoint": "http://localhost:9000/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

### Call 2: JWK Set (Public Keys for Token Verification)

```
GET http://localhost:9000/oauth2/jwks
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "some-uuid-key-id",
      "n": "base64-encoded-modulus..."
    }
  ]
}
```

> **Yeh public keys kaam aati hai** client ko JWT token verify karne ke liye. Token ke `kid` header se match karke sahi key select hoti hai.

---

## 3. Flow 1: Web Application - Authorization Code Grant

> **Client:** `web-client` (Confidential Client - server-side web app)
> **Use case:** Traditional web application jahan backend server hai

### Step 1: Authorization Request (Browser Redirect)

User ka browser redirect hota hai authorization server pe:

```
GET http://localhost:9000/oauth2/authorize?
    response_type=code
    &client_id=web-client
    &redirect_uri=http://localhost:8080/login/oauth2/code/authserver
    &scope=openid profile email read
    &state=random-state-value-xyz
```

| Parameter      | Value                          | Description                    |
|----------------|--------------------------------|--------------------------------|
| response_type  | `code`                         | Authorization code chahiye     |
| client_id      | `web-client`                   | Registered client ID           |
| redirect_uri   | `http://localhost:8080/login/oauth2/code/authserver` | Callback URL |
| scope          | `openid profile email read`    | Requested permissions          |
| state          | random string                  | CSRF protection ke liye        |

### Step 2: User Login (Form-based Authentication)

Authorization server login page dikhata hai. User credentials dalta hai:

```
POST http://localhost:9000/login
Content-Type: application/x-www-form-urlencoded

username=user&password=password
```

### Step 3: Consent Screen

Kyunki `web-client` ke liye `requireAuthorizationConsent: true` hai, user ko consent page dikhega.
User scopes approve karega.

### Step 4: Authorization Code Redirect

Login + consent ke baad, server browser ko redirect karega:

```
HTTP/1.1 302 Found
Location: http://localhost:8080/login/oauth2/code/authserver?
    code=AUTHORIZATION_CODE_VALUE
    &state=random-state-value-xyz
```

> **`code`** = temporary authorization code (short-lived, one-time use)

### Step 5: Exchange Code for Tokens (Backend Call)

Web app ka backend server yeh call karega (server-to-server, browser se nahi):

```
POST http://localhost:9000/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWNsaWVudDp3ZWItY2xpZW50LXNlY3JldA==

grant_type=authorization_code
&code=AUTHORIZATION_CODE_VALUE
&redirect_uri=http://localhost:8080/login/oauth2/code/authserver
```

> **Authorization header** = Base64("web-client:web-client-secret")
> Ya phir `client_id` aur `client_secret` body mein bhi bhej sakte ho (CLIENT_SECRET_POST method).

**Response (200 OK):**
```json
{
  "access_token": "eyJraWQiOiJ...",
  "refresh_token": "HaR7dG9rZW...",
  "id_token": "eyJraWQiOiJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email read"
}
```

| Field          | Description                                    |
|----------------|------------------------------------------------|
| access_token   | JWT token - API calls ke liye use karo (1 hour valid) |
| refresh_token  | Naya access token lene ke liye (30 days valid) |
| id_token       | OIDC ID token - user ki identity info (1 hour valid) |
| expires_in     | Access token seconds mein kitni der valid hai  |

### Step 6: Use Access Token to Call APIs

```
GET http://some-api-server/api/resource
Authorization: Bearer eyJraWQiOiJ...
```

---

## 4. Flow 2: Single Page Application - Authorization Code + PKCE

> **Client:** `spa-client` (Public Client - no secret, runs in browser)
> **Use case:** React, Angular, Vue.js applications
> **PKCE mandatory hai** kyunki public client hai (no secret store kar sakta)

### Step 1: Generate PKCE Values (Client-side)

SPA pehle PKCE values generate karega:

```javascript
// 1. Generate random code_verifier (43-128 characters)
code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// 2. Create code_challenge = Base64URL(SHA256(code_verifier))
code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

### Step 2: Authorization Request (Browser Redirect)

```
GET http://localhost:9000/oauth2/authorize?
    response_type=code
    &client_id=spa-client
    &redirect_uri=http://localhost:4200/callback
    &scope=openid profile read
    &state=random-state-value
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
```

| Extra Parameter        | Description                              |
|------------------------|------------------------------------------|
| code_challenge         | SHA256 hash of code_verifier             |
| code_challenge_method  | `S256` = SHA-256 hashing method          |

### Step 3: User Login

Same as Flow 1 - user login karega. Consent screen nahi aayega (`requireAuthorizationConsent: false`).

### Step 4: Authorization Code Redirect

```
HTTP/1.1 302 Found
Location: http://localhost:4200/callback?
    code=AUTHORIZATION_CODE_VALUE
    &state=random-state-value
```

### Step 5: Exchange Code for Tokens (with PKCE Proof)

```
POST http://localhost:9000/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTHORIZATION_CODE_VALUE
&redirect_uri=http://localhost:4200/callback
&client_id=spa-client
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

> **No Authorization header!** Public client hai, secret nahi hai.
> `code_verifier` bhej rahe hain - server verify karega ki SHA256(code_verifier) == code_challenge

**Response (200 OK):**
```json
{
  "access_token": "eyJraWQiOiJ...",
  "refresh_token": "HaR7dG9rZW...",
  "id_token": "eyJraWQiOiJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile read"
}
```

---

## 5. Flow 3: Service-to-Service - Client Credentials Grant

> **Client:** `service-client` (Machine-to-Machine, no user involved)
> **Use case:** Backend microservice calling another service
> **Sabse simple flow** - sirf ek call mein token mil jaata hai

### Step 1 (Only Step): Request Token Directly

```
POST http://localhost:9000/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic c2VydmljZS1jbGllbnQ6c2VydmljZS1jbGllbnQtc2VjcmV0

grant_type=client_credentials
&scope=internal.read internal.write
```

> **Authorization** = Base64("service-client:service-client-secret")

**Response (200 OK):**
```json
{
  "access_token": "eyJraWQiOiJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "internal.read internal.write"
}
```

> **Note:** No `refresh_token` aur no `id_token` - kyunki koi user involved nahi hai.

### Step 2: Use Token to Call Other Services

```
GET http://another-service/api/internal-data
Authorization: Bearer eyJraWQiOiJ...
```

---

## 6. Flow 4: Refresh Token se Naya Access Token Lena

> Jab access token expire ho jaye (1 hour baad), toh refresh token use karke naya le sakte ho.

### Request:

```
POST http://localhost:9000/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWNsaWVudDp3ZWItY2xpZW50LXNlY3JldA==

grant_type=refresh_token
&refresh_token=HaR7dG9rZW...
```

**Response (200 OK):**
```json
{
  "access_token": "eyJuZXdUb2tlbi...",
  "refresh_token": "bmV3UmVmcmVzaA...",
  "id_token": "eyJuZXdJZFRva2Vu...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email read"
}
```

> **Important:** `reuseRefreshTokens: false` hai, matlab har baar **naya refresh token** milega.
> Purana refresh token invalid ho jaayega (Refresh Token Rotation).
> Agar koi purana refresh token use kare, toh sabhi tokens revoke ho sakte hain (replay attack detection).

---

## 7. Flow 5: Token Introspection

> Resource server check karta hai ki token valid hai ya nahi (opaque tokens ke liye useful).

### Request:

```
POST http://localhost:9000/oauth2/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWNsaWVudDp3ZWItY2xpZW50LXNlY3JldA==

token=eyJraWQiOiJ...
```

**Response - Valid Token (200 OK):**
```json
{
  "active": true,
  "sub": "user",
  "aud": ["web-client"],
  "nbf": 1706990300,
  "scope": "openid profile email read",
  "iss": "https://authserver.company.com",
  "exp": 1706993900,
  "iat": 1706990300,
  "client_id": "web-client",
  "token_type": "Bearer"
}
```

**Response - Invalid/Expired Token (200 OK):**
```json
{
  "active": false
}
```

---

## 8. Flow 6: Token Revocation

> User logout kare ya token cancel karna ho.

### Revoke Access Token:

```
POST http://localhost:9000/oauth2/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWNsaWVudDp3ZWItY2xpZW50LXNlY3JldA==

token=eyJraWQiOiJ...
&token_type_hint=access_token
```

### Revoke Refresh Token:

```
POST http://localhost:9000/oauth2/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWNsaWVudDp3ZWItY2xpZW50LXNlY3JldA==

token=HaR7dG9rZW...
&token_type_hint=refresh_token
```

**Response (200 OK):** Empty body (success means token is revoked)

---

## 9. Flow 7: UserInfo Endpoint

> OIDC UserInfo - access token use karke user ki profile info lena.

### Request:

```
GET http://localhost:9000/userinfo
Authorization: Bearer eyJraWQiOiJ...
```

**Response (200 OK):**
```json
{
  "sub": "user",
  "preferred_username": "user",
  "email": "user@company.com",
  "email_verified": true,
  "name": "User Name",
  "roles": ["ROLE_USER"]
}
```

> **Note:** Response mein wahi fields aayenge jo requested scopes allow karti hain (`profile`, `email`).

---

## 10. Flow 8: Client Registration - Management API

> Naya OAuth2 client dynamically register karna.
> **Requires authentication** (`/api/clients/**` protected hai).

### Register a New Client:

```
POST http://localhost:9000/api/clients
Content-Type: application/json
Authorization: Basic YWRtaW46YWRtaW4=

{
  "clientId": "my-new-app",
  "clientSecret": "my-secret-123",
  "authenticationMethods": ["client_secret_basic"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "redirectUris": ["http://localhost:5000/callback"],
  "scopes": ["openid", "profile", "read"],
  "requireProofKey": false,
  "requireAuthorizationConsent": true,
  "accessTokenValiditySeconds": 1800,
  "refreshTokenValiditySeconds": 86400
}
```

> **Authorization** = Basic auth with in-memory user (e.g., `admin:admin`)

**Response (201 Created):**
```json
{
  "id": "generated-uuid",
  "clientId": "my-new-app",
  "clientIdIssuedAt": "2026-02-05T10:00:00Z",
  "clientAuthenticationMethods": ["client_secret_basic"],
  "authorizationGrantTypes": ["authorization_code", "refresh_token"],
  "redirectUris": ["http://localhost:5000/callback"],
  "scopes": ["openid", "profile", "read"],
  "requireProofKey": false,
  "requireAuthorizationConsent": true,
  "accessTokenTtlSeconds": 1800,
  "refreshTokenTtlSeconds": 86400
}
```

### Validation Rules:

| Rule                              | Error                                              |
|-----------------------------------|-----------------------------------------------------|
| `password` grant type bheja       | `400 Bad Request` - "Deprecated grant type: password" |
| `implicit` grant type bheja       | `400 Bad Request` - "Deprecated grant type: implicit" |
| `authorization_code` without redirect URIs | `400 Bad Request` - redirect URIs required |
| clientId blank                    | `400 Bad Request` - "Client ID is required"        |
| Empty grant types                 | `400 Bad Request` - "At least one grant type is required" |

### Get Client Details:

```
GET http://localhost:9000/api/clients/my-new-app
Authorization: Basic YWRtaW46YWRtaW4=
```

**Response (200 OK):**
```json
{
  "id": "generated-uuid",
  "clientId": "my-new-app",
  "clientIdIssuedAt": "2026-02-05T10:00:00Z",
  "clientAuthenticationMethods": ["client_secret_basic"],
  "authorizationGrantTypes": ["authorization_code", "refresh_token"],
  "redirectUris": ["http://localhost:5000/callback"],
  "scopes": ["openid", "profile", "read"],
  "requireProofKey": false,
  "requireAuthorizationConsent": true,
  "accessTokenTtlSeconds": 1800,
  "refreshTokenTtlSeconds": 86400
}
```

**Client Not Found (400 Bad Request):**
```json
{
  "error": "Client not found: unknown-client"
}
```

---

## 11. Flow 9: Key Rotation - Management API

> JWT signing keys rotate karna (security best practice).
> **Requires authentication.**

### Rotate Keys Manually:

```
POST http://localhost:9000/api/keys/rotate
Authorization: Basic YWRtaW46YWRtaW4=
```

**Response (200 OK):**
```json
{
  "status": "rotated",
  "activeKeyId": "new-uuid-key-id",
  "totalKeys": 2
}
```

### Check Key Status:

```
GET http://localhost:9000/api/keys/status
Authorization: Basic YWRtaW46YWRtaW4=
```

**Response (200 OK):**
```json
{
  "activeKeyId": "current-uuid-key-id",
  "totalKeys": 1
}
```

### Automatic Key Rotation:

- **Schedule:** Daily at 2:00 AM (`cron: 0 0 2 * * ?`)
- **Condition:** Jab current key `90 days` se zyada purani ho jaaye
- **Grace Period:** Purani keys `7 days` tak valid rehti hain rotation ke baad
- **Config:** `authserver.key-rotation.enabled: true`

---

## 12. Pre-configured Clients

Server start hone pe 3 clients automatically registered hote hain:

### web-client (Confidential Web Application)

| Property                    | Value                                         |
|-----------------------------|-----------------------------------------------|
| Client ID                   | `web-client`                                  |
| Client Secret               | `web-client-secret`                           |
| Auth Methods                | `client_secret_basic`, `client_secret_post`   |
| Grant Types                 | `authorization_code`, `refresh_token`         |
| Redirect URIs               | `http://localhost:8080/login/oauth2/code/authserver`, `http://localhost:8080/authorized` |
| Scopes                      | `openid`, `profile`, `email`, `read`, `write` |
| PKCE Required               | No                                            |
| Consent Required            | Yes                                           |

### spa-client (Public SPA Application)

| Property                    | Value                                         |
|-----------------------------|-----------------------------------------------|
| Client ID                   | `spa-client`                                  |
| Client Secret               | None (public client)                          |
| Auth Method                 | `none`                                        |
| Grant Types                 | `authorization_code`, `refresh_token`         |
| Redirect URIs               | `http://localhost:4200/callback`, `http://localhost:3000/callback` |
| Scopes                      | `openid`, `profile`, `read`                   |
| PKCE Required               | **Yes (mandatory)**                           |
| Consent Required            | No                                            |

### service-client (Machine-to-Machine)

| Property                    | Value                                         |
|-----------------------------|-----------------------------------------------|
| Client ID                   | `service-client`                              |
| Client Secret               | `service-client-secret`                       |
| Auth Method                 | `client_secret_basic`                         |
| Grant Type                  | `client_credentials`                          |
| Redirect URIs               | None                                          |
| Scopes                      | `internal.read`, `internal.write`             |
| PKCE Required               | No                                            |
| Consent Required            | No                                            |

---

## 13. JWT Token Structure

### Access Token (Decoded)

```json
{
  "header": {
    "alg": "RS256",
    "kid": "uuid-key-id"
  },
  "payload": {
    "sub": "user",
    "aud": "web-client",
    "nbf": 1706990300,
    "scope": ["openid", "profile", "email", "read"],
    "iss": "https://authserver.company.com",
    "exp": 1706993900,
    "iat": 1706990300,
    "jti": "unique-token-id",
    "roles": ["ROLE_USER"],
    "token_type": "access_token",
    "username": "user"
  }
}
```

> Custom claims (`roles`, `token_type`, `username`) `JwtTokenCustomizer` add karta hai.

### ID Token (Decoded)

```json
{
  "header": {
    "alg": "RS256",
    "kid": "uuid-key-id"
  },
  "payload": {
    "sub": "user",
    "aud": "web-client",
    "iss": "https://authserver.company.com",
    "exp": 1706993900,
    "iat": 1706990300,
    "auth_time": 1706990300,
    "nonce": "nonce-value",
    "roles": ["ROLE_USER"],
    "preferred_username": "user"
  }
}
```

### Token Validity

| Token Type     | Validity  | Configurable Property                              |
|----------------|-----------|-----------------------------------------------------|
| Access Token   | 1 hour    | `authserver.token.access-token-validity-seconds`    |
| Refresh Token  | 30 days   | `authserver.token.refresh-token-validity-seconds`   |
| ID Token       | 1 hour    | `authserver.token.id-token-validity-seconds`        |

---

## 14. Complete Sequence Diagrams

### Authorization Code Flow (Web App)

```
User/Browser          Web App Backend         Auth Server (localhost:9000)
     |                      |                          |
     |--- Click Login ----->|                          |
     |                      |--- Redirect ------------>|
     |<---------- 302 to /oauth2/authorize ------------|
     |                                                 |
     |--- GET /oauth2/authorize ---------------------->|
     |<---------- 302 to /login -----------------------|
     |                                                 |
     |--- POST /login (user:password) --------------->|
     |<---------- 302 to consent page -----------------|
     |                                                 |
     |--- POST consent (approve scopes) ------------->|
     |<---------- 302 to redirect_uri?code=XXX -------|
     |                                                 |
     |--- code=XXX ---->|                              |
     |                  |--- POST /oauth2/token ------>|
     |                  |   (code + client_secret)     |
     |                  |<--- access_token, refresh, --|
     |                  |     id_token                 |
     |<-- Set session --|                              |
     |                  |                              |
     |--- API request ->|                              |
     |                  |--- Bearer token ------------>| Resource Server
     |                  |<--- Protected resource ------|
     |<-- Response -----|                              |
```

### PKCE Flow (SPA)

```
SPA (Browser)                          Auth Server (localhost:9000)
     |                                          |
     |-- Generate code_verifier + challenge     |
     |                                          |
     |--- GET /oauth2/authorize --------------->|
     |    + code_challenge                      |
     |    + code_challenge_method=S256          |
     |<---------- 302 to /login ----------------|
     |                                          |
     |--- POST /login (user:password) -------->|
     |<---------- 302 to redirect?code=XXX ----|
     |                                          |
     |--- POST /oauth2/token ----------------->|
     |    + code=XXX                            |
     |    + code_verifier (proof!)              |
     |    + client_id=spa-client                |
     |    (no client_secret!)                   |
     |                                          |
     |<--- access_token, refresh, id_token -----|
     |                                          |
     |--- Bearer token to API ----------------->| Resource Server
```

### Client Credentials Flow (Service)

```
Backend Service                    Auth Server (localhost:9000)
     |                                      |
     |--- POST /oauth2/token ------------->|
     |    grant_type=client_credentials    |
     |    Authorization: Basic (creds)     |
     |    scope=internal.read              |
     |                                      |
     |<--- access_token -------------------|
     |                                      |
     |--- Bearer token to other service -->| Another Service
```

### Token Refresh Flow

```
Client                             Auth Server (localhost:9000)
     |                                      |
     |--- API call with expired token ----->| Resource Server
     |<--- 401 Unauthorized ---------------|
     |                                      |
     |--- POST /oauth2/token ------------->| Auth Server
     |    grant_type=refresh_token          |
     |    refresh_token=OLD_TOKEN           |
     |    Authorization: Basic (creds)      |
     |                                      |
     |<--- new access_token + -------------|
     |     new refresh_token               |
     |     (old refresh_token invalid)     |
     |                                      |
     |--- API call with new token -------->| Resource Server
     |<--- Protected resource --------------|
```

---

## Endpoints Summary

| Endpoint                                    | Method | Auth Required  | Purpose                              |
|---------------------------------------------|--------|----------------|--------------------------------------|
| `/.well-known/openid-configuration`         | GET    | No             | OIDC Discovery                       |
| `/.well-known/oauth-authorization-server`   | GET    | No             | OAuth2 Server Metadata               |
| `/oauth2/authorize`                         | GET    | User Login     | Start authorization flow             |
| `/oauth2/token`                             | POST   | Client Creds   | Get/refresh tokens                   |
| `/oauth2/jwks`                              | GET    | No             | Public keys for JWT verification     |
| `/oauth2/revoke`                            | POST   | Client Creds   | Revoke a token                       |
| `/oauth2/introspect`                        | POST   | Client Creds   | Check if token is valid              |
| `/userinfo`                                 | GET    | Bearer Token   | Get user profile info                |
| `/api/clients`                              | POST   | Basic Auth     | Register new OAuth2 client           |
| `/api/clients/{clientId}`                   | GET    | Basic Auth     | Get client details                   |
| `/api/keys/rotate`                          | POST   | Basic Auth     | Manually rotate JWT signing keys     |
| `/api/keys/status`                          | GET    | Basic Auth     | Check current key status             |
| `/actuator/health`                          | GET    | No             | Health check                         |
| `/actuator/info`                            | GET    | No             | App info                             |
| `/h2-console`                               | GET    | No             | H2 database console                  |
| `/swagger-ui.html`                          | GET    | No             | Swagger API docs                     |

---

## Quick Test Commands (cURL)

### 1. Discovery
```bash
curl http://localhost:9000/.well-known/openid-configuration
```

### 2. Client Credentials Token
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "service-client:service-client-secret" \
  -d "grant_type=client_credentials&scope=internal.read internal.write"
```

### 3. Register New Client
```bash
curl -X POST http://localhost:9000/api/clients \
  -H "Content-Type: application/json" \
  -u "admin:admin" \
  -d '{
    "clientId": "test-app",
    "clientSecret": "test-secret",
    "authenticationMethods": ["client_secret_basic"],
    "grantTypes": ["client_credentials"],
    "scopes": ["read"]
  }'
```

### 4. Key Status
```bash
curl http://localhost:9000/api/keys/status -u "admin:admin"
```

### 5. Introspect Token
```bash
curl -X POST http://localhost:9000/oauth2/introspect \
  -u "web-client:web-client-secret" \
  -d "token=YOUR_ACCESS_TOKEN_HERE"
```
