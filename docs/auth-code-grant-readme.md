# Authorization Code Grant - Angular SPA Integration

## Overview

This document describes the OAuth2 Authorization Code Grant with PKCE implementation between the **AuthorizationCodeApp** (Angular SPA) and the **spring-auth-service** (Spring Authorization Server).

## Architecture

```
┌─────────────────────┐     ┌──────────────────────────────┐
│  Angular SPA        │     │  Spring Auth Service (:9000)  │
│  (:4200)            │     │                               │
│                     │     │  /oauth2/authorize             │
│  /login ──────────────────►  (Authorization Endpoint)     │
│                     │     │                               │
│                     │     │  /login                        │
│                     │     │  (User Authentication Form)    │
│                     │     │                               │
│  /callback ◄──────────────  (Redirect with auth code)     │
│                     │     │                               │
│  AuthService ───────────► /api/auth/token                 │
│  (code + verifier)  │     │  (Token Exchange Proxy)       │
│                     │     │                               │
│  Protected Routes   │     │  /oauth2/token                │
│  (Bearer token)     │     │  (Actual Token Endpoint)      │
└─────────────────────┘     └──────────────────────────────┘
```

## Components

### Spring Backend - AuthorizationCodeController

**Location:** `src/main/java/com/corp/authserver/controller/AuthorizationCodeController.java`

**Endpoints:**

| Method | Path              | Description                                         |
|--------|-------------------|-----------------------------------------------------|
| POST   | `/api/auth/token`   | Exchanges authorization code for tokens (with PKCE) |
| POST   | `/api/auth/refresh` | Refreshes an access token using a refresh token     |
| POST   | `/api/auth/revoke`  | Revokes an access or refresh token                  |

**Token Exchange Request Body:**
```json
{
  "code": "<authorization_code>",
  "code_verifier": "<pkce_code_verifier>",
  "redirect_uri": "http://localhost:4200/callback",
  "client_id": "spa-client"
}
```

**Token Response:**
```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "abc123...",
  "id_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile read"
}
```

### Angular App - AuthorizationCodeApp

**Location:** `D:\poc\AuthorizationCodeApp`

**Key Files:**

| File | Purpose |
|------|---------|
| `src/app/services/auth.service.ts` | Core OAuth2 logic: PKCE generation, login redirect, token exchange, refresh, logout |
| `src/app/guards/auth.guard.ts` | Route guard that protects routes requiring authentication |
| `src/app/interceptors/auth.interceptor.ts` | HTTP interceptor that attaches Bearer token to outgoing requests |
| `src/app/components/callback/callback.component.ts` | Handles the OAuth2 redirect callback, exchanges code for tokens |
| `src/app/components/login/login.component.ts` | Login page with "Sign In" button |
| `src/app/components/protected/protected.component.ts` | Protected dashboard showing token info and user details |
| `src/app/components/home/home.component.ts` | Landing page |
| `src/environments/environment.ts` | OAuth2 configuration (endpoints, client ID, scopes) |

**Routes:**

| Path | Component | Auth Required |
|------|-----------|---------------|
| `/` | HomeComponent | No |
| `/login` | LoginComponent | No |
| `/callback` | CallbackComponent | No |
| `/protected` | ProtectedComponent | Yes |

## OAuth2 Authorization Code Flow with PKCE

### Step-by-Step Flow

1. **User clicks "Sign In"** on the Angular app (`/login`)

2. **PKCE generation** - The `AuthService` generates:
   - `code_verifier`: A cryptographically random 128-character string
   - `code_challenge`: SHA-256 hash of the verifier, base64url-encoded
   - `state`: Random string for CSRF protection

3. **Redirect to Authorization Server** - Browser navigates to:
   ```
   http://localhost:9000/oauth2/authorize?
     response_type=code&
     client_id=spa-client&
     redirect_uri=http://localhost:4200/callback&
     scope=openid profile read&
     state=<random>&
     code_challenge=<sha256_hash>&
     code_challenge_method=S256
   ```

4. **User authenticates** at the Spring Auth Server login form (e.g., `user`/`password`)

5. **Authorization server redirects** back to the Angular app:
   ```
   http://localhost:4200/callback?code=<auth_code>&state=<state>
   ```

6. **CallbackComponent receives the code** and calls `AuthService.handleCallback()`

7. **Token exchange** - `AuthService` sends a POST to `/api/auth/token`:
   ```json
   {
     "code": "<auth_code>",
     "code_verifier": "<original_verifier>",
     "redirect_uri": "http://localhost:4200/callback",
     "client_id": "spa-client"
   }
   ```

8. **AuthorizationCodeController** forwards the request to the internal `/oauth2/token` endpoint

9. **Tokens are stored** in `localStorage` and the user is redirected to `/protected`

### PKCE Security

PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks:
- The `code_verifier` is generated client-side and never sent to the authorization server directly
- Only the `code_challenge` (SHA-256 hash) is sent during the authorization request
- During token exchange, the original `code_verifier` is sent to prove the same client initiated the flow
- The authorization server verifies `SHA256(code_verifier) == code_challenge`

## Registered Client Configuration

The `spa-client` is configured in `AuthorizationServerConfig.java`:

| Setting | Value |
|---------|-------|
| Client ID | `spa-client` |
| Authentication Method | `NONE` (public client) |
| Grant Types | `authorization_code`, `refresh_token` |
| Redirect URIs | `http://localhost:4200/callback`, `http://localhost:3000/callback` |
| Scopes | `openid`, `profile`, `read` |
| PKCE Required | Yes |
| Consent Required | No |
| Access Token TTL | 3600s (1 hour) |
| Refresh Token TTL | 2592000s (30 days) |

## Running Locally

### Prerequisites
- Java 17+
- Node.js 18+
- Angular CLI 19+

### Start the Authorization Server
```bash
cd D:\poc\spring-auth-service
mvn spring-boot:run
```
Server starts on `http://localhost:9000`.

### Start the Angular App
```bash
cd D:\poc\AuthorizationCodeApp
ng serve
```
App starts on `http://localhost:4200`.

### Test the Flow
1. Open `http://localhost:4200`
2. Click **Sign In**
3. You will be redirected to `http://localhost:9000/login`
4. Enter credentials: `user` / `password` (or `admin` / `admin`)
5. After authentication, you are redirected back to `http://localhost:4200/callback`
6. The callback page exchanges the code for tokens and redirects to `/protected`
7. The protected dashboard displays your token info and user details

### Test Users

| Username | Password | Roles |
|----------|----------|-------|
| `user` | `password` | USER |
| `admin` | `admin` | USER, ADMIN |

## Token Storage

| Token | Storage | Purpose |
|-------|---------|---------|
| `access_token` | `localStorage` | API authorization (Bearer token) |
| `refresh_token` | `localStorage` | Obtaining new access tokens |
| `id_token` | `localStorage` | OpenID Connect identity claims |
| `token_expires_at` | `localStorage` | Token expiration tracking |

## API Protection

The `authInterceptor` automatically attaches the Bearer token to all outgoing HTTP requests (excluding OAuth2 endpoints). Protected API calls include:

```
Authorization: Bearer <access_token>
```

The `authGuard` prevents navigation to protected routes when no valid token is present, redirecting to `/login`.
