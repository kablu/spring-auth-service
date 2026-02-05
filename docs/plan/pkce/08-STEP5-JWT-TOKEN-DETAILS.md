# 08 - Step 5: JWT Token Details

## Flow Position

```
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1-4: Complete  ✓                                          │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  ▶ STEP 5: Access Token (JWT)  ◀  (YOU ARE HERE)               │
│                                                                 │
│  Understanding JWT structure, claims, and usage                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## JWT Structure (3 Parts)

```
eyJraWQiOiJhMWIyYzNkNCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ1c2VyIiwiYXVkIjoic3BhLWNsaWVudCIs...SIGNATURE
└──────────────── HEADER ────────────────┘.└──────────────────── PAYLOAD ──────────────────┘.└─ SIGNATURE ─┘
```

### Parts Explained

| Part | Encoding | Content |
|------|----------|---------|
| Header | Base64URL | Algorithm and key info |
| Payload | Base64URL | Claims (data) |
| Signature | Base64URL | Cryptographic signature |

---

## Access Token (Decoded)

### Header

```json
{
  "kid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "alg": "RS256"
}
```

| Field | Value | Description |
|-------|-------|-------------|
| `kid` | UUID | Key ID — which key was used to sign |
| `alg` | `RS256` | Algorithm — RSA with SHA-256 |

### Payload

```json
{
  "sub": "user",
  "aud": "spa-client",
  "nbf": 1738750600,
  "scope": ["openid", "profile", "read"],
  "iss": "http://localhost:9000",
  "exp": 1738754200,
  "iat": 1738750600,
  "jti": "abc123-unique-token-id",

  "username": "user",
  "roles": ["ROLE_USER"],
  "token_type": "access_token"
}
```

### Standard Claims

| Claim | Value | Description |
|-------|-------|-------------|
| `sub` | `"user"` | Subject — who this token represents |
| `aud` | `"spa-client"` | Audience — who this token is for |
| `iss` | `"http://localhost:9000"` | Issuer — who issued this token |
| `iat` | `1738750600` | Issued At — Unix timestamp |
| `exp` | `1738754200` | Expiration — Unix timestamp (iat + 3600) |
| `nbf` | `1738750600` | Not Before — token not valid before this |
| `jti` | UUID | JWT ID — unique identifier |
| `scope` | `["openid", "profile", "read"]` | Granted scopes |

### Custom Claims (from JwtTokenCustomizer)

| Claim | Value | Source |
|-------|-------|--------|
| `username` | `"user"` | `principal.getName()` |
| `roles` | `["ROLE_USER"]` | `principal.getAuthorities()` |
| `token_type` | `"access_token"` | Hardcoded identifier |

---

## ID Token (Decoded)

### Header

```json
{
  "kid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "alg": "RS256"
}
```

### Payload

```json
{
  "sub": "user",
  "aud": "spa-client",
  "azp": "spa-client",
  "iss": "http://localhost:9000",
  "exp": 1738754200,
  "iat": 1738750600,
  "auth_time": 1738750600,
  "nonce": "abc123NonceValue",

  "preferred_username": "user",
  "roles": ["ROLE_USER"]
}
```

### ID Token Specific Claims

| Claim | Value | Description |
|-------|-------|-------------|
| `azp` | `"spa-client"` | Authorized Party |
| `auth_time` | timestamp | When user actually authenticated |
| `nonce` | `"abc123NonceValue"` | Replay protection (from original request) |
| `preferred_username` | `"user"` | Display username |

---

## Token Lifetimes

| Token | TTL | Expiry Calculation |
|-------|-----|-------------------|
| Access Token | 3600 sec (1 hour) | `iat + 3600` |
| Refresh Token | 2592000 sec (30 days) | Opaque, server-tracked |
| ID Token | 3600 sec (1 hour) | `iat + 3600` |

### Checking Expiry in Angular

```typescript
// Check if access token is expired
isTokenExpired(): boolean {
  const expiry = localStorage.getItem('token_expiry');
  if (!expiry) return true;

  const bufferMs = 5 * 60 * 1000; // 5 minute buffer
  return Date.now() > (parseInt(expiry) - bufferMs);
}
```

---

## Using Access Token for API Calls

### Angular HTTP Interceptor

**File:** `src/app/core/auth/auth.interceptor.ts`

```typescript
import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent
} from '@angular/common/http';
import { Observable, from } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { environment } from '../../../environments/environment';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  constructor(private authService: AuthService) {}

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {

    // Only add token for API requests
    if (!request.url.startsWith(environment.apiUrl)) {
      return next.handle(request);
    }

    // Check if token needs refresh
    if (this.authService.isTokenExpired()) {
      return from(this.authService.refreshToken()).pipe(
        switchMap(() => this.addToken(request, next))
      );
    }

    return this.addToken(request, next);
  }

  private addToken(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const token = this.authService.getAccessToken();

    if (token) {
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
    }

    return next.handle(request);
  }
}
```

### Example API Request

```
GET http://localhost:8080/api/users/profile HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJraWQiOiJhMWIyYzNkNCIs...
Accept: application/json
```

---

## Token Verification by Resource Server

### Resource Server Configuration

```yaml
# Resource Server application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:9000
          jwk-set-uri: http://localhost:9000/oauth2/jwks
```

### Verification Steps

```
1. Receive request with Authorization: Bearer {token}

2. Extract JWT from header

3. Decode header:
   - kid: "a1b2c3d4-e5f6-..."
   - alg: "RS256"

4. Fetch public key from JWKS endpoint:
   GET http://localhost:9000/oauth2/jwks
   → Find key with matching kid

5. Verify signature:
   - RSA-SHA256 verify using public key
   - Signature valid? ✓

6. Validate claims:
   - iss matches expected issuer? ✓
   - aud contains expected audience? ✓
   - exp > current time? ✓
   - nbf < current time? ✓

7. Extract authorities from roles claim:
   - roles: ["ROLE_USER"]
   → User has ROLE_USER authority

8. All checks pass → Request authorized
```

---

## Decoding Tokens in Angular

### Using jwt-decode Library

```typescript
import { jwtDecode } from 'jwt-decode';

// Decode access token
const accessToken = localStorage.getItem('access_token');
const decoded = jwtDecode<AccessTokenPayload>(accessToken);

console.log(decoded);
// {
//   sub: "user",
//   aud: "spa-client",
//   iss: "http://localhost:9000",
//   exp: 1738754200,
//   username: "user",
//   roles: ["ROLE_USER"],
//   scope: ["openid", "profile", "read"]
// }
```

### Display User Info

```typescript
// In a component
getUserInfo(): { username: string; roles: string[] } | null {
  const decoded = this.authService.getDecodedAccessToken();
  if (!decoded) return null;

  return {
    username: decoded.username,
    roles: decoded.roles
  };
}
```

---

## Refresh Token Flow

### When to Refresh

```
Access token expires: iat + 3600 = 1 hour
Refresh buffer: 5 minutes before expiry

Timeline:
  T+0:00  — Token issued
  T+0:55  — Check: isTokenExpired()? → approaching expiry
  T+0:55  — Silently refresh token
  T+0:55  — New access token received (valid for another hour)
  T+1:00  — Old token expired (but already refreshed)
```

### Refresh Request

```
POST http://localhost:9000/oauth2/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=HaR7dG9rZW4tYWJjMTIzLXJlZnJlc2gtdG9rZW4
&client_id=spa-client
```

### Refresh Response

```json
{
  "access_token": "eyJraWQiOiJhMWIyYzNkNCIs...(NEW)",
  "refresh_token": "TmV3UmVmcmVzaFRva2VuLXh5eg==(NEW)",
  "id_token": "eyJraWQiOiJhMWIyYzNkNCIs...(NEW)",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Note:** New refresh token issued (rotation enabled: `reuseRefreshTokens: false`)

---

## Token Storage Security

### localStorage vs sessionStorage

| Storage | Persistence | Tab Scope | XSS Vulnerable |
|---------|-------------|-----------|----------------|
| localStorage | Permanent | All tabs | Yes |
| sessionStorage | Tab session | Single tab | Yes |
| Memory only | None | Single tab | Less |

### Current Implementation

- **Access/Refresh tokens:** localStorage (persists across sessions)
- **PKCE state:** sessionStorage (single tab, cleared on close)

### XSS Mitigation

```typescript
// Avoid XSS by never using innerHTML with untrusted data
// Angular's built-in sanitization helps

// Additional measures:
// 1. Content Security Policy headers
// 2. HttpOnly cookies (not used here, but for server-rendered apps)
// 3. Token binding (DPoP — covered in zero-trust plan)
```

---

## Token Claims Summary

### Access Token

| Claim | Type | Used By | Purpose |
|-------|------|---------|---------|
| `sub` | string | Resource Server | User identification |
| `iss` | string | Resource Server | Issuer validation |
| `aud` | string | Resource Server | Audience validation |
| `exp` | number | Angular, Resource Server | Expiry check |
| `scope` | array | Resource Server | Permission check |
| `roles` | array | Resource Server | RBAC authorization |
| `username` | string | Angular UI | Display name |
| `token_type` | string | Debugging | Token identification |

### ID Token

| Claim | Type | Used By | Purpose |
|-------|------|---------|---------|
| `sub` | string | Angular | User identification |
| `preferred_username` | string | Angular UI | Display name |
| `roles` | array | Angular | UI role checks |
| `nonce` | string | Angular | Replay protection |
| `auth_time` | number | Angular | Session freshness |

---

## JWKS Endpoint Response

```
GET http://localhost:9000/oauth2/jwks

{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78..."
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `kty` | Key Type (RSA) |
| `kid` | Key ID (matches header.kid) |
| `e` | RSA Public Exponent |
| `n` | RSA Public Modulus |

---

## Complete Token Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TOKEN LIFECYCLE                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  T+0:00  ┌──────────────────────────────────────────────────────────┐  │
│          │ Token Exchange Complete                                   │  │
│          │ access_token: eyJraWQ... (expires T+1:00)                 │  │
│          │ refresh_token: HaR7d... (expires T+30 days)               │  │
│          │ id_token: eyJraWQ... (expires T+1:00)                     │  │
│          └──────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  T+0:10  ┌──────────────────────────────────────────────────────────┐  │
│          │ API Call                                                  │  │
│          │ GET /api/resource                                         │  │
│          │ Authorization: Bearer eyJraWQ...                          │  │
│          │                                                           │  │
│          │ Resource Server:                                          │  │
│          │ 1. Verify signature via JWKS                              │  │
│          │ 2. Check exp > now ✓                                      │  │
│          │ 3. Check iss, aud ✓                                       │  │
│          │ 4. Extract roles → authorize                              │  │
│          └──────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  T+0:55  ┌──────────────────────────────────────────────────────────┐  │
│          │ Token Refresh (5 min before expiry)                       │  │
│          │ POST /oauth2/token                                        │  │
│          │ grant_type=refresh_token                                  │  │
│          │ refresh_token=HaR7d...                                    │  │
│          │                                                           │  │
│          │ Response:                                                 │  │
│          │ NEW access_token (expires T+1:55)                         │  │
│          │ NEW refresh_token (rotation)                              │  │
│          │ NEW id_token                                              │  │
│          └──────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│                                    ▼                                    │
│  T+1:00  ┌──────────────────────────────────────────────────────────┐  │
│          │ Old access_token EXPIRED                                  │  │
│          │ (but we already refreshed at T+0:55)                      │  │
│          └──────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```
