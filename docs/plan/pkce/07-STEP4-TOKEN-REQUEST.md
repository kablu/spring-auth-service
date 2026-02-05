# 07 - Step 4: Token Request (Exchange Code for Tokens)

## Flow Position

```
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: Authorization Request  ✓                               │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: User Login  ✓                                         │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Authorization Code  ✓                                  │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  ▶ STEP 4: Token Request  ◀  (YOU ARE HERE)                    │
│                                                                 │
│  Angular sends code + code_verifier to token endpoint          │
│  Server validates PKCE and issues tokens                        │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 5: Access Token (JWT)                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Token Request from Angular

### Code Location

**File:** `src/app/core/auth/auth.service.ts` — `exchangeCodeForTokens()`

```typescript
private async exchangeCodeForTokens(
  code: string,
  codeVerifier: string
): Promise<void> {
  // Build request body
  const body = new HttpParams()
    .set('grant_type', 'authorization_code')
    .set('code', code)
    .set('redirect_uri', AUTH_CONFIG.redirectUri)
    .set('client_id', AUTH_CONFIG.clientId)
    .set('code_verifier', codeVerifier);

  const headers = new HttpHeaders()
    .set('Content-Type', 'application/x-www-form-urlencoded');

  // Send request
  const response = await this.http.post<TokenResponse>(
    AUTH_CONFIG.tokenEndpoint,
    body.toString(),
    { headers }
  ).toPromise();

  if (response) {
    this.storeTokens(response);
  }
}
```

---

## Complete Token Request

### HTTP Request

```
POST http://localhost:9000/oauth2/token HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded
Origin: http://localhost:4200
Accept: application/json

grant_type=authorization_code
&code=dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz
&redirect_uri=http://localhost:4200/callback
&client_id=spa-client
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### Request Parameters

| Parameter | Value | Required | Description |
|-----------|-------|----------|-------------|
| `grant_type` | `authorization_code` | Yes | Indicates code exchange |
| `code` | `dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz` | Yes | Authorization code from callback |
| `redirect_uri` | `http://localhost:4200/callback` | Yes | Must match original request |
| `client_id` | `spa-client` | Yes | Client identifier |
| `code_verifier` | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` | Yes | PKCE proof |

### Important Notes

- **No client_secret** — `spa-client` is a public client
- **code_verifier sent** — This is the PKCE proof
- **Content-Type must be** `application/x-www-form-urlencoded`

---

## Server-Side PKCE Validation

### Validation Flow

```
1. Receive POST /oauth2/token

2. Parse request body:
   - grant_type: "authorization_code"
   - code: "dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz"
   - redirect_uri: "http://localhost:4200/callback"
   - client_id: "spa-client"
   - code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

3. Lookup authorization by code:
   - Found: {
       code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
       code_challenge_method: "S256",
       client_id: "spa-client",
       redirect_uri: "http://localhost:4200/callback",
       principal: "user",
       scopes: ["openid", "profile", "read"],
       expires_at: timestamp
     }

4. Validate code not expired:
   - Current time < expires_at? YES ✓

5. Validate code not already used:
   - Code still valid? YES ✓

6. Validate client_id matches:
   - "spa-client" == "spa-client"? YES ✓

7. Validate redirect_uri matches:
   - "http://localhost:4200/callback" == "http://localhost:4200/callback"? YES ✓

8. PKCE Validation (THE KEY STEP):
   - Received code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
   - Calculate: SHA256(code_verifier)
   - Encode: BASE64URL(hash)
   - Result: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
   - Compare with stored code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
   - MATCH? YES ✓

9. All validations passed → Generate tokens
```

### PKCE Verification Code (Conceptual)

```java
// Server-side PKCE verification
String codeVerifier = request.getParameter("code_verifier");
String storedChallenge = authorization.getCodeChallenge();
String storedMethod = authorization.getCodeChallengeMethod();

if ("S256".equals(storedMethod)) {
    // Calculate SHA256 of verifier
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));

    // Base64URL encode
    String calculatedChallenge = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(hash);

    // Compare
    if (!calculatedChallenge.equals(storedChallenge)) {
        throw new OAuth2AuthenticationException("invalid_grant",
            "PKCE verification failed");
    }
}
```

---

## Successful Token Response

### HTTP Response

```
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJraWQiOiJhMWIyYzNkNCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ1c2VyIiwiYXVkIjoic3BhLWNsaWVudCIsIm5iZiI6MTczODc1MDYwMCwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSIsInJlYWQiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNzM4NzU0MjAwLCJpYXQiOjE3Mzg3NTA2MDAsInVzZXJuYW1lIjoidXNlciIsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIn0.SIGNATURE",
  "refresh_token": "HaR7dG9rZW4tYWJjMTIzLXJlZnJlc2gtdG9rZW4",
  "id_token": "eyJraWQiOiJhMWIyYzNkNCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ1c2VyIiwiYXVkIjoic3BhLWNsaWVudCIsImF6cCI6InNwYS1jbGllbnQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE3Mzg3NTQyMDAsImlhdCI6MTczODc1MDYwMCwibm9uY2UiOiJhYmMxMjNOb25jZVZhbHVlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlciIsInJvbGVzIjpbIlJPTEVfVVNFUiJdfQ.SIGNATURE",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile read"
}
```

### Response Fields

| Field | Value | Description |
|-------|-------|-------------|
| `access_token` | JWT string | For API calls (1 hour validity) |
| `refresh_token` | Opaque string | For silent token refresh (30 days) |
| `id_token` | JWT string | User identity info (OIDC) |
| `token_type` | `Bearer` | How to use access_token |
| `expires_in` | `3600` | Seconds until access_token expires |
| `scope` | `openid profile read` | Granted scopes |

---

## Storing Tokens in Angular

### Code Location

**File:** `src/app/core/auth/auth.service.ts` — `storeTokens()`

```typescript
private storeTokens(response: TokenResponse): void {
  // Store access token
  localStorage.setItem('access_token', response.access_token);

  // Store refresh token
  if (response.refresh_token) {
    localStorage.setItem('refresh_token', response.refresh_token);
  }

  // Store ID token
  if (response.id_token) {
    localStorage.setItem('id_token', response.id_token);
  }

  // Calculate and store expiry time
  const expiresAt = Date.now() + (response.expires_in * 1000);
  localStorage.setItem('token_expiry', expiresAt.toString());
}
```

### Browser Storage After Token Exchange

**localStorage:**

```json
{
  "access_token": "eyJraWQiOiJhMWIyYzNkNCIs...",
  "refresh_token": "HaR7dG9rZW4tYWJjMTIzLXJlZnJlc2gtdG9rZW4",
  "id_token": "eyJraWQiOiJhMWIyYzNkNCIs...",
  "token_expiry": "1738754200000"
}
```

**sessionStorage:**

```json
{
  "pkce_state": null  // Cleared after successful exchange
}
```

---

## Error Scenarios

### 1. Invalid Authorization Code

```
POST /oauth2/token
code=invalid_or_expired_code&...

Response:
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

### 2. PKCE Verification Failed

```
POST /oauth2/token
code=valid_code
&code_verifier=wrong_verifier

Response:
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_grant",
  "error_description": "PKCE verification failed"
}
```

### 3. Code Already Used (Replay Attack)

```
POST /oauth2/token
code=already_used_code&...

Response:
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

### 4. redirect_uri Mismatch

```
POST /oauth2/token
redirect_uri=http://evil.com/callback&...

Response:
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_grant",
  "error_description": "redirect_uri does not match the original request"
}
```

### 5. CORS Error (Browser)

If CORS is not configured for `http://localhost:4200`:

```
Access to XMLHttpRequest at 'http://localhost:9000/oauth2/token'
from origin 'http://localhost:4200' has been blocked by CORS policy:
No 'Access-Control-Allow-Origin' header is present.
```

**Fix:** Add `http://localhost:4200` to `authserver.cors.allowed-origins` in `application.yml`

---

## Sequence Diagram

```
Angular App            Token Endpoint              Authorization Store
     │                       │                            │
     │──POST /oauth2/token──>│                            │
     │   grant_type=auth_code│                            │
     │   code=ABC123         │                            │
     │   code_verifier=XYZ   │                            │
     │   client_id=spa-client│                            │
     │   redirect_uri=...    │                            │
     │                       │                            │
     │                       │──Lookup code ABC123───────>│
     │                       │                            │
     │                       │<──Authorization found──────│
     │                       │   code_challenge: E9M...   │
     │                       │   principal: user          │
     │                       │   scopes: [openid,...]     │
     │                       │                            │
     │                       │──PKCE Verify:              │
     │                       │  SHA256(XYZ) == E9M...?    │
     │                       │  YES ✓                     │
     │                       │                            │
     │                       │──Generate tokens:          │
     │                       │  - access_token (JWT)      │
     │                       │  - refresh_token           │
     │                       │  - id_token (JWT)          │
     │                       │                            │
     │                       │──Mark code as used────────>│
     │                       │                            │
     │<──200 OK──────────────│                            │
     │   {                   │                            │
     │     access_token,     │                            │
     │     refresh_token,    │                            │
     │     id_token,         │                            │
     │     expires_in: 3600  │                            │
     │   }                   │                            │
     │                       │                            │
     │──Store in localStorage│                            │
     │                       │                            │
     │──Clear PKCE state     │                            │
     │  from sessionStorage  │                            │
     │                       │                            │
     │──Redirect to /home    │                            │
```

---

## CORS Configuration for Token Endpoint

**File:** `application.yml` — Update `allowed-origins`:

```yaml
authserver:
  cors:
    allowed-origins:
      - http://localhost:4200      # Angular dev server
      - http://localhost:3000      # Alternative dev server
      - https://webapp.company.com # Production
    allowed-methods:
      - GET
      - POST
    allowed-headers:
      - Content-Type
      - Authorization
      - Accept
    allow-credentials: true
```

---

## Key Points

1. **code_verifier is the PKCE proof** — Server verifies SHA256(verifier) matches stored challenge
2. **No client_secret needed** — Public client authentication via PKCE
3. **Code is single-use** — Server marks as used immediately
4. **Three tokens returned** — access_token, refresh_token, id_token
5. **Tokens stored in localStorage** — Accessible across sessions
6. **PKCE state cleared** — No longer needed after successful exchange
7. **CORS must allow origin** — Token endpoint must accept requests from Angular origin
