# 04 - Step 1: Authorization Request

## Flow Position

```
┌─────────────────────────────────────────────────────────────────┐
│  ▶ STEP 1: Authorization Request  ◀  (YOU ARE HERE)            │
│                                                                 │
│  Angular App ──────> Authorization Server                       │
│  GET /oauth2/authorize?...                                      │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: User Login                                             │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Authorization Code                                     │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 4: Token Request                                          │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 5: Access Token (JWT)                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## User Action

User clicks "Login" button in Angular app.

## Angular Login Component

**File:** `src/app/pages/login/login.component.ts`

```typescript
import { Component } from '@angular/core';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-login',
  template: `
    <div class="login-container">
      <h1>Welcome to Angular OAuth App</h1>
      <p>Please login to continue</p>

      <button
        class="login-btn"
        (click)="login()"
        [disabled]="isLoading">
        {{ isLoading ? 'Redirecting...' : 'Login with SSO' }}
      </button>
    </div>
  `,
  styles: [`
    .login-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
    }
    .login-btn {
      padding: 12px 24px;
      font-size: 16px;
      background-color: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    .login-btn:hover {
      background-color: #0056b3;
    }
    .login-btn:disabled {
      background-color: #ccc;
      cursor: not-allowed;
    }
  `]
})
export class LoginComponent {
  isLoading = false;

  constructor(private authService: AuthService) {}

  async login(): Promise<void> {
    this.isLoading = true;
    await this.authService.login();
    // Page will redirect, so no need to set isLoading = false
  }
}
```

---

## What Happens When User Clicks Login

### Step 1.1: Generate PKCE Values

```typescript
// In AuthService.login():

// Generate code_verifier (random 43 chars)
const codeVerifier = generateCodeVerifier();
// Example: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// Generate code_challenge = SHA256(code_verifier)
const codeChallenge = await generateCodeChallenge(codeVerifier);
// Example: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// Generate state (CSRF protection)
const state = generateState();
// Example: "xyzABC123randomState"

// Generate nonce (ID token validation)
const nonce = generateNonce();
// Example: "abc123NonceValue"
```

### Step 1.2: Store PKCE State in Browser

```typescript
// Store in sessionStorage (not localStorage — more secure)
const pkceState: PkceState = {
  codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  state: "xyzABC123randomState",
  nonce: "abc123NonceValue",
  redirectUri: "http://localhost:4200/callback"
};

sessionStorage.setItem('pkce_state', JSON.stringify(pkceState));
```

### Step 1.3: Build Authorization URL

```typescript
const params = new URLSearchParams({
  response_type: 'code',
  client_id: 'spa-client',
  redirect_uri: 'http://localhost:4200/callback',
  scope: 'openid profile read',
  state: 'xyzABC123randomState',
  nonce: 'abc123NonceValue',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256'
});

const authUrl = `http://localhost:9000/oauth2/authorize?${params.toString()}`;
```

### Step 1.4: Redirect Browser

```typescript
window.location.href = authUrl;
```

---

## Complete Authorization Request

### Request URL

```
GET http://localhost:9000/oauth2/authorize?
    response_type=code
    &client_id=spa-client
    &redirect_uri=http://localhost:4200/callback
    &scope=openid%20profile%20read
    &state=xyzABC123randomState
    &nonce=abc123NonceValue
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
```

### Request Parameters Explained

| Parameter | Value | Description |
|-----------|-------|-------------|
| `response_type` | `code` | We want authorization code (not token) |
| `client_id` | `spa-client` | Registered client identifier |
| `redirect_uri` | `http://localhost:4200/callback` | Where to send code after login |
| `scope` | `openid profile read` | Permissions requested |
| `state` | random string | CSRF protection — server returns same value |
| `nonce` | random string | ID token replay protection |
| `code_challenge` | SHA256 hash | PKCE challenge (hashed verifier) |
| `code_challenge_method` | `S256` | SHA-256 hashing method |

---

## Server-Side Processing

### What Authorization Server Does

```
1. Receive GET /oauth2/authorize

2. Validate client_id:
   - "spa-client" exists? YES ✓
   - Client type: PUBLIC (no secret)

3. Validate redirect_uri:
   - "http://localhost:4200/callback" registered for spa-client? YES ✓

4. Validate response_type:
   - "code" supported? YES ✓

5. Validate scope:
   - "openid" allowed for spa-client? YES ✓
   - "profile" allowed? YES ✓
   - "read" allowed? YES ✓

6. PKCE Validation:
   - code_challenge present? YES (required for spa-client) ✓
   - code_challenge_method = S256? YES ✓

7. Check if user already authenticated:
   - Session exists? NO → Redirect to login page

8. Store PKCE challenge temporarily:
   - Key: will be linked to authorization code later
   - Value: { challenge: "E9Melhoa2...", method: "S256", state: "xyz..." }
```

### Server Response: Redirect to Login

```
HTTP/1.1 302 Found
Location: http://localhost:9000/login
Set-Cookie: JSESSIONID=abc123...; Path=/; HttpOnly
```

Browser automatically follows redirect to login page.

---

## Browser State After Step 1

### sessionStorage

```json
{
  "pkce_state": {
    "codeVerifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "state": "xyzABC123randomState",
    "nonce": "abc123NonceValue",
    "redirectUri": "http://localhost:4200/callback"
  }
}
```

### Browser URL

```
http://localhost:9000/login
```

### Server Session

```
JSESSIONID=abc123...
  - pendingAuthorization: {
      client_id: "spa-client",
      redirect_uri: "http://localhost:4200/callback",
      scope: ["openid", "profile", "read"],
      state: "xyzABC123randomState",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256"
    }
```

---

## Error Scenarios

### 1. Invalid client_id

```
GET /oauth2/authorize?client_id=unknown-client&...

Response:
HTTP/1.1 400 Bad Request
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

### 2. Invalid redirect_uri

```
GET /oauth2/authorize?redirect_uri=http://evil.com/callback&...

Response:
HTTP/1.1 400 Bad Request
{
  "error": "invalid_request",
  "error_description": "redirect_uri does not match registered value"
}
```

### 3. Missing code_challenge (for spa-client)

```
GET /oauth2/authorize?client_id=spa-client&...  (no code_challenge)

Response:
HTTP/1.1 400 Bad Request
{
  "error": "invalid_request",
  "error_description": "PKCE required for this client"
}
```

### 4. Invalid scope

```
GET /oauth2/authorize?scope=openid write admin&...

Response:
HTTP/1.1 400 Bad Request
{
  "error": "invalid_scope",
  "error_description": "Scope 'admin' is not allowed for this client"
}
```

---

## Sequence Diagram

```
User        Angular App           Browser              Auth Server
 │               │                    │                     │
 │──Click Login─>│                    │                     │
 │               │                    │                     │
 │               │──Generate PKCE────>│                     │
 │               │  verifier, challenge                     │
 │               │                    │                     │
 │               │──Store in──────────│                     │
 │               │  sessionStorage    │                     │
 │               │                    │                     │
 │               │──Build auth URL───>│                     │
 │               │                    │                     │
 │               │──window.location───│                     │
 │               │  .href = authUrl   │                     │
 │               │                    │                     │
 │               │                    │──GET /oauth2/authorize─>│
 │               │                    │   ?code_challenge=...  │
 │               │                    │                     │
 │               │                    │<──302 to /login─────│
 │               │                    │   Set-Cookie        │
 │               │                    │                     │
 │               │                    │──GET /login────────>│
 │               │                    │                     │
 │<──────────────│<───────────────────│<──Login Page HTML───│
 │  See login    │                    │                     │
 │  form         │                    │                     │
```

---

## Key Points

1. **code_verifier stays in browser** — never sent to server in Step 1
2. **code_challenge sent to server** — server stores it temporarily
3. **state sent to server** — server returns same value (CSRF check)
4. **sessionStorage used** — cleared on tab close (more secure than localStorage)
5. **Browser redirects** — Angular app unloads, login page loads
