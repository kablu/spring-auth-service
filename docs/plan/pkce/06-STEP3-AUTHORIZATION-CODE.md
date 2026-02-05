# 06 - Step 3: Authorization Code Redirect

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
│  ▶ STEP 3: Authorization Code Redirect  ◀  (YOU ARE HERE)      │
│                                                                 │
│  Server redirects to Angular callback with code                 │
│  Angular validates state and extracts code                      │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 4: Token Request                                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Server Redirect Response

After successful login, authorization server redirects:

```
HTTP/1.1 302 Found
Location: http://localhost:4200/callback?code=dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz&state=xyzABC123randomState
Cache-Control: no-store
Pragma: no-cache
```

### Redirect URL Breakdown

```
http://localhost:4200/callback
    ?code=dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz
    &state=xyzABC123randomState
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `code` | `dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz` | Authorization code (one-time use) |
| `state` | `xyzABC123randomState` | Same value sent in Step 1 |

---

## Authorization Code Details

### Properties

| Property | Value |
|----------|-------|
| Format | Opaque string (base64-like) |
| Length | ~40-60 characters |
| Lifetime | 5 minutes (default) |
| Usage | One-time only |
| Storage | Server-side (in-memory or database) |

### Server-Side Storage

Authorization code is linked to:

```json
{
  "code": "dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz",
  "client_id": "spa-client",
  "principal": "user",
  "authorized_scopes": ["openid", "profile", "read"],
  "redirect_uri": "http://localhost:4200/callback",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "state": "xyzABC123randomState",
  "nonce": "abc123NonceValue",
  "created_at": "2026-02-05T10:30:00Z",
  "expires_at": "2026-02-05T10:35:00Z"
}
```

### Database Storage (oauth2_authorization table)

**File:** `schema.sql`

```sql
-- Stored in oauth2_authorization table
INSERT INTO oauth2_authorization (
    id,
    registered_client_id,
    principal_name,
    authorization_grant_type,
    authorized_scopes,
    state,
    authorization_code_value,
    authorization_code_issued_at,
    authorization_code_expires_at,
    authorization_code_metadata
) VALUES (
    'uuid-123',
    'spa-client-id',
    'user',
    'authorization_code',
    'openid,profile,read',
    'xyzABC123randomState',
    'dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz',
    '2026-02-05 10:30:00',
    '2026-02-05 10:35:00',
    '{"code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM","code_challenge_method":"S256"}'
);
```

---

## Angular Callback Component

**File:** `src/app/pages/callback/callback.component.ts`

```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-callback',
  template: `
    <div class="callback-container">
      <div *ngIf="!error" class="loading">
        <div class="spinner"></div>
        <p>Completing login...</p>
      </div>

      <div *ngIf="error" class="error">
        <h2>Login Failed</h2>
        <p>{{ error }}</p>
        <button (click)="retry()">Try Again</button>
      </div>
    </div>
  `,
  styles: [`
    .callback-container {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
    }
    .spinner {
      width: 50px;
      height: 50px;
      border: 5px solid #f3f3f3;
      border-top: 5px solid #3498db;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .error {
      color: #e74c3c;
      text-align: center;
    }
  `]
})
export class CallbackComponent implements OnInit {
  error: string | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService
  ) {}

  async ngOnInit(): Promise<void> {
    // Extract parameters from URL
    const code = this.route.snapshot.queryParamMap.get('code');
    const state = this.route.snapshot.queryParamMap.get('state');
    const error = this.route.snapshot.queryParamMap.get('error');
    const errorDescription = this.route.snapshot.queryParamMap.get('error_description');

    console.log('[Callback] Received params:', { code: code?.substring(0, 10) + '...', state, error });

    // Check for error response from server
    if (error) {
      this.error = errorDescription || error;
      console.error('[Callback] Authorization error:', error, errorDescription);
      return;
    }

    // Validate required parameters
    if (!code || !state) {
      this.error = 'Missing authorization code or state parameter';
      console.error('[Callback] Missing parameters');
      return;
    }

    try {
      // Handle the callback (validate state + exchange code for tokens)
      await this.authService.handleCallback(code, state);

      // Redirect to home or intended destination
      const redirectTo = sessionStorage.getItem('auth_redirect') || '/home';
      sessionStorage.removeItem('auth_redirect');

      console.log('[Callback] Login successful, redirecting to:', redirectTo);
      this.router.navigate([redirectTo]);

    } catch (err: any) {
      console.error('[Callback] Error handling callback:', err);
      this.error = err.message || 'Failed to complete login';
    }
  }

  retry(): void {
    this.router.navigate(['/login']);
  }
}
```

---

## State Validation (CSRF Protection)

### Why State Validation?

```
WITHOUT state validation:

1. Attacker creates their own authorization request
2. Attacker gets their own authorization code
3. Attacker tricks victim into loading:
   http://localhost:4200/callback?code=ATTACKER_CODE
4. Victim's browser exchanges ATTACKER_CODE for tokens
5. Victim is now logged in as ATTACKER! ❌

WITH state validation:

1. Angular stores state="xyz123" in sessionStorage
2. Server returns same state in redirect
3. Angular checks: received_state == stored_state?
4. If attacker sends their code with different state → REJECTED ✓
```

### Validation Flow

```typescript
// In AuthService.handleCallback():

// 1. Retrieve stored PKCE state
const storedStateJson = sessionStorage.getItem('pkce_state');
const pkceState: PkceState = JSON.parse(storedStateJson);

// 2. Compare state values
if (state !== pkceState.state) {
  throw new Error('State mismatch. Possible CSRF attack.');
}

// 3. If match, proceed with token exchange
```

---

## Angular Routing Configuration

**File:** `src/app/app.routes.ts`

```typescript
import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';

export const routes: Routes = [
  {
    path: '',
    redirectTo: 'home',
    pathMatch: 'full'
  },
  {
    path: 'login',
    loadComponent: () => import('./pages/login/login.component')
      .then(m => m.LoginComponent)
  },
  {
    path: 'callback',     // OAuth callback route
    loadComponent: () => import('./pages/callback/callback.component')
      .then(m => m.CallbackComponent)
  },
  {
    path: 'home',
    loadComponent: () => import('./pages/home/home.component')
      .then(m => m.HomeComponent),
    canActivate: [authGuard]  // Protected route
  },
  {
    path: 'profile',
    loadComponent: () => import('./pages/profile/profile.component')
      .then(m => m.ProfileComponent),
    canActivate: [authGuard]  // Protected route
  }
];
```

---

## Error Scenarios

### 1. State Mismatch

```
Stored state:   "xyzABC123randomState"
Received state: "differentValue"

Error: "State mismatch. Possible CSRF attack."
```

### 2. Missing Code

```
URL: http://localhost:4200/callback?state=xyz  (no code)

Error: "Missing authorization code or state parameter"
```

### 3. Authorization Denied by User

If consent was required and user denied:

```
URL: http://localhost:4200/callback
    ?error=access_denied
    &error_description=User%20denied%20the%20request
    &state=xyzABC123randomState

Error displayed: "User denied the request"
```

### 4. Server Error

```
URL: http://localhost:4200/callback
    ?error=server_error
    &error_description=Internal%20server%20error
    &state=xyzABC123randomState

Error displayed: "Internal server error"
```

### 5. PKCE State Not Found

```
// sessionStorage was cleared (browser closed, different tab)

Error: "No PKCE state found. Please login again."
```

---

## Sequence Diagram

```
Browser               Angular Callback              AuthService           sessionStorage
   │                        │                            │                      │
   │──Navigate to──────────>│                            │                      │
   │  /callback?code=X      │                            │                      │
   │  &state=Y              │                            │                      │
   │                        │                            │                      │
   │                        │──Extract code, state──────>│                      │
   │                        │  from URL params           │                      │
   │                        │                            │                      │
   │                        │                            │──Get pkce_state─────>│
   │                        │                            │                      │
   │                        │                            │<──pkce_state─────────│
   │                        │                            │  {verifier,state}    │
   │                        │                            │                      │
   │                        │                            │──Validate state      │
   │                        │                            │  Y == stored_state?  │
   │                        │                            │  YES ✓               │
   │                        │                            │                      │
   │                        │<──Proceed to token─────────│                      │
   │                        │   exchange                 │                      │
   │                        │                            │                      │
   │                        │   [STEP 4 STARTS]          │                      │
```

---

## Browser State at This Point

### URL

```
http://localhost:4200/callback?code=dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz&state=xyzABC123randomState
```

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

### What We Have

| Item | Value | Next Action |
|------|-------|-------------|
| Authorization Code | `dXNlci1hdXRob3JpemF0aW9uLWNvZGUtYWJjMTIz` | Send to token endpoint |
| Code Verifier | `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` | Send to token endpoint |
| State | Validated ✓ | No longer needed |

---

## Key Points

1. **Code is in URL** — visible in browser history (hence PKCE needed)
2. **State must match** — prevents CSRF attacks
3. **sessionStorage used** — PKCE state only available in same tab
4. **Code is one-time use** — can only be exchanged once
5. **Code expires quickly** — typically 5 minutes
6. **Next step** — exchange code + verifier for tokens
