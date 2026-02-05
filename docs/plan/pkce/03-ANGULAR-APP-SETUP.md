# 03 - Angular Application Setup

## Project Structure

```
angular-oauth-app/
├── src/
│   ├── app/
│   │   ├── core/
│   │   │   ├── auth/
│   │   │   │   ├── auth.service.ts        # OAuth/PKCE logic
│   │   │   │   ├── auth.guard.ts          # Route protection
│   │   │   │   ├── auth.interceptor.ts    # Token attachment
│   │   │   │   ├── auth.config.ts         # OAuth configuration
│   │   │   │   ├── pkce.util.ts           # PKCE helper functions
│   │   │   │   └── token.model.ts         # Token interfaces
│   │   │   └── core.module.ts
│   │   ├── pages/
│   │   │   ├── login/
│   │   │   │   └── login.component.ts
│   │   │   ├── callback/
│   │   │   │   └── callback.component.ts  # OAuth callback handler
│   │   │   ├── home/
│   │   │   │   └── home.component.ts
│   │   │   └── profile/
│   │   │       └── profile.component.ts
│   │   ├── app.routes.ts
│   │   └── app.component.ts
│   ├── environments/
│   │   ├── environment.ts
│   │   └── environment.prod.ts
│   └── index.html
├── angular.json
└── package.json
```

## Dependencies

```bash
# Create new Angular project
ng new angular-oauth-app --routing --style=scss

# Install dependencies
npm install jwt-decode
```

**No OAuth library needed** — we'll implement PKCE manually for better understanding.

---

## Environment Configuration

**File:** `src/environments/environment.ts`

```typescript
export const environment = {
  production: false,

  // Authorization Server URLs
  auth: {
    issuer: 'http://localhost:9000',
    authorizationEndpoint: 'http://localhost:9000/oauth2/authorize',
    tokenEndpoint: 'http://localhost:9000/oauth2/token',
    userinfoEndpoint: 'http://localhost:9000/userinfo',
    jwksEndpoint: 'http://localhost:9000/oauth2/jwks',
    revocationEndpoint: 'http://localhost:9000/oauth2/revoke',

    // Client configuration
    clientId: 'spa-client',
    redirectUri: 'http://localhost:4200/callback',
    postLogoutRedirectUri: 'http://localhost:4200',

    // Scopes to request
    scope: 'openid profile read',

    // PKCE settings
    codeChallengeMethod: 'S256'
  },

  // Resource Server URL
  apiUrl: 'http://localhost:8080/api'
};
```

---

## PKCE Utility Functions

**File:** `src/app/core/auth/pkce.util.ts`

```typescript
/**
 * PKCE (Proof Key for Code Exchange) utility functions
 * RFC 7636 implementation
 */

/**
 * Generate cryptographically random code_verifier
 * Length: 43-128 characters (we use 43 for consistency)
 * Characters: [A-Z] [a-z] [0-9] - . _ ~
 */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32); // 32 bytes = 43 base64url chars
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Generate code_challenge from code_verifier using SHA-256
 * Formula: BASE64URL(SHA256(code_verifier))
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Generate random state parameter for CSRF protection
 */
export function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Generate random nonce for ID token validation (OIDC)
 */
export function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

/**
 * Base64 URL encoding (different from standard Base64)
 * - '+' becomes '-'
 * - '/' becomes '_'
 * - No '=' padding
 */
function base64UrlEncode(buffer: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
```

---

## Token Models

**File:** `src/app/core/auth/token.model.ts`

```typescript
/**
 * OAuth2 token response from authorization server
 */
export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;      // "Bearer"
  expires_in: number;      // Seconds until expiry
  scope?: string;
}

/**
 * Decoded JWT payload (Access Token)
 */
export interface AccessTokenPayload {
  sub: string;             // Subject (user ID)
  iss: string;             // Issuer
  aud: string | string[];  // Audience (client_id)
  exp: number;             // Expiration timestamp
  iat: number;             // Issued at timestamp
  nbf?: number;            // Not before timestamp
  jti?: string;            // JWT ID

  // Custom claims from JwtTokenCustomizer
  username: string;
  roles: string[];
  scope: string[];
  token_type: string;
}

/**
 * Decoded JWT payload (ID Token)
 */
export interface IdTokenPayload {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;

  // Custom claims
  preferred_username: string;
  roles: string[];
}

/**
 * PKCE state stored in sessionStorage
 */
export interface PkceState {
  codeVerifier: string;
  state: string;
  nonce: string;
  redirectUri: string;
}

/**
 * User profile (simplified)
 */
export interface UserProfile {
  username: string;
  roles: string[];
  email?: string;
  displayName?: string;
}
```

---

## Auth Configuration

**File:** `src/app/core/auth/auth.config.ts`

```typescript
import { environment } from '../../../environments/environment';

export const AUTH_CONFIG = {
  // Server endpoints
  issuer: environment.auth.issuer,
  authorizationEndpoint: environment.auth.authorizationEndpoint,
  tokenEndpoint: environment.auth.tokenEndpoint,
  userinfoEndpoint: environment.auth.userinfoEndpoint,
  revocationEndpoint: environment.auth.revocationEndpoint,

  // Client settings
  clientId: environment.auth.clientId,
  redirectUri: environment.auth.redirectUri,
  postLogoutRedirectUri: environment.auth.postLogoutRedirectUri,
  scope: environment.auth.scope,

  // PKCE
  codeChallengeMethod: environment.auth.codeChallengeMethod,

  // Storage keys
  storageKeys: {
    accessToken: 'access_token',
    refreshToken: 'refresh_token',
    idToken: 'id_token',
    tokenExpiry: 'token_expiry',
    pkceState: 'pkce_state'
  },

  // Token refresh buffer (refresh 5 min before expiry)
  refreshBufferSeconds: 300
};
```

---

## Auth Service (Main OAuth Logic)

**File:** `src/app/core/auth/auth.service.ts`

```typescript
import { Injectable } from '@angular/core';
import { HttpClient, HttpParams, HttpHeaders } from '@angular/common/http';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable, of, throwError } from 'rxjs';
import { map, catchError, tap } from 'rxjs/operators';
import { jwtDecode } from 'jwt-decode';

import { AUTH_CONFIG } from './auth.config';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  generateNonce
} from './pkce.util';
import {
  TokenResponse,
  AccessTokenPayload,
  IdTokenPayload,
  PkceState,
  UserProfile
} from './token.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private isAuthenticatedSubject = new BehaviorSubject<boolean>(false);
  public isAuthenticated$ = this.isAuthenticatedSubject.asObservable();

  private userProfileSubject = new BehaviorSubject<UserProfile | null>(null);
  public userProfile$ = this.userProfileSubject.asObservable();

  constructor(
    private http: HttpClient,
    private router: Router
  ) {
    // Check if user is already logged in on app init
    this.checkAuthentication();
  }

  /**
   * STEP 1: Initiate login flow
   * - Generate PKCE values
   * - Store in sessionStorage
   * - Redirect to authorization endpoint
   */
  async login(): Promise<void> {
    // Generate PKCE values
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateState();
    const nonce = generateNonce();

    // Store PKCE state for callback verification
    const pkceState: PkceState = {
      codeVerifier,
      state,
      nonce,
      redirectUri: AUTH_CONFIG.redirectUri
    };
    sessionStorage.setItem(
      AUTH_CONFIG.storageKeys.pkceState,
      JSON.stringify(pkceState)
    );

    // Build authorization URL
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: AUTH_CONFIG.clientId,
      redirect_uri: AUTH_CONFIG.redirectUri,
      scope: AUTH_CONFIG.scope,
      state: state,
      nonce: nonce,
      code_challenge: codeChallenge,
      code_challenge_method: AUTH_CONFIG.codeChallengeMethod
    });

    const authUrl = `${AUTH_CONFIG.authorizationEndpoint}?${params.toString()}`;

    console.log('[AuthService] Redirecting to authorization endpoint:', authUrl);

    // Redirect to authorization server
    window.location.href = authUrl;
  }

  /**
   * STEP 2: Handle callback after authorization
   * - Validate state
   * - Exchange code for tokens
   * - Store tokens
   */
  async handleCallback(code: string, state: string): Promise<void> {
    // Retrieve stored PKCE state
    const storedStateJson = sessionStorage.getItem(AUTH_CONFIG.storageKeys.pkceState);
    if (!storedStateJson) {
      throw new Error('No PKCE state found. Please login again.');
    }

    const pkceState: PkceState = JSON.parse(storedStateJson);

    // Validate state parameter (CSRF protection)
    if (state !== pkceState.state) {
      throw new Error('State mismatch. Possible CSRF attack.');
    }

    console.log('[AuthService] State validated, exchanging code for tokens');

    // Exchange authorization code for tokens
    await this.exchangeCodeForTokens(code, pkceState.codeVerifier);

    // Clear PKCE state
    sessionStorage.removeItem(AUTH_CONFIG.storageKeys.pkceState);

    // Update authentication state
    this.checkAuthentication();
  }

  /**
   * Exchange authorization code for tokens
   */
  private async exchangeCodeForTokens(
    code: string,
    codeVerifier: string
  ): Promise<void> {
    const body = new HttpParams()
      .set('grant_type', 'authorization_code')
      .set('code', code)
      .set('redirect_uri', AUTH_CONFIG.redirectUri)
      .set('client_id', AUTH_CONFIG.clientId)
      .set('code_verifier', codeVerifier);

    const headers = new HttpHeaders()
      .set('Content-Type', 'application/x-www-form-urlencoded');

    console.log('[AuthService] Token request body:', body.toString());

    const response = await this.http.post<TokenResponse>(
      AUTH_CONFIG.tokenEndpoint,
      body.toString(),
      { headers }
    ).toPromise();

    if (response) {
      this.storeTokens(response);
      console.log('[AuthService] Tokens received and stored');
    }
  }

  /**
   * Store tokens securely
   */
  private storeTokens(response: TokenResponse): void {
    localStorage.setItem(
      AUTH_CONFIG.storageKeys.accessToken,
      response.access_token
    );

    if (response.refresh_token) {
      localStorage.setItem(
        AUTH_CONFIG.storageKeys.refreshToken,
        response.refresh_token
      );
    }

    if (response.id_token) {
      localStorage.setItem(
        AUTH_CONFIG.storageKeys.idToken,
        response.id_token
      );
    }

    // Calculate and store expiry time
    const expiresAt = Date.now() + (response.expires_in * 1000);
    localStorage.setItem(
      AUTH_CONFIG.storageKeys.tokenExpiry,
      expiresAt.toString()
    );
  }

  /**
   * Get current access token
   */
  getAccessToken(): string | null {
    return localStorage.getItem(AUTH_CONFIG.storageKeys.accessToken);
  }

  /**
   * Check if access token is expired
   */
  isTokenExpired(): boolean {
    const expiry = localStorage.getItem(AUTH_CONFIG.storageKeys.tokenExpiry);
    if (!expiry) return true;

    const bufferMs = AUTH_CONFIG.refreshBufferSeconds * 1000;
    return Date.now() > (parseInt(expiry) - bufferMs);
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(): Promise<boolean> {
    const refreshToken = localStorage.getItem(AUTH_CONFIG.storageKeys.refreshToken);
    if (!refreshToken) {
      return false;
    }

    try {
      const body = new HttpParams()
        .set('grant_type', 'refresh_token')
        .set('refresh_token', refreshToken)
        .set('client_id', AUTH_CONFIG.clientId);

      const headers = new HttpHeaders()
        .set('Content-Type', 'application/x-www-form-urlencoded');

      const response = await this.http.post<TokenResponse>(
        AUTH_CONFIG.tokenEndpoint,
        body.toString(),
        { headers }
      ).toPromise();

      if (response) {
        this.storeTokens(response);
        console.log('[AuthService] Token refreshed successfully');
        return true;
      }
      return false;
    } catch (error) {
      console.error('[AuthService] Token refresh failed:', error);
      this.logout();
      return false;
    }
  }

  /**
   * Check authentication state
   */
  private checkAuthentication(): void {
    const token = this.getAccessToken();
    const isExpired = this.isTokenExpired();

    if (token && !isExpired) {
      this.isAuthenticatedSubject.next(true);
      this.loadUserProfile();
    } else {
      this.isAuthenticatedSubject.next(false);
      this.userProfileSubject.next(null);
    }
  }

  /**
   * Load user profile from access token
   */
  private loadUserProfile(): void {
    const token = this.getAccessToken();
    if (!token) return;

    try {
      const decoded = jwtDecode<AccessTokenPayload>(token);
      const profile: UserProfile = {
        username: decoded.username,
        roles: decoded.roles
      };
      this.userProfileSubject.next(profile);
    } catch (error) {
      console.error('[AuthService] Failed to decode token:', error);
    }
  }

  /**
   * Logout - clear tokens and redirect
   */
  logout(): void {
    // Clear all stored tokens
    localStorage.removeItem(AUTH_CONFIG.storageKeys.accessToken);
    localStorage.removeItem(AUTH_CONFIG.storageKeys.refreshToken);
    localStorage.removeItem(AUTH_CONFIG.storageKeys.idToken);
    localStorage.removeItem(AUTH_CONFIG.storageKeys.tokenExpiry);
    sessionStorage.removeItem(AUTH_CONFIG.storageKeys.pkceState);

    // Update state
    this.isAuthenticatedSubject.next(false);
    this.userProfileSubject.next(null);

    // Redirect to home or login
    this.router.navigate(['/']);

    console.log('[AuthService] User logged out');
  }

  /**
   * Get decoded access token payload
   */
  getDecodedAccessToken(): AccessTokenPayload | null {
    const token = this.getAccessToken();
    if (!token) return null;

    try {
      return jwtDecode<AccessTokenPayload>(token);
    } catch {
      return null;
    }
  }

  /**
   * Get decoded ID token payload
   */
  getDecodedIdToken(): IdTokenPayload | null {
    const token = localStorage.getItem(AUTH_CONFIG.storageKeys.idToken);
    if (!token) return null;

    try {
      return jwtDecode<IdTokenPayload>(token);
    } catch {
      return null;
    }
  }

  /**
   * Check if user has specific role
   */
  hasRole(role: string): boolean {
    const decoded = this.getDecodedAccessToken();
    if (!decoded || !decoded.roles) return false;
    return decoded.roles.includes(role) || decoded.roles.includes(`ROLE_${role}`);
  }
}
```

---

## Summary: What This Service Does

| Method | Purpose |
|--------|---------|
| `login()` | Generate PKCE values, redirect to /oauth2/authorize |
| `handleCallback()` | Validate state, exchange code for tokens |
| `refreshToken()` | Silent token refresh using refresh_token |
| `logout()` | Clear tokens, update state |
| `getAccessToken()` | Return current access token |
| `isTokenExpired()` | Check if token needs refresh |
| `hasRole()` | Role-based access check |
