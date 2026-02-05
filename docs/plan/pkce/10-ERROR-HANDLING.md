# 10 - Error Handling

## Error Types in PKCE Flow

| Error Location | Error Type | HTTP Status | Handling |
|---------------|------------|-------------|----------|
| Authorization Endpoint | OAuth2 error | Redirect | Show error page |
| Token Endpoint | OAuth2 error | 400/401 | Show error, retry |
| API Request | Token error | 401 | Refresh or re-login |
| Client-side | Validation error | N/A | Show error message |

---

## Authorization Endpoint Errors

### Error Response Format

```
http://localhost:4200/callback
    ?error=error_code
    &error_description=Human%20readable%20description
    &state=original_state_value
```

### Common Errors

| Error Code | Description | Cause | Resolution |
|------------|-------------|-------|------------|
| `invalid_request` | Missing required parameter | Bad client config | Fix client code |
| `invalid_client` | Client not found | Wrong client_id | Check client_id |
| `invalid_scope` | Scope not allowed | Requesting unauthorized scope | Request allowed scopes only |
| `access_denied` | User denied consent | User clicked "Deny" | Show user-friendly message |
| `server_error` | Server-side error | Auth server issue | Retry later |
| `temporarily_unavailable` | Server overloaded | High traffic | Retry later |

### Handling in Callback Component

```typescript
// In CallbackComponent.ngOnInit()

const error = this.route.snapshot.queryParamMap.get('error');
const errorDescription = this.route.snapshot.queryParamMap.get('error_description');

if (error) {
  console.error('[Callback] Authorization error:', error, errorDescription);

  switch (error) {
    case 'access_denied':
      this.error = 'You denied access to the application. Please try again and approve the request.';
      break;

    case 'invalid_request':
      this.error = 'Invalid request. Please try logging in again.';
      break;

    case 'server_error':
    case 'temporarily_unavailable':
      this.error = 'The server is temporarily unavailable. Please try again in a few minutes.';
      break;

    default:
      this.error = errorDescription || `Login failed: ${error}`;
  }
  return;
}
```

---

## Token Endpoint Errors

### Error Response Format

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

### Common Errors

| Error Code | HTTP | Description | Cause |
|------------|------|-------------|-------|
| `invalid_grant` | 400 | Grant (code/refresh_token) invalid | Code expired, used, or wrong verifier |
| `invalid_request` | 400 | Malformed request | Missing required parameter |
| `invalid_client` | 401 | Client authentication failed | Wrong client credentials |
| `unauthorized_client` | 400 | Client not allowed this grant type | Misconfigured client |
| `unsupported_grant_type` | 400 | Grant type not supported | Using wrong grant type |

### Handling in AuthService

```typescript
private async exchangeCodeForTokens(
  code: string,
  codeVerifier: string
): Promise<void> {
  try {
    const response = await this.http.post<TokenResponse>(
      AUTH_CONFIG.tokenEndpoint,
      body.toString(),
      { headers }
    ).toPromise();

    if (response) {
      this.storeTokens(response);
    }
  } catch (error: any) {
    // Handle HTTP error response
    if (error.error) {
      const oauthError = error.error;

      switch (oauthError.error) {
        case 'invalid_grant':
          throw new Error('Authorization code expired or invalid. Please login again.');

        case 'invalid_request':
          throw new Error('Invalid request. Please try logging in again.');

        default:
          throw new Error(
            oauthError.error_description ||
            `Token exchange failed: ${oauthError.error}`
          );
      }
    }

    throw new Error('Failed to exchange code for tokens. Please try again.');
  }
}
```

---

## Refresh Token Errors

### Error Scenarios

| Scenario | Error | Resolution |
|----------|-------|------------|
| Refresh token expired | `invalid_grant` | Re-authenticate |
| Refresh token revoked | `invalid_grant` | Re-authenticate |
| Refresh token reused | `invalid_grant` | All tokens revoked, re-authenticate |
| Wrong client | `invalid_client` | Check client configuration |

### Handling in AuthService

```typescript
async refreshToken(): Promise<boolean> {
  const refreshToken = localStorage.getItem('refresh_token');

  if (!refreshToken) {
    console.warn('[AuthService] No refresh token available');
    return false;
  }

  try {
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

  } catch (error: any) {
    console.error('[AuthService] Token refresh failed:', error);

    // Check specific error
    if (error.error?.error === 'invalid_grant') {
      console.warn('[AuthService] Refresh token is invalid or expired');
    }

    // Clear all tokens and redirect to login
    this.logout();
    return false;
  }
}
```

---

## Client-Side Validation Errors

### State Mismatch (CSRF Attack Prevention)

```typescript
// In AuthService.handleCallback()

const pkceState = JSON.parse(sessionStorage.getItem('pkce_state')!);

if (state !== pkceState.state) {
  throw new Error(
    'State mismatch detected. This could be a CSRF attack. ' +
    'Please try logging in again from the application.'
  );
}
```

### Missing PKCE State

```typescript
const storedStateJson = sessionStorage.getItem('pkce_state');

if (!storedStateJson) {
  throw new Error(
    'No login session found. This can happen if:\n' +
    '- You opened the callback URL directly\n' +
    '- Your browser cleared session storage\n' +
    '- You used a different browser tab\n\n' +
    'Please return to the application and login again.'
  );
}
```

### Missing URL Parameters

```typescript
if (!code || !state) {
  throw new Error(
    'Missing authorization response parameters. ' +
    'The login process may have been interrupted. ' +
    'Please try again.'
  );
}
```

---

## API Request Errors (401 Handling)

### Interceptor Error Handling

```typescript
// In AuthInterceptor

intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
  return next.handle(request).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401) {
        // Token expired or invalid
        return this.handle401Error(request, next);
      }

      if (error.status === 403) {
        // User doesn't have permission
        this.router.navigate(['/unauthorized']);
        return throwError(() => new Error('Access denied'));
      }

      // Other errors - pass through
      return throwError(() => error);
    })
  );
}

private handle401Error(
  request: HttpRequest<any>,
  next: HttpHandler
): Observable<HttpEvent<any>> {
  // Try to refresh token
  return from(this.authService.refreshToken()).pipe(
    switchMap(success => {
      if (success) {
        // Retry with new token
        const newToken = this.authService.getAccessToken();
        return next.handle(this.addToken(request, newToken!));
      } else {
        // Refresh failed - logout and redirect
        this.authService.logout();
        return throwError(() => new Error('Session expired. Please login again.'));
      }
    })
  );
}
```

---

## Error UI Components

### Error Display Component

```typescript
// src/app/shared/error-display/error-display.component.ts

@Component({
  selector: 'app-error-display',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="error-container" *ngIf="error">
      <div class="error-icon">⚠️</div>
      <h2>{{ title }}</h2>
      <p class="error-message">{{ error }}</p>
      <div class="error-actions">
        <button (click)="onRetry.emit()" *ngIf="showRetry">
          Try Again
        </button>
        <button (click)="onGoHome.emit()" class="secondary">
          Go to Home
        </button>
      </div>
    </div>
  `,
  styles: [`
    .error-container {
      text-align: center;
      padding: 2rem;
      max-width: 500px;
      margin: 2rem auto;
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }

    .error-icon {
      font-size: 3rem;
      margin-bottom: 1rem;
    }

    h2 {
      color: #dc3545;
      margin-bottom: 1rem;
    }

    .error-message {
      color: #666;
      margin-bottom: 1.5rem;
      white-space: pre-line;
    }

    .error-actions {
      display: flex;
      gap: 1rem;
      justify-content: center;
    }

    button {
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 500;
    }

    button:not(.secondary) {
      background: #007bff;
      color: white;
    }

    button.secondary {
      background: #6c757d;
      color: white;
    }
  `]
})
export class ErrorDisplayComponent {
  @Input() error: string | null = null;
  @Input() title = 'Something went wrong';
  @Input() showRetry = true;
  @Output() onRetry = new EventEmitter<void>();
  @Output() onGoHome = new EventEmitter<void>();
}
```

---

## Error Messages Summary

### User-Friendly Error Messages

| Technical Error | User-Friendly Message |
|----------------|----------------------|
| `invalid_grant` (code) | "Your login session expired. Please try again." |
| `invalid_grant` (refresh) | "Your session has ended. Please login again." |
| `access_denied` | "You cancelled the login. Click Login to try again." |
| `invalid_request` | "Something went wrong. Please try logging in again." |
| `server_error` | "The server is temporarily unavailable. Please try again later." |
| State mismatch | "Security check failed. Please start over from the application." |
| Network error | "Unable to connect. Please check your internet connection." |
| 401 Unauthorized | "Your session expired. Refreshing..." |
| 403 Forbidden | "You don't have permission to access this resource." |

---

## Logging for Debugging

### Console Logging Pattern

```typescript
// Debug level logging for development
console.log('[AuthService] Initiating login flow');
console.log('[AuthService] PKCE values generated', {
  challengeMethod: 'S256',
  stateLength: state.length
});

// Error logging
console.error('[AuthService] Token exchange failed:', {
  error: error.error?.error,
  description: error.error?.error_description,
  status: error.status
});

// Warning logging
console.warn('[AuthService] Token expired, attempting refresh');
console.warn('[AuthService] Refresh failed, redirecting to login');
```

### Production Logging

```typescript
// In production, send errors to monitoring service
if (environment.production) {
  // Example: Send to error tracking service
  errorTrackingService.captureException(error, {
    context: 'AuthService',
    action: 'tokenExchange',
    user: this.getCurrentUserId()
  });
}
```
