# 09 - Angular Components, Guards & Interceptors

## Complete Angular Project Structure

```
angular-oauth-app/
├── src/
│   ├── app/
│   │   ├── core/
│   │   │   ├── auth/
│   │   │   │   ├── auth.service.ts          ✓ (covered in 03)
│   │   │   │   ├── auth.guard.ts            ← This doc
│   │   │   │   ├── auth.interceptor.ts      ← This doc
│   │   │   │   ├── auth.config.ts           ✓ (covered in 03)
│   │   │   │   ├── pkce.util.ts             ✓ (covered in 03)
│   │   │   │   └── token.model.ts           ✓ (covered in 03)
│   │   │   └── core.module.ts
│   │   ├── pages/
│   │   │   ├── login/
│   │   │   │   └── login.component.ts       ← This doc
│   │   │   ├── callback/
│   │   │   │   └── callback.component.ts    ✓ (covered in 06)
│   │   │   ├── home/
│   │   │   │   └── home.component.ts        ← This doc
│   │   │   └── profile/
│   │   │       └── profile.component.ts     ← This doc
│   │   ├── shared/
│   │   │   ├── navbar/
│   │   │   │   └── navbar.component.ts      ← This doc
│   │   │   └── loading/
│   │   │       └── loading.component.ts
│   │   ├── app.routes.ts
│   │   ├── app.config.ts
│   │   └── app.component.ts
│   └── environments/
│       └── environment.ts
└── package.json
```

---

## Auth Guard (Route Protection)

**File:** `src/app/core/auth/auth.guard.ts`

```typescript
import { inject } from '@angular/core';
import { Router, CanActivateFn } from '@angular/router';
import { AuthService } from './auth.service';
import { map, take } from 'rxjs/operators';

/**
 * Route guard that checks if user is authenticated
 * Redirects to login if not authenticated
 */
export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.isAuthenticated$.pipe(
    take(1),
    map(isAuthenticated => {
      if (isAuthenticated) {
        return true;
      }

      // Store intended destination for redirect after login
      sessionStorage.setItem('auth_redirect', state.url);

      // Redirect to login
      router.navigate(['/login']);
      return false;
    })
  );
};

/**
 * Role-based guard
 * Usage: canActivate: [roleGuard(['ADMIN'])]
 */
export const roleGuard = (allowedRoles: string[]): CanActivateFn => {
  return (route, state) => {
    const authService = inject(AuthService);
    const router = inject(Router);

    // Check if user has any of the allowed roles
    const hasRole = allowedRoles.some(role => authService.hasRole(role));

    if (hasRole) {
      return true;
    }

    // User is authenticated but doesn't have required role
    router.navigate(['/unauthorized']);
    return false;
  };
};
```

---

## Auth Interceptor (Token Attachment)

**File:** `src/app/core/auth/auth.interceptor.ts`

```typescript
import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpErrorResponse
} from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, filter, take, switchMap } from 'rxjs/operators';
import { AuthService } from './auth.service';
import { environment } from '../../../environments/environment';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  private isRefreshing = false;
  private refreshTokenSubject = new BehaviorSubject<string | null>(null);

  constructor(private authService: AuthService) {}

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {

    // Skip token for auth server requests (except userinfo)
    if (this.isAuthServerRequest(request.url) &&
        !request.url.includes('/userinfo')) {
      return next.handle(request);
    }

    // Add token to API requests
    const token = this.authService.getAccessToken();
    if (token) {
      request = this.addToken(request, token);
    }

    return next.handle(request).pipe(
      catchError(error => {
        if (error instanceof HttpErrorResponse && error.status === 401) {
          return this.handle401Error(request, next);
        }
        return throwError(() => error);
      })
    );
  }

  private isAuthServerRequest(url: string): boolean {
    return url.startsWith(environment.auth.issuer);
  }

  private addToken(request: HttpRequest<any>, token: string): HttpRequest<any> {
    return request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  /**
   * Handle 401 errors by refreshing token
   * Uses a lock mechanism to prevent multiple refresh attempts
   */
  private handle401Error(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {

    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      return new Observable(observer => {
        this.authService.refreshToken().then(success => {
          this.isRefreshing = false;

          if (success) {
            const newToken = this.authService.getAccessToken();
            this.refreshTokenSubject.next(newToken);

            // Retry original request with new token
            next.handle(this.addToken(request, newToken!)).subscribe({
              next: (event) => observer.next(event),
              error: (err) => observer.error(err),
              complete: () => observer.complete()
            });
          } else {
            // Refresh failed, redirect to login
            this.authService.logout();
            observer.error(new Error('Session expired'));
          }
        });
      });
    } else {
      // Wait for refresh to complete, then retry
      return this.refreshTokenSubject.pipe(
        filter(token => token !== null),
        take(1),
        switchMap(token => next.handle(this.addToken(request, token!)))
      );
    }
  }
}
```

---

## App Configuration

**File:** `src/app/app.config.ts`

```typescript
import { ApplicationConfig, importProvidersFrom } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptors, HTTP_INTERCEPTORS } from '@angular/common/http';

import { routes } from './app.routes';
import { AuthInterceptor } from './core/auth/auth.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(),
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ]
};
```

---

## Routes Configuration

**File:** `src/app/app.routes.ts`

```typescript
import { Routes } from '@angular/router';
import { authGuard, roleGuard } from './core/auth/auth.guard';

export const routes: Routes = [
  {
    path: '',
    redirectTo: 'home',
    pathMatch: 'full'
  },
  {
    path: 'login',
    loadComponent: () => import('./pages/login/login.component')
      .then(m => m.LoginComponent),
    title: 'Login'
  },
  {
    path: 'callback',
    loadComponent: () => import('./pages/callback/callback.component')
      .then(m => m.CallbackComponent),
    title: 'Logging in...'
  },
  {
    path: 'home',
    loadComponent: () => import('./pages/home/home.component')
      .then(m => m.HomeComponent),
    canActivate: [authGuard],
    title: 'Home'
  },
  {
    path: 'profile',
    loadComponent: () => import('./pages/profile/profile.component')
      .then(m => m.ProfileComponent),
    canActivate: [authGuard],
    title: 'Profile'
  },
  {
    path: 'admin',
    loadComponent: () => import('./pages/admin/admin.component')
      .then(m => m.AdminComponent),
    canActivate: [authGuard, roleGuard(['ROLE_ADMIN'])],  // Admin only
    title: 'Admin Panel'
  },
  {
    path: 'unauthorized',
    loadComponent: () => import('./pages/unauthorized/unauthorized.component')
      .then(m => m.UnauthorizedComponent),
    title: 'Unauthorized'
  },
  {
    path: '**',
    redirectTo: 'home'
  }
];
```

---

## Login Component

**File:** `src/app/pages/login/login.component.ts`

```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="login-container">
      <div class="login-card">
        <h1>Welcome</h1>
        <p>Please sign in to continue to the application</p>

        <button
          class="login-btn"
          (click)="login()"
          [disabled]="isLoading">
          <span *ngIf="!isLoading">
            🔐 Sign in with SSO
          </span>
          <span *ngIf="isLoading">
            Redirecting...
          </span>
        </button>

        <div class="info">
          <p>You will be redirected to the company login page</p>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .login-container {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }

    .login-card {
      background: white;
      padding: 3rem;
      border-radius: 12px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.2);
      text-align: center;
      max-width: 400px;
      width: 90%;
    }

    h1 {
      margin-bottom: 0.5rem;
      color: #333;
    }

    p {
      color: #666;
      margin-bottom: 2rem;
    }

    .login-btn {
      width: 100%;
      padding: 1rem 2rem;
      font-size: 1.1rem;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }

    .login-btn:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
    }

    .login-btn:disabled {
      opacity: 0.7;
      cursor: not-allowed;
    }

    .info {
      margin-top: 2rem;
      font-size: 0.85rem;
      color: #888;
    }
  `]
})
export class LoginComponent implements OnInit {
  isLoading = false;

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    // If already authenticated, redirect to home
    this.authService.isAuthenticated$.subscribe(isAuth => {
      if (isAuth) {
        this.router.navigate(['/home']);
      }
    });
  }

  async login(): Promise<void> {
    this.isLoading = true;
    await this.authService.login();
  }
}
```

---

## Home Component

**File:** `src/app/pages/home/home.component.ts`

```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { NavbarComponent } from '../../shared/navbar/navbar.component';
import { UserProfile } from '../../core/auth/token.model';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, RouterModule, NavbarComponent],
  template: `
    <app-navbar></app-navbar>

    <div class="home-container">
      <div class="welcome-card">
        <h1>Welcome, {{ user?.username }}!</h1>
        <p>You are successfully logged in.</p>

        <div class="user-info">
          <div class="info-item">
            <span class="label">Username:</span>
            <span class="value">{{ user?.username }}</span>
          </div>
          <div class="info-item">
            <span class="label">Roles:</span>
            <span class="value">{{ user?.roles?.join(', ') }}</span>
          </div>
        </div>

        <div class="actions">
          <a routerLink="/profile" class="btn btn-primary">
            View Profile
          </a>
          <a *ngIf="isAdmin" routerLink="/admin" class="btn btn-secondary">
            Admin Panel
          </a>
        </div>
      </div>

      <div class="token-info">
        <h3>Session Info</h3>
        <div class="token-details">
          <p><strong>Token expires in:</strong> {{ tokenExpiresIn }} minutes</p>
          <p><strong>Scopes:</strong> {{ scopes }}</p>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .home-container {
      padding: 2rem;
      max-width: 800px;
      margin: 0 auto;
    }

    .welcome-card {
      background: white;
      padding: 2rem;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      margin-bottom: 2rem;
    }

    h1 {
      color: #333;
      margin-bottom: 0.5rem;
    }

    .user-info {
      background: #f8f9fa;
      padding: 1rem;
      border-radius: 8px;
      margin: 1.5rem 0;
    }

    .info-item {
      display: flex;
      gap: 1rem;
      padding: 0.5rem 0;
    }

    .label {
      font-weight: bold;
      color: #666;
      min-width: 100px;
    }

    .value {
      color: #333;
    }

    .actions {
      display: flex;
      gap: 1rem;
      margin-top: 1.5rem;
    }

    .btn {
      padding: 0.75rem 1.5rem;
      border-radius: 6px;
      text-decoration: none;
      font-weight: 500;
      transition: all 0.2s;
    }

    .btn-primary {
      background: #667eea;
      color: white;
    }

    .btn-secondary {
      background: #6c757d;
      color: white;
    }

    .token-info {
      background: white;
      padding: 1.5rem;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }

    .token-info h3 {
      margin-bottom: 1rem;
      color: #333;
    }

    .token-details p {
      margin: 0.5rem 0;
      color: #666;
    }
  `]
})
export class HomeComponent implements OnInit {
  user: UserProfile | null = null;
  isAdmin = false;
  tokenExpiresIn = 0;
  scopes = '';

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    // Subscribe to user profile updates
    this.authService.userProfile$.subscribe(profile => {
      this.user = profile;
      this.isAdmin = this.authService.hasRole('ADMIN');
    });

    // Calculate token expiry
    this.updateTokenExpiry();
    setInterval(() => this.updateTokenExpiry(), 60000); // Update every minute

    // Get scopes from token
    const decoded = this.authService.getDecodedAccessToken();
    if (decoded?.scope) {
      this.scopes = Array.isArray(decoded.scope)
        ? decoded.scope.join(', ')
        : decoded.scope;
    }
  }

  private updateTokenExpiry(): void {
    const expiry = localStorage.getItem('token_expiry');
    if (expiry) {
      const expiresAt = parseInt(expiry);
      const now = Date.now();
      this.tokenExpiresIn = Math.max(0, Math.floor((expiresAt - now) / 60000));
    }
  }
}
```

---

## Navbar Component

**File:** `src/app/shared/navbar/navbar.component.ts`

```typescript
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <nav class="navbar">
      <div class="nav-brand">
        <a routerLink="/home">Angular OAuth App</a>
      </div>

      <div class="nav-links" *ngIf="isAuthenticated$ | async">
        <a routerLink="/home" routerLinkActive="active">Home</a>
        <a routerLink="/profile" routerLinkActive="active">Profile</a>
      </div>

      <div class="nav-user" *ngIf="userProfile$ | async as user">
        <span class="username">{{ user.username }}</span>
        <button class="logout-btn" (click)="logout()">Logout</button>
      </div>
    </nav>
  `,
  styles: [`
    .navbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem 2rem;
      background: white;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }

    .nav-brand a {
      font-size: 1.25rem;
      font-weight: bold;
      color: #667eea;
      text-decoration: none;
    }

    .nav-links {
      display: flex;
      gap: 1.5rem;
    }

    .nav-links a {
      color: #666;
      text-decoration: none;
      padding: 0.5rem 0;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
    }

    .nav-links a:hover,
    .nav-links a.active {
      color: #667eea;
      border-bottom-color: #667eea;
    }

    .nav-user {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .username {
      color: #333;
      font-weight: 500;
    }

    .logout-btn {
      padding: 0.5rem 1rem;
      background: #dc3545;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      transition: background 0.2s;
    }

    .logout-btn:hover {
      background: #c82333;
    }
  `]
})
export class NavbarComponent {
  isAuthenticated$ = this.authService.isAuthenticated$;
  userProfile$ = this.authService.userProfile$;

  constructor(private authService: AuthService) {}

  logout(): void {
    this.authService.logout();
  }
}
```

---

## Profile Component

**File:** `src/app/pages/profile/profile.component.ts`

```typescript
import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../core/auth/auth.service';
import { NavbarComponent } from '../../shared/navbar/navbar.component';
import { AccessTokenPayload, IdTokenPayload } from '../../core/auth/token.model';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, NavbarComponent],
  template: `
    <app-navbar></app-navbar>

    <div class="profile-container">
      <h1>User Profile</h1>

      <div class="card">
        <h2>Access Token Claims</h2>
        <pre>{{ accessTokenJson }}</pre>
      </div>

      <div class="card">
        <h2>ID Token Claims</h2>
        <pre>{{ idTokenJson }}</pre>
      </div>

      <div class="card">
        <h2>Raw Tokens</h2>
        <div class="token-section">
          <h3>Access Token</h3>
          <textarea readonly>{{ accessToken }}</textarea>
        </div>
        <div class="token-section">
          <h3>Refresh Token</h3>
          <textarea readonly>{{ refreshToken }}</textarea>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .profile-container {
      padding: 2rem;
      max-width: 900px;
      margin: 0 auto;
    }

    h1 {
      margin-bottom: 2rem;
      color: #333;
    }

    .card {
      background: white;
      padding: 1.5rem;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      margin-bottom: 1.5rem;
    }

    .card h2 {
      color: #667eea;
      margin-bottom: 1rem;
      font-size: 1.1rem;
    }

    pre {
      background: #f8f9fa;
      padding: 1rem;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.85rem;
      line-height: 1.5;
    }

    .token-section {
      margin-bottom: 1rem;
    }

    .token-section h3 {
      font-size: 0.9rem;
      color: #666;
      margin-bottom: 0.5rem;
    }

    textarea {
      width: 100%;
      height: 100px;
      font-family: monospace;
      font-size: 0.75rem;
      padding: 0.5rem;
      border: 1px solid #ddd;
      border-radius: 4px;
      resize: vertical;
    }
  `]
})
export class ProfileComponent implements OnInit {
  accessToken = '';
  refreshToken = '';
  accessTokenJson = '';
  idTokenJson = '';

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    // Get raw tokens
    this.accessToken = this.authService.getAccessToken() || '';
    this.refreshToken = localStorage.getItem('refresh_token') || '';

    // Get decoded tokens
    const accessPayload = this.authService.getDecodedAccessToken();
    const idPayload = this.authService.getDecodedIdToken();

    this.accessTokenJson = JSON.stringify(accessPayload, null, 2);
    this.idTokenJson = JSON.stringify(idPayload, null, 2);
  }
}
```

---

## UI Screens Summary

| Screen | Route | Auth Required | Description |
|--------|-------|---------------|-------------|
| Login | `/login` | No | Login button, redirects to auth server |
| Callback | `/callback` | No | OAuth callback handler |
| Home | `/home` | Yes | Welcome page with user info |
| Profile | `/profile` | Yes | Token details and claims |
| Admin | `/admin` | Yes + ADMIN role | Admin-only panel |
| Unauthorized | `/unauthorized` | No | Access denied message |
