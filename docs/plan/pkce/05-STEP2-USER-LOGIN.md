# 05 - Step 2: User Login

## Flow Position

```
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: Authorization Request  ✓                               │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  ▶ STEP 2: User Login  ◀  (YOU ARE HERE)                       │
│                                                                 │
│  Authorization Server shows login form                          │
│  User enters credentials                                        │
│  Server authenticates user                                      │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Authorization Code                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Login Page UI

### Default Spring Security Login Page

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│                         Please sign in                          │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Username                                                  │  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │ user                                                │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │ Password                                                  │  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │ ********                                            │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │              Sign in                                │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### HTML Form Structure (Default)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Please sign in</title>
    <style>
        /* Default Spring Security styles */
    </style>
</head>
<body>
    <div class="container">
        <form class="form-signin" method="post" action="/login">
            <h2>Please sign in</h2>

            <label for="username">Username</label>
            <input type="text"
                   id="username"
                   name="username"
                   placeholder="Username"
                   required
                   autofocus>

            <label for="password">Password</label>
            <input type="password"
                   id="password"
                   name="password"
                   placeholder="Password"
                   required>

            <!-- CSRF Token (auto-generated) -->
            <input type="hidden"
                   name="_csrf"
                   value="abc123-csrf-token-xyz">

            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>
```

---

## User Credentials Capture

### Form Fields

| Field | Name | Type | Required | Description |
|-------|------|------|----------|-------------|
| Username | `username` | text | Yes | User's login name |
| Password | `password` | password | Yes | User's password |
| CSRF Token | `_csrf` | hidden | Yes | Auto-generated, prevents CSRF |

### Test User Credentials

| Username | Password | Roles | Notes |
|----------|----------|-------|-------|
| `user` | `password` | ROLE_USER | Normal user |
| `admin` | `admin` | ROLE_USER, ROLE_ADMIN | Admin user |

---

## Login Form Submission

### Request

```
POST http://localhost:9000/login
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=abc123...

username=user&password=password&_csrf=abc123-csrf-token-xyz
```

### Request Headers

```
POST /login HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Cookie: JSESSIONID=abc123...
Origin: http://localhost:9000
Referer: http://localhost:9000/login
```

### Request Body (Form Data)

```
username=user
password=password
_csrf=abc123-csrf-token-xyz
```

---

## Server-Side Authentication

### Authentication Flow

```
1. Receive POST /login

2. CSRF Validation:
   - Token from form: "abc123-csrf-token-xyz"
   - Token from session: "abc123-csrf-token-xyz"
   - Match? YES ✓

3. Load User Details:
   - UserDetailsService.loadUserByUsername("user")
   - Found: {
       username: "user",
       password: "{noop}password",
       roles: ["ROLE_USER"],
       enabled: true,
       accountNonLocked: true,
       accountNonExpired: true,
       credentialsNonExpired: true
     }

4. Password Verification:
   - Submitted: "password"
   - Stored: "{noop}password"
   - Encoder: NoOpPasswordEncoder (for {noop} prefix)
   - Match? YES ✓

5. Create Authentication Object:
   - UsernamePasswordAuthenticationToken
   - Principal: User("user")
   - Authorities: [ROLE_USER]
   - Authenticated: true

6. Store in SecurityContext:
   - SecurityContextHolder.getContext()
     .setAuthentication(authentication)

7. Store in Session:
   - JSESSIONID linked to SecurityContext
   - Session now contains authenticated user

8. Resume OAuth2 Flow:
   - Retrieve pending authorization request
   - Generate authorization code
   - Redirect to callback
```

### Security Configuration

**File:** `SecurityConfig.java` (Line 44)

```java
.formLogin(Customizer.withDefaults())
```

This enables:
- Login page at `/login` (GET)
- Login processor at `/login` (POST)
- Default success redirect: original request URL
- Default failure redirect: `/login?error`

---

## Authentication Success

### Server Response

```
HTTP/1.1 302 Found
Location: http://localhost:4200/callback?code=AUTH_CODE&state=xyzABC123randomState
Set-Cookie: JSESSIONID=abc123...; Path=/; HttpOnly
```

### What Server Does

```
1. User authenticated successfully

2. Retrieve stored authorization request:
   - client_id: "spa-client"
   - redirect_uri: "http://localhost:4200/callback"
   - scope: ["openid", "profile", "read"]
   - state: "xyzABC123randomState"
   - code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

3. Check consent requirement:
   - spa-client has requireAuthorizationConsent: false
   - Skip consent screen

4. Generate authorization code:
   - Code: "AUTH_CODE_xyz123" (random, short-lived)
   - Store: {
       code: "AUTH_CODE_xyz123",
       client_id: "spa-client",
       user: "user",
       scopes: ["openid", "profile", "read"],
       code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
       code_challenge_method: "S256",
       redirect_uri: "http://localhost:4200/callback",
       created_at: timestamp,
       expires_at: timestamp + 5 minutes
     }

5. Redirect to callback with code and state
```

---

## Authentication Failure

### Scenario: Wrong Password

```
POST /login
username=user&password=wrongpassword&_csrf=...

Response:
HTTP/1.1 302 Found
Location: http://localhost:9000/login?error
```

### Login Page with Error

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ ⚠ Bad credentials                                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│                         Please sign in                          │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Username                                                  │  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │                                                     │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │ Password                                                  │  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │                                                     │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  │                                                           │  │
│  │ ┌─────────────────────────────────────────────────────┐   │  │
│  │ │              Sign in                                │   │  │
│  │ └─────────────────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Error Messages

| Scenario | Error Message |
|----------|---------------|
| Wrong password | "Bad credentials" |
| User not found | "Bad credentials" (same, security) |
| Account disabled | "User is disabled" |
| Account locked | "User account is locked" |
| Account expired | "User account has expired" |
| CSRF token invalid | "Invalid CSRF Token" |

---

## Session State After Login

### Server Session

```
JSESSIONID=abc123...
  - SecurityContext:
      - Authentication:
          - principal: User("user")
          - authorities: [ROLE_USER]
          - authenticated: true
  - pendingAuthorization: (cleared after code generation)
  - oauth2Authorization:
      - code: "AUTH_CODE_xyz123"
      - client_id: "spa-client"
      - user: "user"
      - scopes: ["openid", "profile", "read"]
      - code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
      - expires_at: timestamp + 5 minutes
```

### Browser State

```
URL: http://localhost:4200/callback?code=AUTH_CODE_xyz123&state=xyzABC123randomState

sessionStorage:
  pkce_state: {
    "codeVerifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "state": "xyzABC123randomState",
    "nonce": "abc123NonceValue",
    "redirectUri": "http://localhost:4200/callback"
  }
```

---

## Sequence Diagram

```
User              Browser           Auth Server            UserDetailsService
 │                   │                   │                        │
 │───Enter creds────>│                   │                        │
 │   user/password   │                   │                        │
 │                   │                   │                        │
 │───Click Sign in──>│                   │                        │
 │                   │                   │                        │
 │                   │───POST /login────>│                        │
 │                   │   username=user   │                        │
 │                   │   password=...    │                        │
 │                   │   _csrf=...       │                        │
 │                   │                   │                        │
 │                   │                   │──loadUserByUsername───>│
 │                   │                   │   ("user")             │
 │                   │                   │                        │
 │                   │                   │<──UserDetails──────────│
 │                   │                   │   username: user       │
 │                   │                   │   password: {noop}pass │
 │                   │                   │   roles: [USER]        │
 │                   │                   │                        │
 │                   │                   │──Verify password       │
 │                   │                   │  "password" matches?   │
 │                   │                   │  YES ✓                 │
 │                   │                   │                        │
 │                   │                   │──Create auth code      │
 │                   │                   │  Store with challenge  │
 │                   │                   │                        │
 │                   │<──302 Redirect────│                        │
 │                   │   ?code=AUTH_CODE │                        │
 │                   │   &state=xyz...   │                        │
 │                   │                   │                        │
 │<──Page redirects──│                   │                        │
 │   to callback     │                   │                        │
```

---

## Key Points

1. **Login page is server-side** — Angular app is not involved
2. **CSRF protection enabled** — Hidden token in form
3. **Session created** — JSESSIONID cookie set
4. **No consent screen** — spa-client has `requireAuthorizationConsent: false`
5. **Authorization code generated** — After successful login
6. **Redirect to Angular callback** — With code and state in URL
