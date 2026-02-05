# 11 - Security Considerations

## PKCE Security Benefits

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PKCE ATTACK PREVENTION                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  WITHOUT PKCE                         WITH PKCE                         │
│  ───────────                          ─────────                         │
│                                                                         │
│  Attacker steals code ──────────>     Attacker steals code              │
│  Attacker exchanges code ─────>       Attacker tries to exchange        │
│  Attacker gets tokens ❌              Server: "Where's the verifier?"   │
│                                       Attacker: "???"                   │
│                                       Server: "Request denied" ✓        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Token Storage Security

### Options Comparison

| Storage Method | Persistence | Tab Scope | XSS Risk | CSRF Risk | Recommendation |
|---------------|-------------|-----------|----------|-----------|----------------|
| localStorage | Permanent | All tabs | HIGH | None | Avoid for sensitive apps |
| sessionStorage | Tab session | Single tab | HIGH | None | Better, but still XSS vulnerable |
| Memory (variable) | None | Single tab | LOW | None | Most secure, poor UX |
| HttpOnly Cookie | Permanent | All tabs | NONE | HIGH | Best for tokens, needs CSRF protection |

### Current Implementation: localStorage

```typescript
// Current approach (simple, common for SPAs)
localStorage.setItem('access_token', response.access_token);
localStorage.setItem('refresh_token', response.refresh_token);
```

**Pros:**
- Persists across page refreshes
- Works across browser tabs
- Simple implementation

**Cons:**
- Accessible to JavaScript (XSS attack vector)
- Any injected script can steal tokens

---

## XSS (Cross-Site Scripting) Mitigation

### Threat Model

```
Attacker injects malicious script into page
       ↓
Script executes in user's browser
       ↓
Script reads localStorage
       ↓
Script sends tokens to attacker's server
       ↓
Attacker impersonates user ❌
```

### Mitigation Strategies

#### 1. Content Security Policy (CSP)

```html
<!-- In index.html or via HTTP header -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               style-src 'self' 'unsafe-inline';
               connect-src 'self' http://localhost:9000 http://localhost:8080;
               img-src 'self' data:;
               frame-ancestors 'none';">
```

#### 2. Input Sanitization (Angular Built-in)

```typescript
// Angular automatically sanitizes template bindings
// SAFE: Angular escapes HTML
<div>{{ userInput }}</div>

// DANGEROUS: Bypassing sanitization
<div [innerHTML]="userInput"></div>  // Only use with trusted content!
```

#### 3. Avoid Direct DOM Manipulation

```typescript
// DANGEROUS:
document.getElementById('output').innerHTML = userInput;

// SAFE:
document.getElementById('output').textContent = userInput;

// BEST: Use Angular bindings
<span>{{ userInput }}</span>
```

---

## CSRF (Cross-Site Request Forgery) Protection

### State Parameter

```typescript
// 1. Generate random state before redirect
const state = generateState();  // Random 22+ characters
sessionStorage.setItem('oauth_state', state);

// 2. Include in authorization request
GET /oauth2/authorize?...&state=xyz123

// 3. Server returns same state in callback
GET /callback?code=abc&state=xyz123

// 4. Validate state matches
if (receivedState !== sessionStorage.getItem('oauth_state')) {
  throw new Error('State mismatch - possible CSRF attack');
}
```

### Why State Prevents CSRF

```
CSRF Attack Attempt:
─────────────────────
1. Attacker creates malicious link:
   /callback?code=ATTACKER_CODE&state=ATTACKER_STATE

2. Victim clicks link

3. Victim's browser loads callback

4. Angular checks: ATTACKER_STATE !== stored_state

5. Attack BLOCKED ✓
```

---

## Nonce Validation (ID Token)

### What is Nonce?

```
Nonce = "Number used ONCE"

Purpose: Prevent ID token replay attacks
```

### Flow

```typescript
// 1. Generate nonce before authorization
const nonce = generateNonce();
sessionStorage.setItem('oauth_nonce', nonce);

// 2. Include in authorization request
GET /oauth2/authorize?...&nonce=abc123

// 3. Server includes nonce in ID token
{
  "sub": "user",
  "nonce": "abc123",  // <-- Same value
  ...
}

// 4. Validate nonce in ID token
const idToken = jwtDecode(response.id_token);
if (idToken.nonce !== sessionStorage.getItem('oauth_nonce')) {
  throw new Error('Nonce mismatch - possible replay attack');
}
```

---

## Token Lifetime Security

### Short-Lived Access Tokens

| Duration | Security | UX | Recommendation |
|----------|----------|-----|----------------|
| 5 min | Excellent | Poor (frequent refresh) | High-security apps |
| 15 min | Good | Good | Balanced approach |
| 1 hour | Moderate | Excellent | Current setting |
| 24 hours | Poor | Excellent | Not recommended |

### Current Configuration

```yaml
# application.yml
authserver:
  token:
    access-token-validity-seconds: 3600   # 1 hour
    refresh-token-validity-seconds: 2592000  # 30 days
```

### Recommendation for Production

```yaml
authserver:
  token:
    access-token-validity-seconds: 900   # 15 minutes
    refresh-token-validity-seconds: 86400  # 1 day
```

---

## Refresh Token Rotation

### Current Setting

```yaml
authserver:
  token:
    reuse-refresh-tokens: false  # Rotation ENABLED
```

### How Rotation Protects

```
WITHOUT Rotation:
  Refresh token RT_A used multiple times
  Attacker steals RT_A → Uses it forever

WITH Rotation (current):
  RT_A used → Get new access_token + RT_B
  RT_A is NOW INVALID

  If attacker stole RT_A:
    Attacker uses RT_A → Server sees it's old
    Server: "This token was already exchanged"
    Server MAY revoke ALL tokens for this user
    Attack detected and mitigated ✓
```

---

## Secure Communication

### HTTPS Requirements

| Environment | HTTPS | Enforcement |
|-------------|-------|-------------|
| Development | Optional | `require-https: false` |
| Production | MANDATORY | `require-https: true` |

### Current Configuration

```yaml
# application.yml
authserver:
  security:
    require-https: false  # CHANGE TO true IN PRODUCTION!
```

### Why HTTPS is Critical

```
HTTP (insecure):
  Tokens travel as plaintext
  Network attacker can intercept
  Man-in-the-middle attacks possible

HTTPS (secure):
  Tokens encrypted in transit
  Cannot be intercepted
  Server identity verified
```

---

## Redirect URI Security

### Validation Rules

| Rule | Why |
|------|-----|
| Exact match required | Prevent open redirect attacks |
| HTTPS required (prod) | Prevent interception |
| No wildcards | Prevent subdomain hijacking |
| No fragments (#) | Fragments stay in browser |

### Current Configuration

```java
// AuthorizationServerConfig.java
.redirectUri("http://localhost:4200/callback")   // Dev only
.redirectUri("http://localhost:3000/callback")   // Dev only
```

### Production Configuration

```java
// Only HTTPS in production
.redirectUri("https://app.company.com/callback")
.redirectUri("https://admin.company.com/callback")
```

---

## Security Checklist

### Development

- [ ] PKCE enforced for spa-client (`requireProofKey: true`)
- [ ] State parameter validated
- [ ] Nonce validated (for ID tokens)
- [ ] CORS configured for allowed origins
- [ ] CSRF protection enabled

### Production

- [ ] HTTPS enforced (`require-https: true`)
- [ ] Redirect URIs use HTTPS only
- [ ] Short token lifetimes (15 min access, 1 day refresh)
- [ ] Refresh token rotation enabled
- [ ] Content Security Policy headers
- [ ] Client secrets hashed (BCrypt)
- [ ] No hardcoded credentials
- [ ] Audit logging enabled
- [ ] Rate limiting implemented

---

## Security Headers (Server-Side)

### Recommended Headers

```java
// In SecurityConfig.java
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'"))
    .frameOptions(frame -> frame.deny())
    .xssProtection(xss -> xss
        .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
    .httpStrictTransportSecurity(hsts -> hsts
        .includeSubDomains(true)
        .maxAgeInSeconds(31536000))
);
```

### Response Headers

```
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
```

---

## Summary: Defense in Depth

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       SECURITY LAYERS                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Layer 1: PKCE                                                          │
│  └── Prevents authorization code interception                           │
│                                                                         │
│  Layer 2: State Parameter                                               │
│  └── Prevents CSRF attacks                                              │
│                                                                         │
│  Layer 3: Nonce (ID Token)                                              │
│  └── Prevents replay attacks                                            │
│                                                                         │
│  Layer 4: Short Token Lifetimes                                         │
│  └── Limits damage if tokens stolen                                     │
│                                                                         │
│  Layer 5: Refresh Token Rotation                                        │
│  └── Detects token theft, single-use refresh tokens                     │
│                                                                         │
│  Layer 6: HTTPS                                                         │
│  └── Encrypts all communication                                         │
│                                                                         │
│  Layer 7: Content Security Policy                                       │
│  └── Mitigates XSS attacks                                              │
│                                                                         │
│  Layer 8: Strict Redirect URIs                                          │
│  └── Prevents open redirect attacks                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```
