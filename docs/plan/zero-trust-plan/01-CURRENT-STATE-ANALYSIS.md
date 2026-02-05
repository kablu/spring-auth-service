# 01 - Current State Security Analysis

> Har finding ke saath exact file path aur line number diya hai taaki code mein directly navigate kar sako.

---

## CRITICAL Findings

### 1. Password Storage - Plaintext ({noop})

**Affected Files:**

| File | Line | Issue |
|------|------|-------|
| `SecurityConfig.java` | 62 | `{noop}password` — user password plaintext |
| `SecurityConfig.java` | 68 | `{noop}admin` — admin password plaintext |
| `AuthorizationServerConfig.java` | 61 | `{noop}web-client-secret` — client secret plaintext |
| `AuthorizationServerConfig.java` | 101 | `{noop}service-client-secret` — client secret plaintext |
| `ClientManagementService.java` | 45 | `"{noop}" + request.getClientSecret()` — dynamic client secrets also plaintext |

**What `{noop}` means:**
```
{noop} = NoOpPasswordEncoder = password stored AS-IS, no hashing
{bcrypt} = BCryptPasswordEncoder = password hashed with bcrypt (SECURE)

Current:  {noop}password        → stored as: password
Should:   {bcrypt}$2a$10$xyz... → stored as: bcrypt hash
```

**Risk:** Database breach = all passwords exposed immediately.

---

### 2. HTTPS Not Enforced

| File | Line | Current Value |
|------|------|---------------|
| `AuthServerProperties.java` | 51 | `private boolean requireHttps = false` |
| `application.yml` | 107 | `require-https: false` |
| `SecurityConfig.java` | 51-53 | Conditional — only if property is true |

**Risk:** Tokens, credentials, authorization codes transmitted over plain HTTP.

---

### 3. H2 Console Enabled

| File | Line | Current Value |
|------|------|---------------|
| `application.yml` | 24 | `enabled: true` |
| `application.yml` | 25 | `path: /h2-console` |

**Risk:** Direct database access. Anyone can access `http://localhost:9000/h2-console` — no authentication required by default. Can read/modify all OAuth2 tables, client secrets, tokens.

---

### 4. LDAP Unencrypted

| File | Line | Current Value |
|------|------|---------------|
| `application.yml` | 36 | `urls: ldap://localhost:389` |
| `application.yml` | 39 | `password: ${LDAP_PASSWORD:changeit}` |

**Risk:** AD credentials (username/password) sent in plaintext over network. Default service account password is "changeit".

---

## HIGH Findings

### 5. CORS Overly Permissive

| File | Line | Issue |
|------|------|-------|
| `SecurityConfig.java` | 85 | `allowedHeaders: "*"` — any header accepted |
| `SecurityConfig.java` | 86 | `allowCredentials: true` — with wildcard headers |
| `SecurityConfig.java` | 89 | Applied to `/**` — ALL endpoints |

**Risk:** Cross-origin requests with credentials allowed from configured origins with ANY headers. Browsers will preflight but server accepts everything.

---

### 6. Rate Limiting Not Implemented

| File | Line | Status |
|------|------|--------|
| `AuthServerProperties.java` | 57-60 | `RateLimitProperties` class defined |
| `application.yml` | 111-114 | `rate-limit.enabled: true, requests-per-minute: 60` |

**Missing:** No `RateLimitFilter`, no `RateLimitInterceptor`, no implementation anywhere in code.

**Risk:** Token endpoint brute-forceable. Login endpoint has no lockout.

---

### 7. Token Blacklist Not Implemented

| File | Line | Status |
|------|------|--------|
| `schema.sql` | 66-77 | `token_blacklist` table defined |

**Missing:** No `TokenBlacklistService`, no `TokenBlacklistRepository`, no check on token validation.

**Risk:** Revoked tokens may still be accepted. The `/oauth2/revoke` endpoint uses Spring's default which marks authorization as voided, but custom blacklist table is unused.

---

### 8. Client Secrets Not Encrypted in Database

| File | Line | Issue |
|------|------|-------|
| `schema.sql` | 8 | `client_secret VARCHAR(200)` — plaintext storage |
| `ClientManagementService.java` | 45 | `"{noop}" + request.getClientSecret()` — no hashing |

**Risk:** Database dump = all client secrets exposed.

---

### 9. In-Memory Client Repository

| File | Line | Issue |
|------|------|-------|
| `AuthorizationServerConfig.java` | 114 | `InMemoryRegisteredClientRepository` |

**Risk:** All pre-configured clients lost on restart. Not suitable for multi-instance deployment.

---

## MEDIUM Findings

### 10. No Audit Logging

No `AuditLog` entity, no audit service, no security event logging. Only DEBUG-level logging in `JwtTokenCustomizer.java`.

**Risk:** Cannot answer "who issued which token when" or "who registered which client".

---

### 11. No Security Headers

| Missing Header | Purpose |
|---------------|---------|
| Content-Security-Policy | XSS protection |
| X-Content-Type-Options | MIME sniffing prevention |
| X-Frame-Options | Clickjacking prevention |
| Strict-Transport-Security | HTTPS enforcement |
| X-XSS-Protection | Browser XSS filter |
| Referrer-Policy | Referrer leakage prevention |

No `.headers()` configuration in `SecurityConfig.java` or `AuthorizationServerConfig.java`.

---

### 12. No Session Fixation Protection

`SecurityConfig.java` has no `.sessionManagement()` configuration. Default Spring Security behavior applies but no explicit session fixation protection, no concurrent session control.

---

### 13. Redirect URI Validation Weak

| File | Line | Issue |
|------|------|-------|
| `ClientManagementService.java` | 108-113 | Only checks if redirectUris is non-empty |

**Missing:** No check that redirect URIs use HTTPS. No pattern matching. No open redirect prevention.

---

### 14. Swagger UI Publicly Accessible

| File | Line | Issue |
|------|------|-------|
| `SecurityConfig.java` | 36-38 | `/swagger-ui/**`, `/v3/api-docs/**` whitelisted |

**Risk:** API schema enumeration without authentication.

---

### 15. Default Keystore Password

| File | Line | Issue |
|------|------|-------|
| `AuthServerProperties.java` | 38 | `password = "changeit"` |
| `application.yml` | 96 | `password: ${JWT_KEYSTORE_PASSWORD:changeit}` |

**Risk:** Well-known default password for Java keystores.

---

### 16. RSA Key Size

| File | Line | Current | Recommended |
|------|------|---------|-------------|
| `JwkConfig.java` | 48 | 2048-bit | 4096-bit for zero-trust |

2048-bit is acceptable currently but NIST recommends transitioning to larger keys.

---

### 17. No mTLS Support

`AuthorizationServerConfig.java` includes `tls_client_auth` as a client authentication method but no server-side TLS client certificate configuration exists.

---

### 18. No Device Trust / Token Binding

No DPoP (Demonstration of Proof-of-Possession), no device fingerprinting, no `cnf` (confirmation) claim in JWT tokens.

---

## Integration Points Summary

| System | Protocol | Config Location | Security Status |
|--------|----------|-----------------|-----------------|
| LDAP/AD | ldap:// (plaintext) | application.yml:36 | NOT SECURE |
| H2 Database | In-memory | application.yml:15-26 | CONSOLE EXPOSED |
| Actuator | HTTP | application.yml:69-80 | health/info PUBLIC |
| Swagger | HTTP | application.yml:131-137 | FULLY PUBLIC |
| Prometheus | HTTP | application.yml:76 | Metrics exposed |
