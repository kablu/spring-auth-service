# 08 - Development Order & Dependencies

> Kis phase ko pehle implement karna hai, kis phase ki dependency kahan hai, aur testing strategy kya hogi.

---

## Implementation Sequence

```
PHASE 1 ─────────────────────────────────────────────────  CRITICAL (Do First)
│ 1.1 Password Hashing (BCrypt)
│ 1.2 Enforce HTTPS
│ 1.3 Disable H2 Console
│ 1.4 Switch to LDAPS
│ 1.5 Remove Hardcoded Credentials
│
├──── PHASE 2 ────────────────────────────────────────────  HIGH (Token Security)
│     │ 2.1 Token Blacklist Service      (depends on 1.x complete)
│     │ 2.2 DPoP Implementation          (depends on 2.1)
│     │ 2.3 Shorten Token Lifetimes      (independent)
│     │ 2.4 Add jti Claim                (depends on 2.1, needed for blacklist)
│     │
│     ├──── PHASE 3 ──────────────────────────────────────  HIGH (Rate Limiting)
│     │     │ 3.1 Rate Limiting Filter    (independent of Phase 2)
│     │     │ 3.2 Login Brute Force       (independent)
│     │     │ 3.3 Client Lockout          (independent)
│     │     │ 3.4 Redis Distributed       (depends on 3.1-3.3)
│     │     │
│     │     ├──── PHASE 4 ────────────────────────────────  MEDIUM (Audit)
│     │     │     │ 4.1 Audit Log Entity   (independent)
│     │     │     │ 4.2 Integrate Audit    (depends on 4.1)
│     │     │     │ 4.3 Structured Logging (depends on 4.1)
│     │     │     │ 4.4 Event Detection    (depends on 4.2, 3.2)
│     │     │     │ 4.5 Metrics Dashboard  (depends on 4.1)
│     │     │     │
│     │     │     ├──── PHASE 5 ──────────────────────────  MEDIUM (mTLS)
│     │     │     │     │ 5.1 mTLS Setup   (depends on 1.2 HTTPS)
│     │     │     │     │ 5.2 Device FP    (depends on 4.1 audit)
│     │     │     │     │ 5.3 Continuous   (depends on 2.1 blacklist)
│     │     │     │     │     Verification
│     │     │     │     │
│     │     │     │     ├──── PHASE 6 ────────────────────  LOW (Hardening)
│     │     │     │     │     6.1 Security Headers
│     │     │     │     │     6.2 CORS Tightening
│     │     │     │     │     6.3 Swagger Protection
│     │     │     │     │     6.4 Actuator Protection
│     │     │     │     │     6.5 Session Security
│     │     │     │     │     6.6 Redirect URI Validation
```

---

## Dependency Map

```
Task           Depends On           Reason
────────────   ──────────────────   ─────────────────────────────
2.1 Blacklist  1.x (all)            Needs secure foundation first
2.2 DPoP       2.1, 2.4             Needs jti + blacklist for token binding
2.4 jti claim  None                 Can start early, but useful with 2.1
3.4 Redis      3.1, 3.2, 3.3       Distributed version of in-memory
4.2 Integrate  4.1                  Needs audit entity first
4.4 Detection  4.2 + 3.2            Needs audit + login tracking
5.1 mTLS       1.2                  Needs HTTPS infrastructure
5.2 Device FP  4.1                  Needs audit logging for new device alerts
5.3 Continuous 2.1                  Needs blacklist service for re-verification
```

---

## Parallel Development Opportunities

Yeh tasks simultaneously develop ho sakte hain (no dependencies between them):

### Parallel Track A: Security Foundation
```
Developer 1:
  1.1 Password Hashing → 1.5 Remove Hardcoded Creds → 2.4 jti Claim
```

### Parallel Track B: Infrastructure
```
Developer 2:
  1.2 HTTPS Setup → 1.3 H2 Disable → 1.4 LDAPS
```

### Parallel Track C: Rate Limiting
```
Developer 3 (can start after Phase 1):
  3.1 Rate Limit Filter → 3.2 Login Lockout → 3.3 Client Lockout
```

### Parallel Track D: Audit & Monitoring
```
Developer 4 (can start after Phase 1):
  4.1 Audit Entity → 4.3 Structured Logging → 4.5 Metrics
```

---

## New Files Summary (All Phases)

### Java Source Files

| # | File Path (under src/main/java/com/corp/authserver/) | Phase |
|---|------------------------------------------------------|-------|
| 1 | `service/LdapUserDetailsService.java` | Phase 1 |
| 2 | `entity/TokenBlacklist.java` | Phase 2 |
| 3 | `repository/TokenBlacklistRepository.java` | Phase 2 |
| 4 | `service/TokenBlacklistService.java` | Phase 2 |
| 5 | `security/BlacklistTokenValidator.java` | Phase 2 |
| 6 | `security/DPoPProofValidator.java` | Phase 2 |
| 7 | `security/DPoPTokenCustomizer.java` | Phase 2 |
| 8 | `filter/DPoPFilter.java` | Phase 2 |
| 9 | `filter/RateLimitFilter.java` | Phase 3 |
| 10 | `service/RateLimitService.java` | Phase 3 |
| 11 | `service/LoginAttemptService.java` | Phase 3 |
| 12 | `security/AuthenticationFailureListener.java` | Phase 3 |
| 13 | `security/AuthenticationSuccessListener.java` | Phase 3 |
| 14 | `entity/AuditLog.java` | Phase 4 |
| 15 | `repository/AuditLogRepository.java` | Phase 4 |
| 16 | `service/AuditEventService.java` | Phase 4 |
| 17 | `enums/AuditEventType.java` | Phase 4 |
| 18 | `security/SecurityEventDetector.java` | Phase 4 |
| 19 | `metrics/SecurityMetrics.java` | Phase 4 |
| 20 | `security/MtlsClientAuthenticationProvider.java` | Phase 5 |
| 21 | `config/MtlsConfig.java` | Phase 5 |
| 22 | `security/DeviceFingerprintValidator.java` | Phase 5 |
| 23 | `service/DeviceTrustService.java` | Phase 5 |
| 24 | `entity/TrustedDevice.java` | Phase 5 |
| 25 | `repository/TrustedDeviceRepository.java` | Phase 5 |
| 26 | `filter/ContinuousVerificationFilter.java` | Phase 5 |

### Modified Files

| # | File Path | Phases |
|---|-----------|--------|
| 1 | `config/SecurityConfig.java` | 1, 3, 6 |
| 2 | `config/AuthorizationServerConfig.java` | 1, 2, 5 |
| 3 | `service/ClientManagementService.java` | 1, 6 |
| 4 | `security/JwtTokenCustomizer.java` | 2, 4, 5 |
| 5 | `src/main/resources/application.yml` | 1, 2, 5, 6 |
| 6 | `src/main/resources/schema.sql` | 4, 5 |
| 7 | `controller/ClientManagementController.java` | 4 |
| 8 | `controller/KeyManagementController.java` | 4 |
| 9 | `pom.xml` | 1, 3 |

### New Resource Files

| # | File Path | Phase |
|---|-----------|-------|
| 1 | `application-prod.yml` | Phase 1 |
| 2 | `application-dev.yml` | Phase 1 |
| 3 | `keystore.p12` (SSL) | Phase 1 |
| 4 | `generate-ssl-cert.sh` | Phase 1 |
| 5 | `logback-spring.xml` | Phase 4 |
| 6 | `server-keystore.p12` | Phase 5 |
| 7 | `truststore.p12` | Phase 5 |
| 8 | `generate-certs.sh` | Phase 5 |

---

## Testing Strategy Per Phase

### Phase 1 Tests

```
Test: BCrypt passwords work with existing login flow
Test: HTTPS redirect from HTTP
Test: H2 console returns 403
Test: LDAPS connection succeeds
Test: Hardcoded users removed, LDAP users can login
```

### Phase 2 Tests

```
Test: Token with jti claim present
Test: Revoked token returns 401 (blacklist check)
Test: Revoked token introspection returns active=false
Test: DPoP proof required for DPoP-bound tokens
Test: DPoP-bound token rejected without proof
Test: Short-lived token expires in 5 minutes
Test: Refresh token rotation generates new refresh token
```

### Phase 3 Tests

```
Test: 61st request in 1 minute returns 429
Test: Rate limit resets after 1 minute
Test: 6th failed login returns 423 Locked
Test: Account unlocks after 15 minutes
Test: Successful login resets failure counter
Test: Client locked after 5 wrong secrets
```

### Phase 4 Tests

```
Test: Login success creates audit_log entry
Test: Login failure creates audit_log entry
Test: Token issuance logged
Test: Client registration logged
Test: Key rotation logged
Test: Rate limit event logged
Test: Prometheus metrics endpoint returns custom metrics
Test: Audit log has correct IP, user-agent, timestamp
```

### Phase 5 Tests

```
Test: mTLS client authenticated with certificate
Test: mTLS client rejected without certificate
Test: mTLS client rejected with untrusted certificate
Test: Device fingerprint stored on first login
Test: Different device triggers suspicious activity alert
Test: Continuous verification rejects revoked token mid-request
```

### Phase 6 Tests

```
Test: Security headers present in all responses
Test: X-Frame-Options: DENY present
Test: CORS rejects non-whitelisted origins
Test: CORS allows only specific headers (not wildcard)
Test: Swagger UI requires authentication
Test: Swagger UI disabled in prod profile
Test: Actuator /metrics requires ADMIN role
Test: Redirect URI without HTTPS rejected
Test: Redirect URI with fragment rejected
Test: Session cookie has Secure, HttpOnly, SameSite flags
```

---

## Risk Assessment

| Phase | Risk if Skipped | Impact |
|-------|----------------|--------|
| Phase 1 | Passwords in plaintext, HTTP traffic, DB exposed | CRITICAL — data breach |
| Phase 2 | Stolen tokens usable indefinitely | HIGH — unauthorized access |
| Phase 3 | Brute force attacks succeed | HIGH — account compromise |
| Phase 4 | Cannot detect or investigate breaches | MEDIUM — compliance failure |
| Phase 5 | Device theft = full access | MEDIUM — advanced attacks |
| Phase 6 | XSS, clickjacking, CSRF possible | LOW — defense in depth |

---

## Definition of Done (Zero-Trust Checklist)

```
[ ] All passwords hashed with BCrypt
[ ] HTTPS enforced on all endpoints
[ ] H2 console disabled
[ ] LDAPS configured (encrypted LDAP)
[ ] No hardcoded credentials in code
[ ] Token blacklist implemented and active
[ ] jti claim present in all tokens
[ ] DPoP supported for public clients
[ ] Access tokens expire in 5 minutes
[ ] Refresh token rotation active
[ ] Rate limiting active on all endpoints
[ ] Login lockout after 5 failures
[ ] Client lockout after 5 failures
[ ] Audit logging for all security events
[ ] Structured logging for SIEM integration
[ ] Custom Prometheus metrics
[ ] Suspicious activity detection
[ ] mTLS for service-to-service
[ ] Device fingerprinting for user sessions
[ ] Continuous token verification
[ ] Security headers on all responses
[ ] CORS tightened per endpoint
[ ] Swagger protected/disabled in prod
[ ] Actuator endpoints protected
[ ] Session cookies with Secure, HttpOnly, SameSite
[ ] Redirect URIs validated (HTTPS, no wildcards)
```
