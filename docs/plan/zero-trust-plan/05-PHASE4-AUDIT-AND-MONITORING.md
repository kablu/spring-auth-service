# 05 - Phase 4: Audit Logging & Monitoring (P2 - MEDIUM)

> Zero-Trust mein har action ka audit trail hona chahiye: "Who did what, when, from where?"

---

## Task 4.1: Audit Log Entity & Service

### Problem

Currently koi audit logging nahi hai. Token issuance, client registration, key rotation — kuch bhi track nahi ho raha.

### Architecture

```
Any Security Event
      |
      v
+-----------------------+
| AuditEventService     |    <-- NEW
+-----------------------+
      |
      v
+-----------------------+
| audit_log table       |    <-- NEW (DB)
+-----------------------+
      |
      v
+-----------------------+
| Structured Log Output |    <-- For SIEM integration
+-----------------------+
```

### New Files to Create

| File | Purpose |
|------|---------|
| `entity/AuditLog.java` | JPA Entity for audit events |
| `repository/AuditLogRepository.java` | Data access |
| `service/AuditEventService.java` | Audit logging service |
| `enums/AuditEventType.java` | Enum for event types |

### Database Schema Addition

**File: `schema.sql` — ADD:**

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,         -- TOKEN_ISSUED, CLIENT_REGISTERED, etc.
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    principal VARCHAR(200),                  -- Who (username or client_id)
    client_id VARCHAR(100),                  -- Which OAuth2 client
    ip_address VARCHAR(45),                  -- From where (IPv4/IPv6)
    user_agent VARCHAR(500),                 -- Browser/client info
    resource VARCHAR(500),                   -- What resource/endpoint
    action VARCHAR(50),                      -- CREATE, READ, UPDATE, DELETE
    outcome VARCHAR(20) NOT NULL,            -- SUCCESS, FAILURE, DENIED
    details TEXT,                             -- Additional JSON details
    token_id VARCHAR(255),                   -- Related token JTI (if applicable)
    session_id VARCHAR(255)                  -- Session tracking
);

CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log(principal);
CREATE INDEX IF NOT EXISTS idx_audit_event_time ON audit_log(event_time);
CREATE INDEX IF NOT EXISTS idx_audit_client_id ON audit_log(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_log(outcome);
```

### Audit Event Types

```java
public enum AuditEventType {
    // Authentication Events
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGIN_LOCKED,
    LOGOUT,

    // Token Events
    TOKEN_ISSUED,
    TOKEN_REFRESHED,
    TOKEN_REVOKED,
    TOKEN_INTROSPECTED,
    TOKEN_EXPIRED,

    // Client Management Events
    CLIENT_REGISTERED,
    CLIENT_RETRIEVED,
    CLIENT_UPDATED,
    CLIENT_DELETED,

    // Key Management Events
    KEY_ROTATED,
    KEY_EXPIRED_REMOVED,
    KEY_STATUS_CHECKED,

    // Authorization Events
    AUTHORIZATION_CONSENT_GRANTED,
    AUTHORIZATION_CONSENT_DENIED,
    AUTHORIZATION_CODE_ISSUED,

    // Security Events
    RATE_LIMIT_EXCEEDED,
    SUSPICIOUS_ACTIVITY,
    CORS_VIOLATION,
    INVALID_TOKEN_PRESENTED
}
```

### AuditEventService Usage

```java
@Service
@RequiredArgsConstructor
public class AuditEventService {

    private final AuditLogRepository repository;

    public void logEvent(AuditEventType eventType,
                         String principal,
                         String clientId,
                         HttpServletRequest request,
                         String outcome,
                         String details) {
        AuditLog log = AuditLog.builder()
            .eventType(eventType.name())
            .principal(principal)
            .clientId(clientId)
            .ipAddress(getClientIp(request))
            .userAgent(request.getHeader("User-Agent"))
            .resource(request.getRequestURI())
            .action(request.getMethod())
            .outcome(outcome)
            .details(details)
            .eventTime(Instant.now())
            .build();

        repository.save(log);

        // Also log as structured log for SIEM
        structuredLog.info("AUDIT event={} principal={} client={} ip={} outcome={}",
            eventType, principal, clientId, getClientIp(request), outcome);
    }
}
```

---

## Task 4.2: Integrate Audit into Existing Code

### Where to Add Audit Logging

**1. Token Issuance** — `JwtTokenCustomizer.java`

```java
// After customizing token claims:
auditService.logEvent(
    AuditEventType.TOKEN_ISSUED,
    principal.getName(),
    context.getRegisteredClient().getClientId(),
    request,
    "SUCCESS",
    "token_type=" + context.getTokenType().getValue()
);
```

**2. Client Registration** — `ClientManagementController.java`

```java
// After successful registration:
auditService.logEvent(AuditEventType.CLIENT_REGISTERED, ...);

// After failed registration (validation error):
auditService.logEvent(AuditEventType.CLIENT_REGISTERED, ..., "FAILURE", error);
```

**3. Key Rotation** — `KeyManagementController.java`

```java
// After rotation:
auditService.logEvent(AuditEventType.KEY_ROTATED, ...);
```

**4. Login Events** — `AuthenticationFailureListener.java` / `AuthenticationSuccessListener.java`

```java
// On success:
auditService.logEvent(AuditEventType.LOGIN_SUCCESS, username, ...);

// On failure:
auditService.logEvent(AuditEventType.LOGIN_FAILURE, username, ..., "FAILURE");

// On lockout:
auditService.logEvent(AuditEventType.LOGIN_LOCKED, username, ..., "DENIED");
```

**5. Rate Limiting** — `RateLimitFilter.java`

```java
// When rate limit hit:
auditService.logEvent(AuditEventType.RATE_LIMIT_EXCEEDED, ip, ..., "DENIED");
```

---

## Task 4.3: Structured Logging Format

### Log Format for SIEM Integration

All audit logs should follow a consistent structured format:

```
2026-02-05T10:30:00Z AUDIT event=TOKEN_ISSUED principal=user client=web-client ip=192.168.1.100 outcome=SUCCESS scope="openid profile" token_type=access_token
2026-02-05T10:30:05Z AUDIT event=LOGIN_FAILURE principal=admin client=null ip=10.0.0.50 outcome=FAILURE details="Bad credentials, attempt 3/5"
2026-02-05T10:30:10Z AUDIT event=RATE_LIMIT_EXCEEDED principal=null client=null ip=10.0.0.50 outcome=DENIED endpoint=/oauth2/token
2026-02-05T10:31:00Z AUDIT event=KEY_ROTATED principal=admin client=null ip=192.168.1.1 outcome=SUCCESS new_kid=x9y8z7w6 total_keys=2
```

### Logback Configuration

**File: `src/main/resources/logback-spring.xml` (NEW)**

```xml
<configuration>
    <!-- Audit log - separate file -->
    <appender name="AUDIT_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/audit.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/audit.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>90</maxHistory>  <!-- 90 days retention -->
        </rollingPolicy>
        <encoder>
            <pattern>%d{ISO8601} AUDIT %msg%n</pattern>
        </encoder>
    </appender>

    <logger name="AUDIT" level="INFO" additivity="false">
        <appender-ref ref="AUDIT_FILE" />
    </logger>
</configuration>
```

---

## Task 4.4: Security Event Detection

### Suspicious Activity Patterns

| Pattern | Trigger | Action |
|---------|---------|--------|
| Multiple failed logins | 5+ failures for same user in 15 min | Lock account + alert |
| Token reuse after revocation | Revoked token presented | Log SUSPICIOUS_ACTIVITY |
| Unusual IP | Login from new IP for user | Log for review |
| Burst token requests | 10+ token requests in 10 sec | Rate limit + alert |
| Client secret guessing | 3+ wrong secrets for client | Lock client + alert |
| Refresh token replay | Old refresh token reused | Revoke ALL tokens for user |

### Implementation

```java
@Component
public class SecurityEventDetector {

    @EventListener
    public void onAuthFailure(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        int recentFailures = loginAttemptService.getRecentFailureCount(username);

        if (recentFailures >= 3) {
            auditService.logEvent(AuditEventType.SUSPICIOUS_ACTIVITY,
                username, null, request, "WARNING",
                "Multiple failed logins: " + recentFailures);
            // Trigger alert (email, Slack, PagerDuty, etc.)
        }
    }
}
```

---

## Task 4.5: Monitoring Dashboard Metrics

### Custom Micrometer Metrics

```java
@Component
public class SecurityMetrics {

    private final MeterRegistry meterRegistry;

    // Counters
    Counter tokenIssuedCounter;      // authserver.tokens.issued
    Counter tokenRevokedCounter;     // authserver.tokens.revoked
    Counter loginSuccessCounter;     // authserver.login.success
    Counter loginFailureCounter;     // authserver.login.failure
    Counter rateLimitHitCounter;     // authserver.ratelimit.exceeded
    Counter clientRegisteredCounter; // authserver.clients.registered

    // Gauges
    Gauge activeTokensGauge;         // authserver.tokens.active
    Gauge activeKeysGauge;           // authserver.keys.active
    Gauge lockedAccountsGauge;       // authserver.accounts.locked
}
```

### Prometheus Endpoints (already enabled at `/actuator/prometheus`)

```
# Token metrics
authserver_tokens_issued_total{client="web-client",grant_type="authorization_code"} 150
authserver_tokens_issued_total{client="service-client",grant_type="client_credentials"} 500
authserver_tokens_revoked_total 10

# Login metrics
authserver_login_success_total 200
authserver_login_failure_total 15

# Rate limit
authserver_ratelimit_exceeded_total{endpoint="/oauth2/token"} 5

# Key rotation
authserver_keys_active 2
authserver_keys_rotation_total 3
```

---

## Phase 4 Summary — Files

### New Files

| File | Purpose |
|------|---------|
| `entity/AuditLog.java` | Audit log JPA entity |
| `repository/AuditLogRepository.java` | Audit data access |
| `service/AuditEventService.java` | Audit logging service |
| `enums/AuditEventType.java` | Event type enum |
| `security/SecurityEventDetector.java` | Suspicious activity detection |
| `metrics/SecurityMetrics.java` | Custom Micrometer metrics |
| `src/main/resources/logback-spring.xml` | Structured logging config |

### Modified Files

| File | Changes |
|------|---------|
| `schema.sql` | Add `audit_log` table |
| `JwtTokenCustomizer.java` | Add audit logging on token issuance |
| `ClientManagementController.java` | Add audit on client operations |
| `KeyManagementController.java` | Add audit on key operations |
| `RateLimitFilter.java` | Add audit on rate limit events |
| `AuthenticationFailureListener.java` | Add audit on failed logins |
| `AuthenticationSuccessListener.java` | Add audit on successful logins |
