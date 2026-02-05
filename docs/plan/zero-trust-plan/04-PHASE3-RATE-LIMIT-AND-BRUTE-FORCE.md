# 04 - Phase 3: Rate Limiting & Brute Force Protection (P1 - HIGH)

> Token endpoint aur login page ko brute force attacks se protect karna hai.

---

## Task 3.1: Implement Rate Limiting Filter

### Problem

`AuthServerProperties.java` mein `RateLimitProperties` defined hai (`enabled: true, requestsPerMinute: 60`) lekin koi actual filter implement nahi hai.

### Architecture

```
Client Request
      |
      v
+------------------+
| RateLimitFilter  |    <-- NEW
| (OncePerRequest) |
+------------------+
      |
      | Check: requests from this IP in last 1 min?
      |
      +--- > 60 per min? --> 429 Too Many Requests
      |
      +--- < 60 per min? --> Continue to next filter
      |
      v
+------------------+
| SecurityFilter   |
| Chain            |
+------------------+
```

### New Files to Create

| File | Purpose |
|------|---------|
| `filter/RateLimitFilter.java` | Servlet filter for request throttling |
| `service/RateLimitService.java` | Rate counting logic (in-memory or Redis) |

### Implementation Details

**1. RateLimitFilter.java**

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final AuthServerProperties properties;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) {
        if (!properties.getRateLimit().isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientIp = getClientIp(request);
        String endpoint = request.getRequestURI();

        if (rateLimitService.isRateLimited(clientIp, endpoint)) {
            response.setStatus(429);  // Too Many Requests
            response.setHeader("Retry-After", "60");
            response.getWriter().write("{\"error\":\"rate_limit_exceeded\"}");
            return;
        }

        rateLimitService.recordRequest(clientIp, endpoint);
        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
```

**2. RateLimitService.java (In-Memory with Sliding Window)**

```java
@Service
public class RateLimitService {

    // IP -> Endpoint -> List<Timestamp>
    private final ConcurrentHashMap<String, ConcurrentHashMap<String, Queue<Instant>>> requestLog;

    public boolean isRateLimited(String clientIp, String endpoint) {
        // Count requests in last 1 minute
        // If count >= requestsPerMinute (60) -> return true
    }

    public void recordRequest(String clientIp, String endpoint) {
        // Add current timestamp to queue
    }

    @Scheduled(fixedRate = 60000)  // Cleanup every minute
    public void cleanupOldEntries() {
        // Remove entries older than 1 minute
    }
}
```

### Rate Limits Per Endpoint

| Endpoint | Limit | Reason |
|----------|-------|--------|
| `POST /oauth2/token` | 30/min per IP | Token requests — high value target |
| `POST /login` | 10/min per IP | Login attempts — brute force target |
| `POST /api/clients` | 5/min per IP | Client registration — abuse prevention |
| `POST /api/keys/rotate` | 2/min per IP | Key rotation — sensitive operation |
| `GET /*` (default) | 60/min per IP | General reads |

### Response When Rate Limited

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests. Try again after 60 seconds.",
  "retry_after": 60
}
```

---

## Task 3.2: Login Brute Force Protection

### Problem

`POST /login` has no lockout mechanism. Attacker can try unlimited passwords.

### Architecture

```
Login Attempt (user: "admin", pass: "guess1")
      |
      v
+-------------------------+
| LoginAttemptService     |    <-- NEW
+-------------------------+
      |
      | Check: How many failed attempts for "admin"?
      |
      +--- >= 5 failures in 15 min? --> ACCOUNT LOCKED (15 min)
      |                                  Return 423 Locked
      |
      +--- < 5 failures? --> Allow login attempt
      |
      v
+-------------------------+
| Spring Authentication   |
+-------------------------+
      |
      +--- Success? --> Reset failure counter
      |
      +--- Failure? --> Increment failure counter
```

### New Files to Create

| File | Purpose |
|------|---------|
| `service/LoginAttemptService.java` | Track failed login attempts |
| `security/AuthenticationFailureListener.java` | Listen for failed auth events |
| `security/AuthenticationSuccessListener.java` | Listen for successful auth events |

### Implementation Details

**1. LoginAttemptService.java**

```java
@Service
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 15;

    // username -> List<failedAttemptTimestamp>
    private final ConcurrentHashMap<String, Queue<Instant>> failedAttempts;

    public boolean isBlocked(String username) {
        Queue<Instant> attempts = failedAttempts.get(username);
        if (attempts == null) return false;

        // Remove attempts older than LOCK_DURATION
        cleanOldAttempts(attempts);

        return attempts.size() >= MAX_ATTEMPTS;
    }

    public void loginFailed(String username) {
        failedAttempts
            .computeIfAbsent(username, k -> new ConcurrentLinkedQueue<>())
            .add(Instant.now());
    }

    public void loginSucceeded(String username) {
        failedAttempts.remove(username);  // Reset on success
    }
}
```

**2. AuthenticationFailureListener.java**

```java
@Component
public class AuthenticationFailureListener
    implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        loginAttemptService.loginFailed(username);
        log.warn("Failed login attempt for user: {} from IP: {}", username, ip);
    }
}
```

**3. AuthenticationSuccessListener.java**

```java
@Component
public class AuthenticationSuccessListener
    implements ApplicationListener<AuthenticationSuccessEvent> {

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        loginAttemptService.loginSucceeded(username);
    }
}
```

### Lockout Behavior

```
Attempt 1: wrong password → 401 Unauthorized ("Bad credentials")
Attempt 2: wrong password → 401 Unauthorized ("Bad credentials")
Attempt 3: wrong password → 401 Unauthorized ("Bad credentials")
Attempt 4: wrong password → 401 Unauthorized ("Bad credentials")
Attempt 5: wrong password → 401 Unauthorized ("Bad credentials")
Attempt 6: ANY password   → 423 Locked ("Account locked for 15 minutes")
...
After 15 minutes → Counter resets, login attempts allowed again
```

---

## Task 3.3: Client Credentials Brute Force Protection

### Problem

`POST /oauth2/token` with `grant_type=client_credentials` has no protection against client_secret guessing.

### Implementation

Same pattern as login lockout but keyed on `client_id`:

```java
// In RateLimitService or new ClientAuthAttemptService:

// Track failed client authentications
// After 5 failed attempts → block client_id for 30 minutes
// Log all failed attempts (audit trail)
```

### Response When Client Locked

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "client_locked",
  "error_description": "Client authentication locked due to multiple failed attempts. Try again after 30 minutes."
}
```

---

## Task 3.4: Distributed Rate Limiting (Production)

### Problem

In-memory rate limiting only works for single instance. Production needs distributed tracking.

### Solution: Redis-backed Rate Limiting

```
                 +---------------+
Instance 1 ----->|               |
                 |    Redis      |   Shared rate limit counters
Instance 2 ----->|               |
                 |  Key: rate:{ip}:{endpoint}
Instance 3 ----->|  Value: count |
                 |  TTL: 60 sec  |
                 +---------------+
```

### New Dependencies (pom.xml)

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

### Implementation Steps

1. Start with in-memory implementation (Task 3.1) — works for single instance
2. Create `RedisRateLimitService` implementing same interface
3. Use Spring profiles: `@Profile("!redis")` for in-memory, `@Profile("redis")` for Redis
4. Redis key format: `rate_limit:{ip}:{endpoint}` with TTL = 60 seconds
5. Use Redis `INCR` + `EXPIRE` for atomic counting

---

## Phase 3 Summary — Files

### New Files

| File | Purpose |
|------|---------|
| `filter/RateLimitFilter.java` | Request throttling filter |
| `service/RateLimitService.java` | In-memory rate counting |
| `service/LoginAttemptService.java` | Login lockout tracking |
| `security/AuthenticationFailureListener.java` | Failed login event handler |
| `security/AuthenticationSuccessListener.java` | Successful login event handler |

### Modified Files

| File | Changes |
|------|---------|
| `SecurityConfig.java` | Add login lockout check before authentication |
| `AuthorizationServerConfig.java` | Add client lockout check |
| `application.yml` | Rate limit config per endpoint |
| `pom.xml` | Redis dependency (for distributed mode) |
