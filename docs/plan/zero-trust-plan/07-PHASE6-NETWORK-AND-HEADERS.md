# 07 - Phase 6: Network Security & Headers (P3 - LOW)

> Defense-in-depth: Multiple layers of security headers aur network controls.

---

## Task 6.1: Add Security Headers

### Problem

`SecurityConfig.java` aur `AuthorizationServerConfig.java` mein koi `.headers()` configuration nahi hai.

### What to Add

**File: `SecurityConfig.java` — modify `defaultSecurityFilterChain`:**

```java
http
    .headers(headers -> headers
        // Prevent clickjacking
        .frameOptions(frame -> frame.deny())

        // Prevent MIME type sniffing
        .contentTypeOptions(Customizer.withDefaults())

        // Enable XSS filter
        .xssProtection(xss -> xss.headerValue(
            XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))

        // Content Security Policy
        .contentSecurityPolicy(csp -> csp
            .policyDirectives("default-src 'self'; " +
                "script-src 'self'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data:; " +
                "font-src 'self'; " +
                "frame-ancestors 'none'; " +
                "form-action 'self'"))

        // HSTS - enforce HTTPS
        .httpStrictTransportSecurity(hsts -> hsts
            .includeSubDomains(true)
            .maxAgeInSeconds(31536000)    // 1 year
            .preload(true))

        // Referrer Policy
        .referrerPolicy(referrer -> referrer
            .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))

        // Permissions Policy
        .permissionsPolicy(permissions -> permissions
            .policy("camera=(), microphone=(), geolocation=(), payment=()"))
    );
```

### Response Headers After Implementation

```
HTTP/1.1 200 OK
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cache-Control: no-store                 (for token responses)
Pragma: no-cache                        (for token responses)
```

### Headers Explanation

| Header | Purpose | Attack Prevented |
|--------|---------|-----------------|
| X-Frame-Options: DENY | Page cannot be embedded in iframe | Clickjacking |
| X-Content-Type-Options: nosniff | Browser respects Content-Type | MIME sniffing attacks |
| X-XSS-Protection: 1; mode=block | Browser blocks XSS attempts | Reflected XSS |
| Content-Security-Policy | Controls what resources page can load | XSS, data injection |
| Strict-Transport-Security | Forces HTTPS for future requests | SSL stripping |
| Referrer-Policy | Controls referrer header leakage | Token leakage in URL |
| Permissions-Policy | Disables browser features | Feature abuse |
| Cache-Control: no-store | Prevents token caching | Token theft from cache |

---

## Task 6.2: Tighten CORS Configuration

### Problem

| Current | Issue |
|---------|-------|
| `allowedHeaders: "*"` | Accepts ANY header from cross-origin requests |
| Applied to `/**` | ALL endpoints have same CORS policy |
| `allowCredentials: true` | With wildcard headers — dangerous combination |

### What to Change

**File: `SecurityConfig.java` — modify `corsConfigurationSource`:**

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    // Config for OAuth2 endpoints
    CorsConfiguration oauthConfig = new CorsConfiguration();
    oauthConfig.setAllowedOrigins(properties.getCors().getAllowedOrigins());
    oauthConfig.setAllowedMethods(List.of("POST"));  // Token endpoint = POST only
    oauthConfig.setAllowedHeaders(List.of(
        "Authorization", "Content-Type", "Accept", "DPoP"
    ));  // SPECIFIC headers, not wildcard
    oauthConfig.setAllowCredentials(true);
    oauthConfig.setMaxAge(600L);  // 10 min, not 1 hour

    // Config for Management API
    CorsConfiguration apiConfig = new CorsConfiguration();
    apiConfig.setAllowedOrigins(List.of("https://admin.company.com"));  // Admin only
    apiConfig.setAllowedMethods(List.of("GET", "POST"));
    apiConfig.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    apiConfig.setAllowCredentials(true);

    // Config for JWKS (public, no credentials)
    CorsConfiguration jwksConfig = new CorsConfiguration();
    jwksConfig.setAllowedOrigins(List.of("*"));  // Anyone can fetch public keys
    jwksConfig.setAllowedMethods(List.of("GET"));
    jwksConfig.setAllowCredentials(false);  // No credentials for public endpoint

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/oauth2/token", oauthConfig);
    source.registerCorsConfiguration("/oauth2/authorize", oauthConfig);
    source.registerCorsConfiguration("/oauth2/revoke", oauthConfig);
    source.registerCorsConfiguration("/oauth2/introspect", oauthConfig);
    source.registerCorsConfiguration("/oauth2/jwks", jwksConfig);
    source.registerCorsConfiguration("/api/**", apiConfig);
    return source;
}
```

---

## Task 6.3: Protect Swagger UI

### Problem

`/swagger-ui/**` and `/v3/api-docs/**` are publicly accessible. Attackers can enumerate all API endpoints.

### Options

| Option | When to Use |
|--------|------------|
| Remove in production | Best for production |
| Require authentication | If API docs needed for internal teams |
| IP whitelist | If needed from specific networks only |

### Implementation — Profile-based

**File: `application.yml`:**

```yaml
# Default: Swagger enabled (development)
springdoc:
  swagger-ui:
    enabled: true
```

**File: `application-prod.yml` (NEW/MODIFY):**

```yaml
# Production: Swagger disabled
springdoc:
  swagger-ui:
    enabled: false
  api-docs:
    enabled: false
```

**File: `SecurityConfig.java` — conditional permit:**

```java
// Only permit Swagger if springdoc enabled
@Value("${springdoc.swagger-ui.enabled:false}")
private boolean swaggerEnabled;

// In security filter chain:
if (swaggerEnabled) {
    authorize.requestMatchers("/swagger-ui/**", "/v3/api-docs/**").authenticated();
    // Requires login, not public
} else {
    authorize.requestMatchers("/swagger-ui/**", "/v3/api-docs/**").denyAll();
}
```

---

## Task 6.4: Protect Actuator Endpoints

### Current State

| Endpoint | Current Access | Risk |
|----------|---------------|------|
| `/actuator/health` | PUBLIC | LOW — acceptable |
| `/actuator/info` | PUBLIC | LOW — may leak version info |
| `/actuator/metrics` | Authenticated | MEDIUM — performance data |
| `/actuator/prometheus` | Authenticated | MEDIUM — detailed metrics |

### What to Change

**File: `application.yml`:**

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health           # Only health publicly
      base-path: /internal/actuator   # Non-standard path
  endpoint:
    health:
      show-details: never         # No details, just UP/DOWN
    info:
      enabled: false              # Disable info endpoint
```

**File: `SecurityConfig.java`:**

```java
// Actuator - only health is public, rest needs admin
authorize.requestMatchers("/internal/actuator/health").permitAll();
authorize.requestMatchers("/internal/actuator/**").hasRole("ADMIN");
```

---

## Task 6.5: Session Security

### Problem

No explicit session configuration. Defaults may not be secure enough.

### What to Add

**File: `SecurityConfig.java`:**

```java
http
    .sessionManagement(session -> session
        // Session fixation protection
        .sessionFixation(fixation -> fixation.migrateSession())

        // Max concurrent sessions per user
        .maximumSessions(1)

        // Session creation policy for API endpoints
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    );
```

**File: `application.yml`:**

```yaml
server:
  servlet:
    session:
      cookie:
        http-only: true          # Cannot be accessed by JavaScript
        secure: true             # Only sent over HTTPS
        same-site: strict        # CSRF protection
        name: __Host-SESSIONID   # Secure cookie prefix
        max-age: 1800            # 30 min session timeout
      timeout: 30m               # Server-side session timeout
```

### Session Cookie Headers After Implementation

```
Set-Cookie: __Host-SESSIONID=abc123;
  Path=/;
  Secure;
  HttpOnly;
  SameSite=Strict;
  Max-Age=1800
```

---

## Task 6.6: Redirect URI Validation

### Problem

`ClientManagementService.java` line 108-113 only checks if redirect URIs are non-empty. No format validation.

### What to Add

```java
private void validateRedirectUris(ClientRegistrationRequest request) {
    // Existing: check non-empty for auth_code grant
    if (request.getGrantTypes().contains("authorization_code")) {
        if (request.getRedirectUris() == null || request.getRedirectUris().isEmpty()) {
            throw new IllegalArgumentException("Redirect URIs required");
        }

        // NEW: Validate each URI
        for (String uri : request.getRedirectUris()) {
            URI parsed = URI.create(uri);

            // Must be HTTPS (except localhost for dev)
            if (!"https".equals(parsed.getScheme())
                && !"localhost".equals(parsed.getHost())
                && !"127.0.0.1".equals(parsed.getHost())) {
                throw new IllegalArgumentException(
                    "Redirect URI must use HTTPS: " + uri);
            }

            // No fragments allowed
            if (parsed.getFragment() != null) {
                throw new IllegalArgumentException(
                    "Redirect URI must not contain fragment: " + uri);
            }

            // No wildcard in path
            if (parsed.getPath().contains("*")) {
                throw new IllegalArgumentException(
                    "Redirect URI must not contain wildcards: " + uri);
            }

            // Must not be a known open redirector
            // (e.g., google.com/url?q=, bit.ly, etc.)
        }
    }
}
```

---

## Phase 6 Summary — Files

### Modified Files

| File | Changes |
|------|---------|
| `SecurityConfig.java` | Security headers, CORS tightening, session config, Swagger protection, actuator protection |
| `ClientManagementService.java` | Redirect URI validation (HTTPS, no fragments, no wildcards) |
| `application.yml` | Actuator path change, session cookie config, Swagger conditional |
| `application-prod.yml` | Swagger disabled, strict session config |

### No New Files Required

All changes are modifications to existing configuration files.
