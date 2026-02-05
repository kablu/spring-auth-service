# 06 - Phase 5: mTLS & Device Trust (P2 - MEDIUM)

> Zero-Trust mein sirf user verify karna kaafi nahi — device bhi verify hona chahiye.

---

## Task 5.1: Mutual TLS (mTLS) for Service-to-Service

### What is mTLS?

Normal TLS mein sirf server apna certificate dikhata hai. mTLS mein **client bhi apna certificate dikhata hai**.

```
NORMAL TLS (current):
  Client -------> Server
  "Show me your cert"
  Server cert ✅
  Client cert: NOT CHECKED

mTLS (zero-trust):
  Client -------> Server
  "Show me your cert"
  Server cert ✅
  "Now YOU show me YOUR cert"
  Client cert ✅   (both verified!)
```

### When to Use mTLS

| Client Type | mTLS Required? | Reason |
|-------------|---------------|--------|
| service-client (M2M) | YES | Service-to-service, no user involved |
| web-client | NO | Browser cannot present client certs easily |
| spa-client | NO | Public client, uses PKCE instead |

### Server-side Configuration

**File: `application.yml` — ADD:**

```yaml
server:
  ssl:
    enabled: true
    key-store: classpath:server-keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12

    # mTLS - client certificate verification
    client-auth: want           # "want" = optional, "need" = required
    trust-store: classpath:truststore.p12
    trust-store-password: ${TRUSTSTORE_PASSWORD}
    trust-store-type: PKCS12
```

| Setting | Value | Meaning |
|---------|-------|---------|
| `client-auth: want` | Optional | Clients CAN present cert, not required for all |
| `client-auth: need` | Required | ALL clients MUST present cert |
| `trust-store` | Truststore | Contains CA certs that issued client certs |

### Architecture

```
Service Client                        Auth Server
+-----------------+                   +------------------+
| Has:            |                   | Has:             |
| - Client cert   |  mTLS handshake  | - Server cert    |
| - Client key    |<================>| - Server key     |
| - Server CA cert|                   | - Client CA cert |
|   (truststore)  |                   |   (truststore)   |
+-----------------+                   +------------------+

1. TCP connection established
2. Server sends its certificate
3. Client verifies server cert against its truststore ✅
4. Server requests client certificate
5. Client sends its certificate
6. Server verifies client cert against its truststore ✅
7. mTLS handshake complete — both sides verified
8. Now OAuth2 token request proceeds over mTLS channel
```

### New Files to Create

| File | Purpose |
|------|---------|
| `security/MtlsClientAuthenticationProvider.java` | Extract client identity from certificate |
| `config/MtlsConfig.java` | mTLS configuration bean |

### Implementation Steps

1. Generate CA certificate (Certificate Authority)
2. Generate server certificate signed by CA
3. Generate client certificates signed by same CA (one per service)
4. Configure server truststore with CA cert
5. Configure client truststore with CA cert
6. Create `MtlsClientAuthenticationProvider`:
   ```java
   // Extract client_id from certificate CN (Common Name)
   // or from SAN (Subject Alternative Name)
   // Map certificate to registered client
   ```
7. Update `service-client` to use `tls_client_auth` method (already configured in `AuthorizationServerConfig.java`)
8. mTLS replaces client_secret for service clients — more secure than shared secrets

### Certificate Generation (Development)

```bash
# 1. Create CA
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem \
  -days 365 -subj "/CN=Auth Server CA" -nodes

# 2. Create Server cert
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-csr.pem \
  -subj "/CN=localhost" -nodes
openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365

# 3. Create Client cert (for service-client)
openssl req -newkey rsa:2048 -keyout client-key.pem -out client-csr.pem \
  -subj "/CN=service-client" -nodes
openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365

# 4. Create PKCS12 keystores
openssl pkcs12 -export -in server-cert.pem -inkey server-key.pem \
  -out server-keystore.p12 -name authserver -password pass:changeit
openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem \
  -out client-keystore.p12 -name service-client -password pass:changeit

# 5. Create truststore with CA cert
keytool -import -alias ca -file ca-cert.pem -keystore truststore.p12 \
  -storetype PKCS12 -storepass changeit -noprompt
```

### Token Request with mTLS

```bash
# Client presents its certificate during TLS handshake
curl --cert client-cert.pem --key client-key.pem \
  --cacert ca-cert.pem \
  -X POST https://localhost:9000/oauth2/token \
  -d "grant_type=client_credentials&client_id=service-client&scope=internal.read"

# No client_secret needed! Certificate IS the authentication
```

---

## Task 5.2: Device Fingerprinting

### What is Device Fingerprinting?

Har device ka ek unique fingerprint hota hai based on browser/OS properties. Yeh token ko device se bind karta hai.

```
User logs in from Chrome on Windows:
  fingerprint = hash(userAgent + screenRes + timezone + language + ...)
  fingerprint = "fp_abc123def456"

Token contains: { "device_fp": "fp_abc123def456" }

Same token used from Firefox on Mac:
  new_fingerprint = "fp_xyz789ghi012"
  "fp_abc123def456" != "fp_xyz789ghi012"  → TOKEN REJECTED!
```

### Implementation

**Client-side (SPA/Web App):**

```javascript
// Generate device fingerprint
const fingerprint = await generateFingerprint({
    userAgent: navigator.userAgent,
    language: navigator.language,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screenResolution: `${screen.width}x${screen.height}`,
    colorDepth: screen.colorDepth,
    platform: navigator.platform
});

// Send with authorization request
GET /oauth2/authorize?...&device_fp=fp_abc123def456
```

**Server-side:**

### New Files

| File | Purpose |
|------|---------|
| `security/DeviceFingerprintValidator.java` | Validate device fingerprint in token |
| `service/DeviceTrustService.java` | Track trusted devices per user |
| `entity/TrustedDevice.java` | Store trusted device records |

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS trusted_devices (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(200) NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(200),           -- "Chrome on Windows 11"
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_trusted BOOLEAN DEFAULT FALSE,   -- Requires explicit user trust
    trust_expires_at TIMESTAMP,
    UNIQUE(username, device_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_trusted_device_user ON trusted_devices(username);
```

### Flow

```
1. User logs in with device_fp = "fp_abc123"
2. DeviceTrustService checks: Is this a known device for this user?

   Known + Trusted:
     → Add device_fp to token claims
     → Normal login flow

   Known + NOT Trusted:
     → Require additional verification (email OTP, etc.)
     → After verification → mark device as trusted

   Unknown (first time):
     → Log SUSPICIOUS_ACTIVITY
     → Send notification to user: "New device login detected"
     → Require additional verification
     → After verification → add to trusted devices
```

---

## Task 5.3: Continuous Token Verification

### Problem

Currently token is verified ONCE at request start. Zero-Trust requires continuous verification.

### What is Continuous Verification?

```
CURRENT (verify once):
  Request arrives → Verify token → Process request → Return response
  (token could be revoked DURING processing — still accepted)

ZERO-TRUST (continuous):
  Request arrives → Verify token → Check blacklist → Process
  Long request   → Re-verify mid-processing
  WebSocket      → Re-verify on each message
  Streaming      → Re-verify periodically
```

### Implementation for Standard HTTP Requests

For normal REST APIs (short-lived requests), continuous verification means:

1. **Token blacklist check on EVERY request** (not just token signature validation)
2. **Re-verify for long-running requests** (requests > 30 seconds)
3. **Session binding** — verify session hasn't been invalidated

### New Files

| File | Purpose |
|------|---------|
| `filter/ContinuousVerificationFilter.java` | Re-verify token during long requests |

### Implementation

```java
@Component
public class ContinuousVerificationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, ...) {
        // 1. Extract token from request
        String token = extractBearerToken(request);

        // 2. Check blacklist (real-time check, not cached)
        if (tokenBlacklistService.isTokenRevoked(getJti(token))) {
            response.setStatus(401);
            return;
        }

        // 3. For normal requests, proceed
        filterChain.doFilter(request, response);
    }
}
```

---

## Phase 5 Summary — Files

### New Files

| File | Purpose |
|------|---------|
| `security/MtlsClientAuthenticationProvider.java` | Certificate-based client auth |
| `config/MtlsConfig.java` | mTLS configuration |
| `security/DeviceFingerprintValidator.java` | Device fingerprint validation |
| `service/DeviceTrustService.java` | Trusted device management |
| `entity/TrustedDevice.java` | Trusted device entity |
| `repository/TrustedDeviceRepository.java` | Trusted device data access |
| `filter/ContinuousVerificationFilter.java` | Continuous token verification |

### Modified Files

| File | Changes |
|------|---------|
| `application.yml` | SSL client-auth config, truststore config |
| `AuthorizationServerConfig.java` | Register mTLS auth provider |
| `JwtTokenCustomizer.java` | Add device_fp claim |
| `schema.sql` | Add trusted_devices table |
| `pom.xml` | No new dependencies (Spring Security handles mTLS) |

### New Resources

| File | Purpose |
|------|---------|
| `server-keystore.p12` | Server SSL certificate |
| `truststore.p12` | Trusted CA certificates |
| `generate-certs.sh` | Certificate generation script |
