# 03 - Phase 2: Token Security (P1 - HIGH)

> Token ko tamper-proof, theft-proof, aur revocable banana hai.

---

## Task 2.1: Implement Token Blacklist Service

### Problem

`schema.sql` mein `token_blacklist` table hai lekin koi service implement nahi hai. Matlab `/oauth2/revoke` call karne ke baad bhi revoked token potentially kaam kar sakta hai.

### Architecture

```
Client                    Resource Server              Auth Server
  |                            |                           |
  |--- Bearer token ---------> |                           |
  |                            |--- POST /oauth2/introspect -->|
  |                            |    token=xyz               |
  |                            |                           |
  |                            |    Check: Is token in     |
  |                            |    token_blacklist table?  |
  |                            |                           |
  |                            |<-- { "active": false } ---|
  |<-- 401 Unauthorized ------|                           |
```

### New Files to Create

| File | Purpose |
|------|---------|
| `entity/TokenBlacklist.java` | JPA Entity for token_blacklist table |
| `repository/TokenBlacklistRepository.java` | JPA Repository |
| `service/TokenBlacklistService.java` | Revocation logic + scheduled cleanup |
| `security/BlacklistTokenValidator.java` | OAuth2TokenValidator that checks blacklist |

### Implementation Details

**1. Entity: `TokenBlacklist.java`**
```java
@Entity
@Table(name = "token_blacklist")
public class TokenBlacklist {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token_id", nullable = false, unique = true)
    private String tokenId;          // JWT 'jti' claim

    @Column(name = "token_type", nullable = false)
    private String tokenType;        // access_token / refresh_token

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;       // Cleanup after this time

    @Column(name = "revoked_by")
    private String revokedBy;        // Who revoked (audit)
}
```

**2. Repository: `TokenBlacklistRepository.java`**
```java
public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {
    boolean existsByTokenId(String tokenId);
    void deleteByExpiresAtBefore(Instant now);  // Cleanup expired entries
}
```

**3. Service: `TokenBlacklistService.java`**
```java
@Service
public class TokenBlacklistService {

    public void revokeToken(String tokenId, String tokenType,
                            Instant expiresAt, String revokedBy) {
        // Save to token_blacklist table
    }

    public boolean isTokenRevoked(String tokenId) {
        return repository.existsByTokenId(tokenId);
    }

    @Scheduled(cron = "0 0 3 * * ?")  // Daily 3 AM cleanup
    public void cleanupExpiredEntries() {
        repository.deleteByExpiresAtBefore(Instant.now());
    }
}
```

**4. Validator: `BlacklistTokenValidator.java`**
```java
public class BlacklistTokenValidator implements OAuth2TokenValidator<Jwt> {
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (blacklistService.isTokenRevoked(jwt.getId())) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("token_revoked", "Token has been revoked", null)
            );
        }
        return OAuth2TokenValidatorResult.success();
    }
}
```

### Integration Points

- Register `BlacklistTokenValidator` as additional JWT validator in resource server config
- Hook into Spring's token revocation endpoint to call `TokenBlacklistService.revokeToken()`
- Ensure `jti` (JWT ID) claim is present in all tokens

---

## Task 2.2: Implement DPoP (Demonstration of Proof-of-Possession)

### What is DPoP?

Normal Bearer token koi bhi use kar sakta hai agar steal ho jaye. DPoP token ko client ke private key se bind karta hai.

```
WITHOUT DPoP (current):
  Attacker steals token → Can use it from ANY device ❌

WITH DPoP:
  Attacker steals token → Cannot use it without client's private key ✅
```

### Flow

```
1. Client generates ephemeral key pair (per session)

2. Client creates DPoP proof JWT:
   {
     "typ": "dpop+jwt",
     "alg": "ES256",
     "jwk": { client's public key }
   }
   {
     "jti": "unique-id",
     "htm": "POST",               // HTTP method
     "htu": "http://localhost:9000/oauth2/token",  // target URL
     "iat": 1738866400
   }
   Signed with client's PRIVATE key

3. Token request includes DPoP header:
   POST /oauth2/token
   DPoP: eyJ0eXAiOiJkcG9w...     // DPoP proof JWT
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=xxx

4. Auth server:
   - Validates DPoP proof signature
   - Binds access token to client's public key
   - Adds 'cnf' claim: { "jkt": "thumbprint-of-client-public-key" }

5. API calls must include DPoP proof:
   GET /api/resource
   Authorization: DPoP eyJhbGci...     // NOT Bearer!
   DPoP: eyJ0eXAiOiJkcG9w...          // Fresh proof for THIS request

6. Resource server:
   - Validates DPoP proof
   - Checks cnf.jkt matches DPoP proof's public key
   - Token theft is useless without client's private key
```

### New Files to Create

| File | Purpose |
|------|---------|
| `security/DPoPProofValidator.java` | Validates DPoP proof JWTs |
| `security/DPoPTokenCustomizer.java` | Adds `cnf` claim to tokens |
| `filter/DPoPFilter.java` | Filter to extract and validate DPoP header |

### Implementation Steps

1. Add DPoP proof validation logic
2. Modify `JwtTokenCustomizer.java` to add `cnf` claim with `jkt` (JWK Thumbprint)
3. Create `DPoPFilter` that intercepts token requests with DPoP header
4. Update token endpoint to issue DPoP-bound tokens
5. Clients that support DPoP get `token_type: "DPoP"` instead of `"Bearer"`

---

## Task 2.3: Shorten Token Lifetimes

### What to Change

**File: `application.yml`**

```yaml
# BEFORE (current):
authserver:
  token:
    access-token-validity-seconds: 3600        # 1 hour
    refresh-token-validity-seconds: 2592000    # 30 days

# AFTER (zero-trust):
authserver:
  token:
    access-token-validity-seconds: 300         # 5 minutes
    refresh-token-validity-seconds: 86400      # 1 day (not 30 days)
    id-token-validity-seconds: 300             # 5 minutes
    reuse-refresh-tokens: false                # Keep rotation (already done)
```

### Why Shorter Tokens?

```
Zero-Trust Principle: "Assume Breach"

Stolen 1-hour token   → Attacker has 1 hour to exploit
Stolen 5-minute token → Attacker has only 5 minutes

With refresh token rotation:
  - Client silently refreshes every 5 min (transparent to user)
  - Stolen refresh token → Used once → Server detects reuse → ALL tokens revoked
```

### Implementation Steps

1. Change token TTL values in `application.yml`
2. Update `AuthorizationServerConfig.java` `tokenSettings()` to use new values
3. Add per-client token TTL override (already supported in `ClientManagementService`)
4. Service clients (M2M) can have longer tokens (15 min) since no user session involved

---

## Task 2.4: Add Token ID (jti) Claim

### Problem

Current `JwtTokenCustomizer.java` does NOT add `jti` claim. Without `jti`, tokens cannot be individually revoked/blacklisted.

### What to Change

**File: `JwtTokenCustomizer.java`**

```java
// ADD to access token customization:
if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
    claims.claim("jti", UUID.randomUUID().toString());  // ADD THIS
    claims.claim("roles", roles);
    claims.claim("token_type", "access_token");
    // ... existing claims
}
```

### Implementation Steps

1. Add `jti` claim generation in `JwtTokenCustomizer`
2. `jti` = UUID per token (unique identifier)
3. Blacklist service uses `jti` to identify revoked tokens
4. Token introspection checks `jti` against blacklist

---

## Phase 2 Summary — Files

### New Files

| File | Purpose |
|------|---------|
| `entity/TokenBlacklist.java` | JPA entity |
| `repository/TokenBlacklistRepository.java` | Data access |
| `service/TokenBlacklistService.java` | Revocation logic |
| `security/BlacklistTokenValidator.java` | JWT validation hook |
| `security/DPoPProofValidator.java` | DPoP proof validation |
| `security/DPoPTokenCustomizer.java` | cnf claim addition |
| `filter/DPoPFilter.java` | DPoP header processing |

### Modified Files

| File | Changes |
|------|---------|
| `JwtTokenCustomizer.java` | Add `jti` claim, `cnf` claim for DPoP |
| `application.yml` | Shorter token TTLs |
| `AuthorizationServerConfig.java` | Register blacklist validator, DPoP support |
