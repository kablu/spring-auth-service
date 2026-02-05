# Spring OAuth2 Authorization Server - Complete Project Plan

## Project Overview
A production-ready OAuth2 Authorization Server built with Spring Boot 3.x and Spring Authorization Server, integrating with Active Directory for authentication and providing enterprise-grade token management.

---

## 1. Technical Architecture

### Technology Stack
- **Framework**: Spring Boot 3.2.x
- **Authorization**: Spring Authorization Server 1.2.x
- **Security**: Spring Security 6.x
- **AD Integration**: Spring LDAP 3.x
- **Database**: PostgreSQL (for client/token storage)
- **Token Format**: JWT (JSON Web Token)
- **Key Management**: RSA 2048-bit asymmetric keys
- **Build Tool**: Maven
- **Java Version**: Java 21 (LTS)

### Architecture Components
```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                      │
│  (Web Apps, Mobile Apps, Backend Services)                 │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│              Spring Authorization Server                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  OAuth2 Endpoints                                    │   │
│  │  - /oauth2/authorize                                 │   │
│  │  - /oauth2/token                                     │   │
│  │  - /oauth2/revoke                                    │   │
│  │  - /oauth2/introspect                               │   │
│  │  - /.well-known/oauth-authorization-server          │   │
│  │  - /.well-known/openid-configuration                │   │
│  │  - /oauth2/jwks (JWK Set)                           │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Authentication Layer                                │   │
│  │  - Active Directory Integration (LDAP)              │   │
│  │  - User Attribute Mapping                           │   │
│  │  - Role/Group Resolution                            │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Token Management                                    │   │
│  │  - JWT Generation                                    │   │
│  │  - Custom Claims Injection                          │   │
│  │  - Token Signing (RSA)                              │   │
│  │  - Token Revocation                                 │   │
│  │  - Refresh Token Rotation                           │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Client Management                                   │   │
│  │  - Client Registration                               │   │
│  │  - Client Authentication (Secret, JWT, mTLS)        │   │
│  │  - Redirect URI Validation                          │   │
│  └─────────────────────────────────────────────────────┘   │
└──────────────────┬──────────────────┬───────────────────────┘
                   │                  │
                   ▼                  ▼
          ┌────────────────┐   ┌────────────────┐
          │ Active         │   │ PostgreSQL     │
          │ Directory      │   │ Database       │
          │ (LDAP)         │   │                │
          └────────────────┘   └────────────────┘
```

---

## 2. Functional Requirements Implementation Plan

### Phase 1: Token Issuance (FR-TOKEN-01 to FR-TOKEN-05)

#### FR-TOKEN-01: OAuth 2.0 Access Tokens
**Implementation:**
- Configure `AuthorizationServerConfiguration` with token endpoint
- Use Spring Authorization Server's built-in token generation
- Return access tokens in OAuth2 token response format

#### FR-TOKEN-02: JWT Format
**Implementation:**
```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
    return context -> {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims()
                .issuer("https://authserver.company.com")
                .audience(List.of("api://default"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600));
        }
    };
}
```

#### FR-TOKEN-03: Refresh Tokens
**Implementation:**
- Enable refresh token grant in authorization server settings
- Configure refresh token TTL
- Implement refresh token rotation for security

**Configuration:**
```java
tokenSettings
    .refreshTokenTimeToLive(Duration.ofDays(30))
    .reuseRefreshTokens(false); // Enable rotation
```

#### FR-TOKEN-04: OpenID Connect ID Tokens
**Implementation:**
- Enable OIDC support in authorization server
- Configure ID token claims with user profile information
- Add `openid` scope support

#### FR-TOKEN-05: Token Validity Configuration
**Implementation:**
```properties
# application.yml
authserver:
  token:
    access-token-validity: 3600      # 1 hour
    refresh-token-validity: 2592000  # 30 days
    id-token-validity: 3600          # 1 hour
```

---

### Phase 2: Token Customization (FR-TOKEN-06 to FR-TOKEN-07)

#### FR-TOKEN-06: Custom JWT Claims
**Implementation:**
```java
@Component
public class CustomClaimsMapper implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication authentication = context.getPrincipal();
        ADUser adUser = (ADUser) authentication.getPrincipal();

        // Add custom claims
        context.getClaims()
            .claim("roles", adUser.getRoles())
            .claim("scopes", context.getAuthorizedScopes())
            .claim("department", adUser.getDepartment())
            .claim("email", adUser.getEmail())
            .claim("displayName", adUser.getDisplayName())
            .claim("tenant", "company.com");
    }
}
```

**Token Structure:**
```json
{
  "sub": "kablu@company.com",
  "iss": "https://authserver.company.com",
  "aud": ["api://default"],
  "exp": 1738617600,
  "iat": 1738614000,
  "jti": "unique-token-id",
  "roles": ["RA_ADMIN", "USER"],
  "scopes": ["read", "write"],
  "department": "Engineering",
  "email": "kablu@company.com",
  "displayName": "Kablu",
  "tenant": "company.com"
}
```

#### FR-TOKEN-07: Asymmetric Cryptography (RSA)
**Implementation:**
```java
@Bean
public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = generateRSAKey();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
}

private RSAKey generateRSAKey() {
    KeyPair keyPair = generateRsaKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
}

private KeyPair generateRsaKeyPair() {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
}
```

---

### Phase 3: Key Management (FR-KEY-01 to FR-KEY-03)

#### FR-KEY-01: JWK Endpoint
**Implementation:**
- Spring Authorization Server automatically exposes `/oauth2/jwks` endpoint
- Public keys published in JWK Set format
- Resource servers can fetch public keys for token validation

**Endpoint Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "key-id-1",
      "alg": "RS256",
      "n": "base64-encoded-modulus..."
    }
  ]
}
```

#### FR-KEY-02: Key Rotation
**Implementation:**
```java
@Component
public class JwkRotationService {

    private static final Duration KEY_ROTATION_INTERVAL = Duration.ofDays(90);

    @Scheduled(cron = "0 0 0 * * *") // Daily check
    public void rotateKeysIfNeeded() {
        if (shouldRotateKeys()) {
            RSAKey newKey = generateRSAKey();
            // Add new key to JWK Set
            // Keep old key for validation period (7 days)
            // Remove expired keys
        }
    }
}
```

**Key Rotation Strategy:**
1. Generate new key pair
2. Add new key to JWK Set (both keys published)
3. Start signing new tokens with new key
4. Keep old key for validation (grace period: 7 days)
5. Remove old key after grace period

#### FR-KEY-03: Token Verification by Resource Servers
**Resource Server Configuration:**
```java
@Configuration
@EnableResourceServer
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) {
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwkSetUri("https://authserver.company.com/oauth2/jwks")
            )
        );
        return http.build();
    }
}
```

---

### Phase 4: OAuth2 Grant Types (FR-GRANT-01 to FR-GRANT-04)

#### FR-GRANT-01: Authorization Code Grant with PKCE
**Implementation:**
```java
@Bean
public RegisteredClient webAppClient() {
    return RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("web-app-client")
        .clientSecret("{noop}secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri("https://webapp.company.com/callback")
        .scope("read")
        .scope("write")
        .clientSettings(ClientSettings.builder()
            .requireProofKey(true) // Enforce PKCE
            .requireAuthorizationConsent(true)
            .build())
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofHours(1))
            .refreshTokenTimeToLive(Duration.ofDays(30))
            .reuseRefreshTokens(false) // Rotation
            .build())
        .build();
}
```

**Authorization Flow:**
```
1. Client generates code_verifier and code_challenge
2. GET /oauth2/authorize?
     response_type=code
     &client_id=web-app-client
     &redirect_uri=https://webapp.company.com/callback
     &scope=read write
     &code_challenge=base64url(sha256(code_verifier))
     &code_challenge_method=S256

3. User authenticates via AD
4. Authorization server redirects with code
5. POST /oauth2/token
     grant_type=authorization_code
     &code=AUTH_CODE
     &redirect_uri=https://webapp.company.com/callback
     &client_id=web-app-client
     &client_secret=secret
     &code_verifier=ORIGINAL_CODE_VERIFIER

6. Server validates code_verifier matches code_challenge
7. Issues access_token + refresh_token
```

#### FR-GRANT-02: Client Credentials Grant
**Implementation:**
```java
@Bean
public RegisteredClient backendServiceClient() {
    return RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("backend-service")
        .clientSecret("{bcrypt}$2a$10$...") // BCrypt encoded
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("api.read")
        .scope("api.write")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofHours(2))
            .build())
        .build();
}
```

**Flow:**
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials
&scope=api.read api.write
```

#### FR-GRANT-03: Refresh Token Grant
**Implementation:**
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN_HERE
&client_id=web-app-client
&client_secret=secret
```

**Refresh Token Rotation:**
- Every refresh token use generates new access_token + new refresh_token
- Old refresh token is invalidated
- Prevents refresh token replay attacks

#### FR-GRANT-04: Deprecated Grant Types Disabled
**Configuration:**
```java
// DO NOT implement:
// - AuthorizationGrantType.PASSWORD (Resource Owner Password Credentials)
// - AuthorizationGrantType.IMPLICIT

// Only support:
// ✓ AUTHORIZATION_CODE (with PKCE)
// ✓ CLIENT_CREDENTIALS
// ✓ REFRESH_TOKEN
```

---

### Phase 5: Client Management (FR-CLIENT-01 to FR-CLIENT-03)

#### FR-CLIENT-01: Multiple OAuth2 Clients
**Implementation:**
```java
@Bean
public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    // Store clients in database for dynamic management
    JdbcRegisteredClientRepository repository =
        new JdbcRegisteredClientRepository(jdbcTemplate);

    // Pre-register default clients
    repository.save(webAppClient());
    repository.save(mobileAppClient());
    repository.save(backendServiceClient());

    return repository;
}
```

**Database Schema:**
```sql
CREATE TABLE oauth2_registered_client (
    id VARCHAR(100) PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret VARCHAR(200),
    client_authentication_methods VARCHAR(1000),
    authorization_grant_types VARCHAR(1000),
    redirect_uris VARCHAR(1000),
    scopes VARCHAR(1000),
    client_settings VARCHAR(2000),
    token_settings VARCHAR(2000)
);
```

#### FR-CLIENT-02: Client Authentication Mechanisms

**1. Client Secret (Basic Authentication):**
```java
.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
.clientSecret("{bcrypt}$2a$10$...")
```

**2. Private Key JWT:**
```java
@Bean
public RegisteredClient privateKeyJwtClient() {
    return RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("secure-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
        .jwkSetUrl("https://client.company.com/.well-known/jwks.json")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .build();
}
```

**Client Authentication (Private Key JWT):**
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=https://client.company.com/callback
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGc...
```

**3. Mutual TLS (mTLS):**
```java
.clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
.clientSettings(ClientSettings.builder()
    .x509CertificateSubjectDN("CN=client.company.com,O=Company")
    .build())
```

#### FR-CLIENT-03: Redirect URI Validation
**Implementation:**
```java
@Bean
public RegisteredClient strictRedirectClient() {
    return RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("webapp")
        .redirectUri("https://webapp.company.com/callback")
        .redirectUri("https://webapp.company.com/oauth2/callback")
        // Exact match required - no wildcards allowed
        .redirectUriValidationStrategy(
            (registeredClient, requestedRedirectUri) -> {
                return registeredClient.getRedirectUris()
                    .contains(requestedRedirectUri);
            }
        )
        .build();
}
```

---

### Phase 6: Token Revocation & Rotation (FR-SEC-01 to FR-SEC-02)

#### FR-SEC-01: Token Revocation Endpoint
**Implementation:**
```java
// Automatically provided by Spring Authorization Server
// Endpoint: POST /oauth2/revoke
```

**Usage:**
```
POST /oauth2/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=ACCESS_TOKEN_OR_REFRESH_TOKEN
&token_type_hint=access_token
```

**Token Blacklist Storage:**
```java
@Service
public class TokenRevocationService {

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    public void revokeToken(String token) {
        OAuth2Authorization authorization =
            authorizationService.findByToken(token, null);

        if (authorization != null) {
            // Invalidate in database
            authorizationService.remove(authorization);

            // Add to blacklist (Redis for distributed systems)
            tokenBlacklist.add(token, getRemainingTTL(token));
        }
    }
}
```

#### FR-SEC-02: Refresh Token Rotation
**Implementation:**
```java
@Bean
public TokenSettings tokenSettings() {
    return TokenSettings.builder()
        .reuseRefreshTokens(false) // CRITICAL: Enable rotation
        .refreshTokenTimeToLive(Duration.ofDays(30))
        .build();
}
```

**Rotation Flow:**
```
1. Client uses refresh_token_A
2. Server validates refresh_token_A
3. Server issues new access_token + refresh_token_B
4. Server INVALIDATES refresh_token_A
5. refresh_token_A can never be used again
6. If refresh_token_A is reused → Security breach detected → Revoke all tokens
```

---

### Phase 7: Security & Hardening (FR-SEC-03 to FR-SEC-06)

#### FR-SEC-03: HTTPS Enforcement
**Implementation:**
```properties
# application.yml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: changeit
    key-store-type: PKCS12
    key-alias: authserver
```

**Redirect HTTP to HTTPS:**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) {
    http.requiresChannel(channel -> channel
        .anyRequest().requiresSecure()
    );
    return http.build();
}
```

#### FR-SEC-04: CSRF Protection
**Implementation:**
```java
@Bean
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
    );

    return http.build();
}
```

#### FR-SEC-05: PKCE Enforcement for Public Clients
**Implementation:**
```java
@Bean
public RegisteredClient publicClient() {
    return RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("mobile-app")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // Public client
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .clientSettings(ClientSettings.builder()
            .requireProofKey(true) // MANDATORY for public clients
            .requireAuthorizationConsent(true)
            .build())
        .build();
}
```

**Validation:**
```java
@Component
public class PkceValidator {

    public void validate(OAuth2AuthorizationCodeRequestAuthenticationToken authentication) {
        if (isPublicClient(authentication.getClientId())) {
            if (!authentication.getCodeChallenge() != null) {
                throw new OAuth2AuthenticationException("PKCE required for public clients");
            }
        }
    }
}
```

#### FR-SEC-06: Prevent Token Issuance Without Authentication
**Implementation:**
```java
@Bean
public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
    http.authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/oauth2/authorize").authenticated() // Must be authenticated
        .requestMatchers("/oauth2/token").permitAll() // Client authentication happens here
        .anyRequest().authenticated()
    )
    .formLogin(Customizer.withDefaults()); // AD authentication

    return http.build();
}
```

---

### Phase 8: Active Directory Integration

#### AD Authentication Configuration
**Implementation:**
```java
@Configuration
public class LdapConfig {

    @Bean
    public AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource) {
        LdapBindAuthenticationManagerFactory factory =
            new LdapBindAuthenticationManagerFactory(contextSource);

        factory.setUserDnPatterns("uid={0},ou=people");
        factory.setUserDetailsContextMapper(new CustomUserDetailsContextMapper());

        return factory.createAuthenticationManager();
    }

    @Bean
    public BaseLdapPathContextSource contextSource() {
        return new DefaultSpringSecurityContextSource(
            "ldap://ad.company.com:389/dc=company,dc=com");
    }
}

@Component
public class CustomUserDetailsContextMapper implements UserDetailsContextMapper {

    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx,
                                         String username,
                                         Collection<? extends GrantedAuthority> authorities) {
        return ADUser.builder()
            .username(username)
            .email(ctx.getStringAttribute("mail"))
            .displayName(ctx.getStringAttribute("displayName"))
            .department(ctx.getStringAttribute("department"))
            .roles(extractRoles(ctx))
            .build();
    }

    private List<String> extractRoles(DirContextOperations ctx) {
        String[] groups = ctx.getStringAttributes("memberOf");
        return Arrays.stream(groups)
            .map(this::extractRoleFromGroup)
            .collect(Collectors.toList());
    }
}
```

**Properties:**
```properties
spring:
  ldap:
    urls: ldap://ad.company.com:389
    base: dc=company,dc=com
    username: CN=service-account,OU=Services,DC=company,DC=com
    password: ${LDAP_PASSWORD}
```

---

### Phase 9: Integration with Resource Servers (FR-INT-01 to FR-INT-02)

#### FR-INT-01: Seamless Integration
**Resource Server Configuration:**
```java
@Configuration
@EnableResourceServer
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) {
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwkSetUri("https://authserver.company.com/oauth2/jwks")
                .jwtAuthenticationConverter(jwtAuthenticationConverter())
            )
        );

        http.authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/api/admin/**").hasRole("RA_ADMIN")
            .requestMatchers("/api/user/**").hasAnyRole("USER", "RA_ADMIN")
            .anyRequest().authenticated()
        );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter jwtAuthenticationConverter =
            new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
            grantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }
}
```

#### FR-INT-02: Independent Token Validation
**How It Works:**
1. Resource server fetches public keys from `/oauth2/jwks` endpoint
2. Caches public keys locally
3. Validates JWT signature using cached public key
4. NO NETWORK CALL to authorization server for every request
5. Refresh public keys periodically (e.g., every 5 minutes)

**Benefits:**
- High performance (no network latency)
- Scalability (resource servers don't depend on auth server availability)
- Offline validation possible

---

## 3. Database Schema

### OAuth2 Tables
```sql
-- Registered Clients
CREATE TABLE oauth2_registered_client (
    id VARCHAR(100) PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_id_issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    client_secret VARCHAR(200),
    client_secret_expires_at TIMESTAMP,
    client_name VARCHAR(200),
    client_authentication_methods VARCHAR(1000),
    authorization_grant_types VARCHAR(1000),
    redirect_uris VARCHAR(1000),
    scopes VARCHAR(1000),
    client_settings VARCHAR(2000),
    token_settings VARCHAR(2000)
);

-- Authorizations (Issued Tokens)
CREATE TABLE oauth2_authorization (
    id VARCHAR(100) PRIMARY KEY,
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorization_grant_type VARCHAR(100) NOT NULL,
    authorized_scopes VARCHAR(1000),
    attributes TEXT,
    state VARCHAR(500),
    authorization_code_value TEXT,
    authorization_code_issued_at TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    authorization_code_metadata TEXT,
    access_token_value TEXT,
    access_token_issued_at TIMESTAMP,
    access_token_expires_at TIMESTAMP,
    access_token_metadata TEXT,
    access_token_type VARCHAR(100),
    access_token_scopes VARCHAR(1000),
    refresh_token_value TEXT,
    refresh_token_issued_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    refresh_token_metadata TEXT,
    oidc_id_token_value TEXT,
    oidc_id_token_issued_at TIMESTAMP,
    oidc_id_token_expires_at TIMESTAMP,
    oidc_id_token_metadata TEXT,
    oidc_id_token_claims TEXT,
    FOREIGN KEY (registered_client_id) REFERENCES oauth2_registered_client(id)
);

-- Authorization Consent
CREATE TABLE oauth2_authorization_consent (
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    authorities VARCHAR(1000),
    PRIMARY KEY (registered_client_id, principal_name),
    FOREIGN KEY (registered_client_id) REFERENCES oauth2_registered_client(id)
);

-- Token Blacklist (Revoked Tokens)
CREATE TABLE token_blacklist (
    token_hash VARCHAR(64) PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_token_blacklist_expires ON token_blacklist(expires_at);
```

---

## 4. API Endpoints

### Discovery Endpoints
```
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration
GET /oauth2/jwks
```

### Authorization Endpoints
```
GET  /oauth2/authorize
POST /oauth2/token
POST /oauth2/revoke
POST /oauth2/introspect
```

### Custom Management Endpoints
```
POST   /api/clients                 - Register new client
GET    /api/clients/{clientId}      - Get client details
PUT    /api/clients/{clientId}      - Update client
DELETE /api/clients/{clientId}      - Delete client
GET    /api/clients                 - List all clients

POST   /api/keys/rotate             - Trigger key rotation
GET    /api/keys                    - List active keys

GET    /api/tokens/active           - List active tokens for user
POST   /api/tokens/revoke-all       - Revoke all user tokens
```

---

## 5. Security Best Practices Implemented

### 1. Password Storage
- Client secrets stored with BCrypt
- Service account passwords in environment variables
- Never log secrets

### 2. Token Security
- Short-lived access tokens (1 hour)
- Refresh token rotation enabled
- Token revocation support
- JWT signature verification

### 3. PKCE Enforcement
- Mandatory for public clients
- Recommended for all clients
- S256 challenge method

### 4. HTTPS Only
- All endpoints require HTTPS
- HTTP redirects to HTTPS
- HSTS headers enabled

### 5. CSRF Protection
- Enabled for state-changing operations
- Cookie-based CSRF tokens
- SPA-compatible CSRF handling

### 6. Rate Limiting
```java
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) {
        String clientIp = request.getRemoteAddr();

        if (!rateLimiter.tryAcquire(clientIp)) {
            response.setStatus(429); // Too Many Requests
            return;
        }

        filterChain.doFilter(request, response);
    }
}
```

### 7. Audit Logging
```java
@Aspect
@Component
public class SecurityAuditAspect {

    @AfterReturning("@annotation(Audited)")
    public void auditSecurityEvent(JoinPoint joinPoint) {
        String username = SecurityContextHolder.getContext()
            .getAuthentication().getName();
        String action = joinPoint.getSignature().getName();

        auditLog.log(username, action, "SUCCESS");
    }
}
```

---

## 6. Testing Strategy

### Unit Tests
- Token generation and validation
- JWT claims customization
- Client authentication mechanisms
- PKCE validation

### Integration Tests
- Full OAuth2 flows
- AD authentication
- Token endpoint
- Revocation endpoint

### Security Tests
- PKCE enforcement
- CSRF protection
- Token expiration
- Refresh token rotation
- Invalid signature detection

---

## 7. Deployment Considerations

### Production Checklist
- [ ] Use production-grade database (PostgreSQL)
- [ ] Enable HTTPS with valid certificate
- [ ] Configure proper CORS policies
- [ ] Set up monitoring and alerting
- [ ] Implement log aggregation (ELK stack)
- [ ] Use external secret management (Vault, AWS Secrets Manager)
- [ ] Configure proper firewall rules
- [ ] Enable rate limiting
- [ ] Set up high availability (multiple instances)
- [ ] Configure database replication
- [ ] Implement key rotation schedule
- [ ] Set up backup and disaster recovery

### Environment Variables
```properties
# Active Directory
LDAP_URL=ldap://ad.company.com:389
LDAP_BASE_DN=dc=company,dc=com
LDAP_SERVICE_USERNAME=CN=service,OU=Services,DC=company,DC=com
LDAP_SERVICE_PASSWORD=<secret>

# Database
DB_URL=jdbc:postgresql://localhost:5432/authserver
DB_USERNAME=authserver
DB_PASSWORD=<secret>

# JWT Signing
JWT_KEY_STORE_PATH=/etc/authserver/keystore.p12
JWT_KEY_STORE_PASSWORD=<secret>
JWT_KEY_ALIAS=authserver-jwt

# Server
SERVER_PORT=8443
SERVER_SSL_KEY_STORE=/etc/authserver/server.p12
SERVER_SSL_KEY_STORE_PASSWORD=<secret>
```

---

## 8. Project Structure

```
spring-auth-service/
├── src/
│   ├── main/
│   │   ├── java/com/corp/authserver/
│   │   │   ├── AuthServerApplication.java
│   │   │   ├── config/
│   │   │   │   ├── AuthorizationServerConfig.java
│   │   │   │   ├── SecurityConfig.java
│   │   │   │   ├── LdapConfig.java
│   │   │   │   ├── JwkConfig.java
│   │   │   │   └── DatabaseConfig.java
│   │   │   ├── controller/
│   │   │   │   ├── ClientManagementController.java
│   │   │   │   ├── KeyManagementController.java
│   │   │   │   └── TokenManagementController.java
│   │   │   ├── service/
│   │   │   │   ├── CustomTokenCustomizer.java
│   │   │   │   ├── TokenRevocationService.java
│   │   │   │   ├── JwkRotationService.java
│   │   │   │   ├── ADAuthenticationService.java
│   │   │   │   └── ClientManagementService.java
│   │   │   ├── model/
│   │   │   │   ├── ADUser.java
│   │   │   │   ├── ClientRegistrationRequest.java
│   │   │   │   └── TokenInfo.java
│   │   │   ├── security/
│   │   │   │   ├── CustomUserDetailsContextMapper.java
│   │   │   │   ├── PkceValidator.java
│   │   │   │   └── RateLimitFilter.java
│   │   │   └── repository/
│   │   │       └── TokenBlacklistRepository.java
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-dev.yml
│   │       ├── application-prod.yml
│   │       ├── schema.sql
│   │       └── data.sql
│   └── test/
│       └── java/com/corp/authserver/
│           ├── OAuth2AuthorizationCodeFlowTest.java
│           ├── ClientCredentialsFlowTest.java
│           ├── TokenRevocationTest.java
│           └── PkceValidationTest.java
├── docs/
│   ├── PROJECT-PLAN.md (this file)
│   ├── API-GUIDE.md
│   ├── DEPLOYMENT-GUIDE.md
│   └── TESTING-GUIDE.md
├── pom.xml
└── README.md
```

---

## 9. Implementation Timeline

### Week 1: Foundation
- Day 1-2: Project setup, dependencies, database schema
- Day 3-4: Basic OAuth2 configuration, token issuance
- Day 5: AD integration

### Week 2: Core Features
- Day 1-2: JWT customization, custom claims
- Day 3: OAuth2 grant types implementation
- Day 4-5: Client management

### Week 3: Security & Advanced Features
- Day 1-2: Token revocation, refresh token rotation
- Day 3: PKCE enforcement, CSRF protection
- Day 4-5: Key rotation, JWK endpoint

### Week 4: Testing & Documentation
- Day 1-3: Unit tests, integration tests
- Day 4-5: Documentation, deployment guide

---

## 10. Success Criteria

### Functional
- ✓ OAuth2 access tokens issued in JWT format
- ✓ Refresh tokens with rotation
- ✓ OIDC ID tokens
- ✓ Custom JWT claims (roles, scopes, user attributes)
- ✓ RSA signing with JWK endpoint
- ✓ Authorization Code + PKCE
- ✓ Client Credentials grant
- ✓ Multiple clients supported
- ✓ Token revocation working
- ✓ AD authentication integrated

### Security
- ✓ HTTPS enforced
- ✓ PKCE mandatory for public clients
- ✓ CSRF protection enabled
- ✓ Refresh token rotation active
- ✓ No deprecated grant types
- ✓ Client secret encryption
- ✓ Rate limiting implemented

### Performance
- ✓ Token validation < 50ms
- ✓ Token issuance < 200ms
- ✓ Support 1000+ concurrent users
- ✓ Resource servers validate tokens independently

---

**Document Version**: 1.0
**Last Updated**: 2026-02-04
**Status**: Ready for Implementation
