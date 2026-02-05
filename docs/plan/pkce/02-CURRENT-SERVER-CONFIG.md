# 02 - Current Server Configuration Analysis

## spa-client Configuration

**File:** `src/main/java/com/corp/authserver/config/AuthorizationServerConfig.java` (Lines 80-96)

```java
// Public client - Authorization Code + PKCE (enforced)
RegisteredClient spaClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("spa-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .redirectUri("http://localhost:4200/callback")
        .redirectUri("http://localhost:3000/callback")
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.PROFILE)
        .scope("read")
        .tokenSettings(tokenSettings())
        .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(true)          // <-- PKCE MANDATORY
                .build())
        .build();
```

## Configuration Breakdown

### 1. Client Identity

| Property | Value | Meaning |
|----------|-------|---------|
| `clientId` | `spa-client` | Unique identifier for Angular app |
| `clientSecret` | None | Public client — no secret |
| `clientAuthenticationMethod` | `NONE` | No client authentication needed |

### 2. Grant Types

```java
.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
```

| Grant Type | Purpose |
|------------|---------|
| `authorization_code` | Primary flow — exchange code for tokens |
| `refresh_token` | Silent token refresh without re-login |

### 3. Redirect URIs

```java
.redirectUri("http://localhost:4200/callback")   // Angular dev server
.redirectUri("http://localhost:3000/callback")   // React/alternative dev server
```

**Security Note:** Yeh development URIs hain. Production mein HTTPS URLs hone chahiye:
```java
.redirectUri("https://app.company.com/callback")
```

### 4. Scopes

```java
.scope(OidcScopes.OPENID)    // "openid"  - OIDC identity
.scope(OidcScopes.PROFILE)   // "profile" - user profile info
.scope("read")               // custom scope for API access
```

| Scope | Purpose | What it enables |
|-------|---------|-----------------|
| `openid` | OIDC compliance | ID token issuance |
| `profile` | User profile | Access to name, picture, etc. |
| `read` | Custom API scope | Read access to resource server |

### 5. PKCE Settings

```java
.clientSettings(ClientSettings.builder()
        .requireAuthorizationConsent(false)    // No consent screen
        .requireProofKey(true)                 // PKCE MANDATORY
        .build())
```

| Setting | Value | Effect |
|---------|-------|--------|
| `requireProofKey` | `true` | PKCE **required** — request without code_challenge will fail |
| `requireAuthorizationConsent` | `false` | User won't see consent screen — auto-approve |

---

## Token Settings

**File:** `AuthorizationServerConfig.java` (Lines 117-124)

```java
@Bean
public TokenSettings tokenSettings() {
    return TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofSeconds(
                properties.getToken().getAccessTokenValiditySeconds()))    // 3600 sec = 1 hour
            .refreshTokenTimeToLive(Duration.ofSeconds(
                properties.getToken().getRefreshTokenValiditySeconds()))   // 2592000 sec = 30 days
            .reuseRefreshTokens(
                properties.getToken().isReuseRefreshTokens())              // false = rotation enabled
            .build();
}
```

**File:** `application.yml` (Lines 84-89)

```yaml
authserver:
  token:
    access-token-validity-seconds: 3600          # 1 hour
    refresh-token-validity-seconds: 2592000      # 30 days
    id-token-validity-seconds: 3600              # 1 hour
    reuse-refresh-tokens: false                  # Rotation enabled
```

### Token Lifetimes

| Token Type | TTL | Notes |
|------------|-----|-------|
| Access Token | 1 hour | API calls ke liye |
| Refresh Token | 30 days | Silent refresh ke liye |
| ID Token | 1 hour | User identity info |

### Refresh Token Rotation

`reuseRefreshTokens: false` means:

```
First refresh:
  Old refresh_token: RT_A → New access_token + New refresh_token: RT_B
  RT_A becomes INVALID

Second refresh:
  RT_B → New access_token + New refresh_token: RT_C
  RT_B becomes INVALID

If attacker steals RT_A and tries to use:
  Server rejects → May revoke ALL tokens for that user (replay detection)
```

---

## Authorization Server Endpoints

**File:** `AuthorizationServerConfig.java` (Lines 126-137)

```java
@Bean
public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder()
            .issuer(properties.getJwt().getIssuer())        // http://localhost:9000
            .authorizationEndpoint("/oauth2/authorize")
            .tokenEndpoint("/oauth2/token")
            .jwkSetEndpoint("/oauth2/jwks")
            .tokenRevocationEndpoint("/oauth2/revoke")
            .tokenIntrospectionEndpoint("/oauth2/introspect")
            .oidcUserInfoEndpoint("/userinfo")
            .build();
}
```

### Endpoint Summary

| Endpoint | URL | Method | Purpose |
|----------|-----|--------|---------|
| Authorization | `/oauth2/authorize` | GET | Start login flow, PKCE challenge |
| Token | `/oauth2/token` | POST | Exchange code for tokens |
| JWK Set | `/oauth2/jwks` | GET | Public keys for JWT verification |
| Revocation | `/oauth2/revoke` | POST | Revoke tokens |
| Introspection | `/oauth2/introspect` | POST | Check token validity |
| UserInfo | `/userinfo` | GET | Get user profile (OIDC) |
| Discovery | `/.well-known/openid-configuration` | GET | OIDC metadata |

---

## JWT Token Customization

**File:** `JwtTokenCustomizer.java`

### Access Token Claims

```java
private void customizeAccessToken(JwtEncodingContext context, Authentication principal) {
    Set<String> roles = principal.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

    context.getClaims().claims(claims -> {
        claims.put("roles", roles);                    // User roles
        claims.put("token_type", "access_token");      // Token type marker
        claims.put("scope", context.getAuthorizedScopes());  // Granted scopes
        claims.put("username", principal.getName());   // Username
    });
}
```

### ID Token Claims

```java
private void customizeIdToken(JwtEncodingContext context, Authentication principal) {
    Set<String> roles = principal.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());

    context.getClaims().claims(claims -> {
        claims.put("roles", roles);                      // User roles
        claims.put("preferred_username", principal.getName());  // Username
    });
}
```

---

## CORS Configuration for Angular

**File:** `SecurityConfig.java` (Lines 80-92)

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(properties.getCors().getAllowedOrigins());
    configuration.setAllowedMethods(properties.getCors().getAllowedMethods());
    configuration.setAllowedHeaders(properties.getCors().getAllowedHeaders());
    configuration.setAllowCredentials(properties.getCors().isAllowCredentials());
    configuration.setMaxAge(properties.getCors().getMaxAge());

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

**File:** `application.yml` (Lines 116-129)

```yaml
authserver:
  cors:
    allowed-origins:
      - https://webapp.company.com
      - https://admin.company.com
    allowed-methods:
      - GET
      - POST
      - PUT
      - DELETE
    allowed-headers:
      - "*"
    allow-credentials: true
    max-age: 3600
```

### Angular Development: Update CORS

For Angular at `localhost:4200`, add to `allowed-origins`:

```yaml
authserver:
  cors:
    allowed-origins:
      - http://localhost:4200      # Angular dev server
      - http://localhost:3000      # Alternative dev server
      - https://webapp.company.com
      - https://admin.company.com
```

---

## Login Configuration

**File:** `SecurityConfig.java` (Line 44)

```java
.formLogin(Customizer.withDefaults())
```

Default Spring Security login:
- **URL:** `/login` (GET for form, POST for submit)
- **Template:** Default Spring Security login page
- **Fields:** `username`, `password`
- **Remember Me:** Not configured

### Test Users

**File:** `SecurityConfig.java` (Lines 58-73)

```java
@Bean
public UserDetailsService userDetailsService() {
    UserDetails user = User.builder()
            .username("user")
            .password("{noop}password")
            .roles("USER")
            .build();

    UserDetails admin = User.builder()
            .username("admin")
            .password("{noop}admin")
            .roles("USER", "ADMIN")
            .build();

    return new InMemoryUserDetailsManager(user, admin);
}
```

| Username | Password | Roles |
|----------|----------|-------|
| `user` | `password` | `ROLE_USER` |
| `admin` | `admin` | `ROLE_USER`, `ROLE_ADMIN` |

---

## Server URL Summary

| Component | URL |
|-----------|-----|
| Auth Server Base | `http://localhost:9000` |
| Issuer | `http://localhost:9000` |
| Angular App | `http://localhost:4200` |
| Resource Server (API) | `http://localhost:8080` (assumed) |
