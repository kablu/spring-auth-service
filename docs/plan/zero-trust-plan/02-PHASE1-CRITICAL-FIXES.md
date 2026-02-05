# 02 - Phase 1: Critical Security Fixes (P0)

> Yeh sabse pehle implement hona chahiye. Bina iske aage ka koi bhi kaam secure nahi hoga.

---

## Task 1.1: Password Hashing (BCrypt)

### What to Change

**File: `SecurityConfig.java`**

```java
// BEFORE (INSECURE):
User.withUsername("user")
    .password("{noop}password")      // plaintext!
    .roles("USER")

// AFTER (SECURE):
User.withUsername("user")
    .password(passwordEncoder.encode("password"))  // bcrypt hashed
    .roles("USER")
```

**File: `AuthorizationServerConfig.java`**

```java
// BEFORE (INSECURE):
.clientSecret("{noop}web-client-secret")

// AFTER (SECURE):
.clientSecret(passwordEncoder.encode("web-client-secret"))
```

**File: `ClientManagementService.java`**

```java
// BEFORE (INSECURE):
.clientSecret("{noop}" + request.getClientSecret())

// AFTER (SECURE):
.clientSecret(passwordEncoder.encode(request.getClientSecret()))
```

### New Files to Create

None — changes in existing files only.

### Implementation Steps

1. Inject `PasswordEncoder` bean into `AuthorizationServerConfig` and `ClientManagementService`
2. Replace all `{noop}` usages with `passwordEncoder.encode()`
3. Ensure `PasswordEncoder` bean in `SecurityConfig.java` (line 76) is `BCryptPasswordEncoder`
4. Update test configurations — tests currently send raw passwords, they should still work as Spring matches raw input against encoded hash

### Testing

```bash
# Client credentials with encoded secret should still work
curl -X POST http://localhost:9000/oauth2/token \
  -u "service-client:service-client-secret" \
  -d "grant_type=client_credentials&scope=internal.read"
# Spring's DelegatingPasswordEncoder handles matching raw input vs stored hash
```

---

## Task 1.2: Enforce HTTPS

### What to Change

**File: `application.yml`**

```yaml
# BEFORE:
authserver:
  security:
    require-https: false

# AFTER:
authserver:
  security:
    require-https: true

# ADD SSL config:
server:
  port: 9000
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
    key-alias: authserver
```

**File: `SecurityConfig.java`** — already handles this conditionally (lines 51-53), just need property change.

### New Files to Create

| File | Purpose |
|------|---------|
| `src/main/resources/keystore.p12` | SSL certificate keystore |
| `generate-ssl-cert.sh` | Script to generate self-signed cert for dev |

### Implementation Steps

1. Generate self-signed certificate for development:
   ```bash
   keytool -genkeypair -alias authserver -keyalg RSA -keysize 2048 \
     -storetype PKCS12 -keystore keystore.p12 -validity 365 \
     -storepass changeit -dname "CN=localhost"
   ```
2. Place `keystore.p12` in `src/main/resources/`
3. Update `application.yml` with SSL config
4. Set `require-https: true`
5. Update all redirect URIs to use `https://`
6. Create `application-dev.yml` profile with `require-https: false` for local dev without SSL

### Testing

```bash
# Should redirect HTTP to HTTPS
curl -v http://localhost:9000/oauth2/token
# Expected: 302 redirect to https://localhost:9000/oauth2/token

# HTTPS should work
curl -k https://localhost:9000/.well-known/openid-configuration
```

---

## Task 1.3: Disable H2 Console

### What to Change

**File: `application.yml`**

```yaml
# BEFORE:
spring:
  h2:
    console:
      enabled: true
      path: /h2-console

# AFTER:
spring:
  h2:
    console:
      enabled: false    # DISABLED in all environments
```

### Production Database Migration

H2 in-memory is for development only. Production needs a real database:

**File: `application-prod.yml`** (NEW)

```yaml
spring:
  datasource:
    url: jdbc:postgresql://${DB_HOST}:${DB_PORT}/${DB_NAME}
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    driver-class-name: org.postgresql.Driver
  h2:
    console:
      enabled: false
  jpa:
    hibernate:
      ddl-auto: validate    # Never auto-create in prod
    show-sql: false
```

### Implementation Steps

1. Set `h2.console.enabled: false` in main `application.yml`
2. Create `application-prod.yml` with PostgreSQL config
3. Add PostgreSQL driver dependency in `pom.xml`
4. Add Flyway/Liquibase for schema migration management
5. Add `SecurityConfig` rule to block `/h2-console` explicitly:
   ```java
   .requestMatchers("/h2-console/**").denyAll()
   ```

---

## Task 1.4: Switch to LDAPS (Encrypted LDAP)

### What to Change

**File: `application.yml`**

```yaml
# BEFORE:
spring:
  ldap:
    urls: ldap://localhost:389                    # PLAINTEXT
    password: ${LDAP_PASSWORD:changeit}           # WEAK DEFAULT

# AFTER:
spring:
  ldap:
    urls: ldaps://ldap.company.com:636            # ENCRYPTED
    password: ${LDAP_PASSWORD}                    # NO DEFAULT - must be provided
```

### Implementation Steps

1. Change `ldap://` to `ldaps://` and port `389` to `636`
2. Remove default password `changeit` — force environment variable
3. Add LDAP server's CA certificate to Java truststore:
   ```bash
   keytool -import -alias ldap-ca -file ldap-ca.crt \
     -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit
   ```
4. Add connection pool and timeout config:
   ```yaml
   spring:
     ldap:
       urls: ldaps://ldap.company.com:636
       base: dc=company,dc=com
       username: ${LDAP_BIND_DN}
       password: ${LDAP_PASSWORD}
     # Connection pool
     pool:
       enabled: true
       max-active: 10
       max-idle: 5
   ```
5. Add LDAP connection health check in actuator

### Testing

```bash
# Verify LDAPS connectivity
openssl s_client -connect ldap.company.com:636 -showcerts

# Test authentication
curl -u "user:password" https://localhost:9000/api/clients
```

---

## Task 1.5: Remove Hardcoded Credentials

### What to Change

**File: `SecurityConfig.java`** — Replace in-memory users with database/LDAP users

```java
// BEFORE: Hardcoded users
@Bean
public UserDetailsService userDetailsService() {
    UserDetails user = User.withUsername("user")
        .password("{noop}password").roles("USER").build();
    UserDetails admin = User.withUsername("admin")
        .password("{noop}admin").roles("USER", "ADMIN").build();
    return new InMemoryUserDetailsManager(user, admin);
}

// AFTER: LDAP-backed authentication
@Bean
public AuthenticationProvider ldapAuthenticationProvider() {
    // Use LdapAuthenticationProvider with AD integration
    // Map AD groups to Spring Security roles
    // Use ADUser model for user details
}
```

### Implementation Steps

1. Create `LdapUserDetailsService` implementing `UserDetailsService`
2. Map AD attributes to `ADUser` model (model already exists)
3. Configure `LdapAuthenticationProvider` in `SecurityConfig`
4. Remove `InMemoryUserDetailsManager` bean
5. Keep a `application-dev.yml` profile with in-memory users for local testing only
6. Ensure admin endpoints (`/api/clients`, `/api/keys`) require `ROLE_ADMIN`

---

## Phase 1 Summary — Files to Modify

| File | Changes |
|------|---------|
| `SecurityConfig.java` | BCrypt passwords, block H2, LDAP auth provider, remove hardcoded users |
| `AuthorizationServerConfig.java` | BCrypt client secrets |
| `ClientManagementService.java` | BCrypt dynamic client secrets |
| `application.yml` | HTTPS, H2 disable, LDAPS, remove default passwords |
| `pom.xml` | PostgreSQL driver, Flyway dependency |

### New Files

| File | Purpose |
|------|---------|
| `application-prod.yml` | Production profile config |
| `application-dev.yml` | Dev profile with relaxed security |
| `keystore.p12` | SSL certificate |
| `LdapUserDetailsService.java` | LDAP authentication service |
| `generate-ssl-cert.sh` | Dev certificate generation script |
