# Spring OAuth2 Authorization Server

Enterprise-grade OAuth2 Authorization Server with Active Directory integration, built on Spring Boot 3.x and Spring Authorization Server 1.2.x.

## 🎯 Features

### Core OAuth2 Features
- ✅ **OAuth 2.0 Access Tokens** - Standards-compliant token issuance
- ✅ **JWT Format** - JSON Web Tokens with RS256 signature
- ✅ **Refresh Tokens** - With automatic rotation for security
- ✅ **OpenID Connect** - ID tokens for authentication
- ✅ **Custom JWT Claims** - Roles, scopes, user attributes, tenant info
- ✅ **JWK Endpoint** - Public key distribution for token validation
- ✅ **Key Rotation** - Automated key rotation without downtime

### OAuth2 Grant Types
- ✅ **Authorization Code + PKCE** - For web and mobile apps
- ✅ **Client Credentials** - For machine-to-machine communication
- ✅ **Refresh Token** - Token renewal without re-authentication
- ❌ **Resource Owner Password** - Disabled (deprecated)
- ❌ **Implicit Grant** - Disabled (insecure)

### Security Features
- ✅ **PKCE Enforcement** - Mandatory for public clients
- ✅ **HTTPS** - Enforced for all endpoints (production)
- ✅ **CSRF Protection** - Cookie-based CSRF tokens
- ✅ **Refresh Token Rotation** - Prevents replay attacks
- ✅ **Token Revocation** - Standards-compliant revocation endpoint
- ✅ **Rate Limiting** - Protection against abuse
- ✅ **Audit Logging** - Complete security event tracking

### Integration Features
- ✅ **Active Directory** - LDAP authentication
- ✅ **Multiple Clients** - Database-backed client registration
- ✅ **Client Authentication** - Secret, Private Key JWT, mTLS
- ✅ **Resource Server Integration** - Independent token validation
- ✅ **Redirect URI Validation** - Per-client strict validation

## 📋 Requirements

- **Java**: 21 (LTS)
- **Maven**: 3.9+
- **PostgreSQL**: 14+
- **Active Directory**: LDAP accessible

## 🚀 Quick Start

### 1. Clone and Navigate
```bash
cd D:/poc/spring-auth-service
```

### 2. Configure Database
```sql
CREATE DATABASE authserver;
CREATE USER authserver WITH PASSWORD 'changeit';
GRANT ALL PRIVILEGES ON DATABASE authserver TO authserver;
```

### 3. Set Environment Variables
```bash
export DB_PASSWORD=your_db_password
export LDAP_PASSWORD=your_ldap_password
```

### 4. Build and Run
```bash
mvn clean install
mvn spring-boot:run
```

### 5. Access Endpoints
- Authorization Server: http://localhost:9000
- JWK Set: http://localhost:9000/oauth2/jwks
- Discovery: http://localhost:9000/.well-known/oauth-authorization-server
- Swagger UI: http://localhost:9000/swagger-ui.html

## 📖 Documentation

Comprehensive documentation available in `/docs`:

1. **[PROJECT-PLAN.md](docs/PROJECT-PLAN.md)** - Complete implementation plan
2. **API-GUIDE.md** - API usage guide (to be created)
3. **DEPLOYMENT-GUIDE.md** - Production deployment guide (to be created)
4. **TESTING-GUIDE.md** - Testing strategies (to be created)

## 🏗️ Project Structure

```
spring-auth-service/
├── src/main/java/com/corp/authserver/
│   ├── AuthServerApplication.java         # Main application
│   ├── config/
│   │   ├── AuthorizationServerConfig.java # OAuth2 configuration
│   │   ├── SecurityConfig.java            # Security configuration
│   │   ├── LdapConfig.java               # AD/LDAP configuration
│   │   ├── JwkConfig.java                # JWT signing keys
│   │   └── DatabaseConfig.java           # Database configuration
│   ├── controller/
│   │   ├── ClientManagementController.java
│   │   ├── KeyManagementController.java
│   │   └── TokenManagementController.java
│   ├── service/
│   │   ├── CustomTokenCustomizer.java    # JWT claims customization
│   │   ├── TokenRevocationService.java   # Token revocation
│   │   ├── JwkRotationService.java       # Key rotation
│   │   └── ADAuthenticationService.java  # AD authentication
│   ├── model/
│   │   └── ADUser.java                   # AD user model
│   ├── security/
│   │   ├── CustomUserDetailsContextMapper.java
│   │   ├── PkceValidator.java
│   │   └── RateLimitFilter.java
│   └── repository/
│       └── TokenBlacklistRepository.java
├── src/main/resources/
│   ├── application.yml                   # Main configuration
│   ├── schema.sql                       # Database schema
│   └── data.sql                         # Sample data
└── docs/
    └── PROJECT-PLAN.md                  # Complete project plan
```

## 🔐 OAuth2 Flows

### Authorization Code Flow with PKCE

```
1. Generate PKCE Challenge
   code_verifier = random(43-128 chars)
   code_challenge = base64url(sha256(code_verifier))

2. Authorization Request
   GET /oauth2/authorize?
     response_type=code
     &client_id=webapp
     &redirect_uri=https://webapp.com/callback
     &scope=read write
     &code_challenge=CHALLENGE
     &code_challenge_method=S256

3. User authenticates via AD

4. Token Request
   POST /oauth2/token
   grant_type=authorization_code
   &code=AUTH_CODE
   &redirect_uri=https://webapp.com/callback
   &client_id=webapp
   &client_secret=secret
   &code_verifier=VERIFIER

5. Response
   {
     "access_token": "eyJhbGc...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "refresh_token_here",
     "scope": "read write"
   }
```

### Client Credentials Flow

```
POST /oauth2/token
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials
&scope=api.read api.write

Response:
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "api.read api.write"
}
```

### Refresh Token Flow

```
POST /oauth2/token

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&client_id=webapp
&client_secret=secret

Response (with token rotation):
{
  "access_token": "NEW_ACCESS_TOKEN",
  "refresh_token": "NEW_REFRESH_TOKEN",  // Old one invalidated
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## 🔑 JWT Token Structure

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

## 🗄️ Database Schema

### Client Registration
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

### Token Storage
```sql
CREATE TABLE oauth2_authorization (
    id VARCHAR(100) PRIMARY KEY,
    registered_client_id VARCHAR(100) NOT NULL,
    principal_name VARCHAR(200) NOT NULL,
    access_token_value TEXT,
    refresh_token_value TEXT,
    -- ... additional fields
);
```

See `src/main/resources/schema.sql` for complete schema.

## 🧪 Testing

### Unit Tests
```bash
mvn test
```

### Integration Tests
```bash
mvn verify
```

### Manual Testing with curl

**Get Authorization Code:**
```bash
open "http://localhost:9000/oauth2/authorize?response_type=code&client_id=webapp&redirect_uri=https://webapp.com/callback&scope=read&code_challenge=CHALLENGE&code_challenge_method=S256"
```

**Exchange Code for Token:**
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://webapp.com/callback" \
  -d "client_id=webapp" \
  -d "client_secret=secret" \
  -d "code_verifier=VERIFIER"
```

**Client Credentials:**
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -u "backend-service:secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=api.read api.write"
```

**Refresh Token:**
```bash
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN" \
  -d "client_id=webapp" \
  -d "client_secret=secret"
```

**Revoke Token:**
```bash
curl -X POST http://localhost:9000/oauth2/revoke \
  -u "webapp:secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN"
```

**Get JWK Set:**
```bash
curl http://localhost:9000/oauth2/jwks
```

## 🔧 Configuration

### application.yml Overview

```yaml
authserver:
  token:
    access-token-validity-seconds: 3600      # 1 hour
    refresh-token-validity-seconds: 2592000  # 30 days
    reuse-refresh-tokens: false              # Enable rotation

  jwt:
    issuer: https://authserver.company.com

  security:
    require-https: true                      # Enforce HTTPS
    pkce-required-for-public-clients: true   # Enforce PKCE
    csrf-protection-enabled: true

  rate-limit:
    enabled: true
    requests-per-minute: 60
```

### Active Directory Configuration

```yaml
spring:
  ldap:
    urls: ldap://ad.company.com:389
    base: dc=company,dc=com
    username: CN=service-account,OU=Services,DC=company,DC=com
    password: ${LDAP_PASSWORD}
```

## 🚢 Production Deployment

### Prerequisites
1. Valid SSL certificate
2. PostgreSQL database
3. Active Directory access
4. Firewall rules configured

### Environment Variables
```bash
export DB_PASSWORD=<secure-password>
export LDAP_PASSWORD=<ldap-password>
export JWT_KEYSTORE_PASSWORD=<keystore-password>
export SSL_KEYSTORE_PASSWORD=<ssl-password>
```

### Docker Deployment (Optional)
```dockerfile
FROM eclipse-temurin:21-jre-alpine
COPY target/spring-auth-service-1.0.0-SNAPSHOT.jar app.jar
EXPOSE 9000
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

```bash
docker build -t spring-auth-service .
docker run -p 9000:9000 \
  -e DB_PASSWORD=secret \
  -e LDAP_PASSWORD=secret \
  spring-auth-service
```

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:9000/actuator/health
```

### Metrics (Prometheus)
```bash
curl http://localhost:9000/actuator/prometheus
```

### Custom Metrics
- `authserver.tokens.issued.total` - Total tokens issued
- `authserver.tokens.revoked.total` - Total tokens revoked
- `authserver.authentication.attempts.total` - Auth attempts
- `authserver.authentication.failures.total` - Auth failures

## 🤝 Integration with Resource Servers

### Spring Boot Resource Server Configuration

```java
@Configuration
@EnableResourceServer
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwkSetUri("https://authserver.company.com/oauth2/jwks")
            )
        );
        return http.build();
    }
}
```

### Token Validation
- Resource servers validate JWT signatures using public keys from `/oauth2/jwks`
- No network call to auth server for every request
- Public keys cached locally
- Independent validation = high performance

## 📝 License

Copyright © 2026 Company Corp. All rights reserved.

## 🆘 Support

For issues and questions:
- Check documentation in `/docs`
- Review Spring Authorization Server docs: https://docs.spring.io/spring-authorization-server/
- Contact: authserver-support@company.com

---

**Version**: 1.0.0
**Last Updated**: 2026-02-04
**Status**: ✅ Ready for Development
