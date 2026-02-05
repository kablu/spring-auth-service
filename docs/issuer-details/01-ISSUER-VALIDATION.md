# JWT Issuer Validation - Complete Flow

## Issuer Kya Hai?

Issuer (`iss`) ek claim hai JWT token ke andar jo batata hai ki **yeh token kisne banaya**.
Aapke project mein issuer configure hai:

**File:** `src/main/resources/application.yml`
```yaml
authserver:
  jwt:
    issuer: http://localhost:9000
```

**File:** `src/main/java/com/corp/authserver/config/AuthServerProperties.java`
```java
private String issuer = "https://authserver.company.com"; // default
```

**File:** `src/main/java/com/corp/authserver/config/AuthorizationServerConfig.java`
```java
.issuer(properties.getJwt().getIssuer())  // config se issuer read hota hai
```

---

## Sample Token se Samjho

### Token milta hai jab `/oauth2/token` call karte ho:

```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoic2VydmljZS1jbGllbnQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE3Mzg4NzAwMDAsImlhdCI6MTczODg2NjQwMCwic2NvcGUiOlsiaW50ZXJuYWwucmVhZCJdLCJyb2xlcyI6WyJST0xFX1VTRVIiXSwidG9rZW5fdHlwZSI6ImFjY2Vzc190b2tlbiIsInVzZXJuYW1lIjoidXNlciJ9.SIGNATURE_HERE
```

### Token ke 3 parts (dot se separated):

**Part 1 - Header:**
```json
{
  "alg": "RS256",
  "kid": "abc123"
}
```

**Part 2 - Payload:**
```json
{
  "sub": "user",
  "aud": "service-client",
  "iss": "http://localhost:9000",    <-- YEH HAI ISSUER
  "exp": 1738870000,
  "iat": 1738866400,
  "scope": ["internal.read"],
  "roles": ["ROLE_USER"],
  "token_type": "access_token",
  "username": "user"
}
```

**Part 3 - Signature:** RSA-SHA256 digital signature

---

## Resource Server Kaise Validate Karta Hai

Jab koi client token lekar API call karta hai:

```
GET http://resource-server:8080/api/data
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

Resource server ke `application.yml` mein:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:9000
```

### Validation Steps:

```
1. Token ka payload decode karo
   -> iss = "http://localhost:9000"

2. Apni config se expected issuer lo
   -> issuer-uri = "http://localhost:9000"

3. MATCH karo:
   "http://localhost:9000" == "http://localhost:9000"  PASS

4. Public key fetch karo:
   GET http://localhost:9000/oauth2/jwks
   -> kid "abc123" wali key select karo

5. Signature verify karo us public key se  PASS

6. Expiration check karo:
   exp (1738870000) > current time?  PASS

7. SAB PASS -> Token valid, request allowed
```

---

## Kab FAIL Hoga?

### Scenario: Issuer Mismatch

```
Token payload:     "iss": "http://localhost:9000"
Resource server:   issuer-uri: https://authserver.company.com

"http://localhost:9000" != "https://authserver.company.com"   FAIL!
```

Response:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token",
  error_description="The iss claim is not valid"
```

### Visual Flow:

```
                    TOKEN MEIN KYA HAI
                    +---------------------+
                    | iss: localhost:9000  |--+
                    | sub: user            |  |
                    | exp: 1738870000      |  |   MATCH?
                    | scope: internal.read |  |
                    +---------------------+  |
                                             v
              RESOURCE SERVER CONFIG     +--------+
              +---------------------+    |Compare |
              |issuer-uri:          |--->| issuer |
              | localhost:9000      |    +---+----+
              +---------------------+        |
                                             v
                                    +--------------+
                              YES   |   Match?     |  NO
                           +--------+              +--------+
                           v        +--------------+        v
                    +-------------+                 +--------------+
                    | Fetch JWKS  |                 | 401          |
                    | Verify sig  |                 | Unauthorized |
                    | Check exp   |                 | invalid_token|
                    |  Allow      |                 +--------------+
                    +-------------+
```
