# JWKS - Kaise Build Hota Hai aur Kya Role Play Karta Hai

## RSA Key Pair - Foundation

```
RSA Key Pair = Private Key + Public Key

Private Key -> Token SIGN karne ke liye (sirf Auth Server ke paas)
Public Key  -> Token VERIFY karne ke liye (sabko share hoti hai via JWKS)
```

---

## Step 1: Server Start - Key Generate Hoti Hai

**File:** `src/main/java/com/corp/authserver/config/JwkConfig.java`

### Bean Creation (Line 31-43):

```java
@Bean
public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = generateRsaKey();        // Key pair generate
    currentKeyId = rsaKey.getKeyID();        // Unique ID assign
    keyMap.put(currentKeyId, rsaKey);        // Memory mein store
    log.info("Generated initial RSA key pair with kid: {}", currentKeyId);

    return (jwkSelector, securityContext) -> {
        List<JWK> keys = new ArrayList<>(keyMap.values());
        JWKSet jwkSet = new JWKSet(keys);
        return jwkSelector.select(jwkSet);
    };
}
```

### Key Generation (Line 45-63):

```java
public RSAKey generateRsaKey() {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);                    // 2048-bit RSA
    KeyPair keyPair = keyPairGenerator.generateKeyPair(); // Private + Public

    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    String keyId = UUID.randomUUID().toString();  // e.g., "a1b2c3d4-..."

    return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(keyId)            // "kid" = key identifier
            .issueTime(new Date())   // kab bani
            .build();
}
```

### Memory mein kya store hua:

```
keyMap = {
  "a1b2c3d4-e5f6-...": RSAKey {
      publicKey:  (2048-bit RSA public key)
      privateKey: (2048-bit RSA private key)   <-- SIRF server ke paas
      kid:        "a1b2c3d4-e5f6-..."
      issueTime:  2026-02-05T10:00:00Z
  }
}
```

---

## Step 2: Token Sign Hota Hai (Private Key se)

Jab koi `/oauth2/token` call karta hai, server internally yeh karta hai:

```
+-----------------------------------------------------------+
|                    JWT Token Banana                        |
|                                                           |
|  Header:                                                  |
|  {                                                        |
|    "alg": "RS256",              <-- Algorithm              |
|    "kid": "a1b2c3d4-e5f6-..."  <-- Kis key se sign hua   |
|  }                                                        |
|                                                           |
|  Payload:                                                 |
|  {                                                        |
|    "iss": "http://localhost:9000",                         |
|    "sub": "user",                                         |
|    "exp": 1738870000,                                     |
|    "roles": ["ROLE_USER"],                                |
|    ...                                                    |
|  }                                                        |
|                                                           |
|  Signature:                                               |
|  RSA-SHA256(                                              |
|    base64(header) + "." + base64(payload),                |
|    PRIVATE KEY   <-- Server ki private key se sign        |
|  )                                                        |
|                                                           |
|  Final Token:                                             |
|  eyJhbGci...  .  eyJzdWIi...  .  SflKxwRJ...             |
|  [header]     .  [payload]    .  [signature]              |
+-----------------------------------------------------------+
```

---

## Step 3: JWKS Endpoint - Public Key Expose Hoti Hai

Jab koi `GET /oauth2/jwks` call karta hai, `JwkConfig.java` line 38-42 execute hota hai:

```java
return (jwkSelector, securityContext) -> {
    List<JWK> keys = new ArrayList<>(keyMap.values());  // Sab keys
    JWKSet jwkSet = new JWKSet(keys);                   // JWK Set banao
    return jwkSelector.select(jwkSet);                  // Selector match
};
```

### Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "a1b2c3d4-e5f6-...",
      "n": "0vx7agoebGcQ...",        <-- Public key ka modulus
      "e": "AQAB"                     <-- Public key ka exponent
    }
  ]
}
```

> **IMPORTANT:** Sirf PUBLIC key parts (`n`, `e`) expose hoti hain. Private key KABHI response mein nahi jaati.

---

## Step 4: Resource Server Token Verify Karta Hai

Jab koi API call aati hai Bearer token ke saath:

```
GET http://resource-server:8080/api/data
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImExYjJjM2Q0LSJ9.eyJpc3Mi...
```

### Step 4a: Token ka header decode karo

```json
{ "alg": "RS256", "kid": "a1b2c3d4-e5f6-..." }

-> Algorithm: RS256 (RSA + SHA-256)
-> kid: "a1b2c3d4-e5f6-..."
```

### Step 4b: JWKS fetch karo (pehli baar, phir cache hoti hai)

```
GET http://localhost:9000/oauth2/jwks

Response:
{
  "keys": [
    { "kty":"RSA", "kid":"a1b2c3d4-e5f6-...", "n":"0vx7a...", "e":"AQAB" },
    { "kty":"RSA", "kid":"x9y8z7w6-...",       "n":"8f3kd...", "e":"AQAB" }
  ]
}
```

### Step 4c: kid se sahi key match karo

```
Token ka kid:     "a1b2c3d4-e5f6-..."
JWKS key 1 kid:   "a1b2c3d4-e5f6-..."  <-- MATCH! Yeh key use karo
JWKS key 2 kid:   "x9y8z7w6-..."       <-- no match
```

### Step 4d: Signature verify karo (PUBLIC key se)

```
expected = RSA-SHA256-VERIFY(
    "eyJhbGci..." + "." + "eyJpc3Mi...",   <-- header.payload
    PUBLIC KEY (from JWKS),                 <-- matched public key
    "SflKxwRJ..."                           <-- token ki signature
)

Agar signature match -> Token tamper nahi hua  VALID
Agar mismatch        -> Token modified/forged  REJECT
```

### Step 4e: Claims validate karo

```
iss check:  "http://localhost:9000" == config issuer-uri?  PASS
exp check:  1738870000 > current timestamp?                PASS (not expired)
aud check:  "service-client" allowed?                      PASS
nbf check:  current time > not-before time?                PASS
```

---

## Complete Visual Flow

```
   AUTH SERVER (localhost:9000)              RESOURCE SERVER (localhost:8080)
   +--------------------------+             +--------------------------+
   |                          |             |                          |
   |  Server Start:           |             |  application.yml:        |
   |  +--------------------+  |             |  issuer-uri:             |
   |  | Generate RSA Key   |  |             |   http://localhost:9000  |
   |  | Private + Public   |  |             |                          |
   |  | kid: "a1b2c3d4"   |  |             |                          |
   |  +--------------------+  |             |                          |
   |           |               |             |                          |
   |           v               |             |                          |
   |  +--------------------+  |             |                          |
   |  | keyMap = {         |  |             |                          |
   |  |  "a1b2c3d4": {    |  |             |                          |
   |  |   public + private |  |             |                          |
   |  |  }                 |  |             |                          |
   |  | }                  |  |             |                          |
   |  +--------------------+  |             |                          |
   |                          |             |                          |
   +--------------------------+             +--------------------------+
                |                                       |
   =================================================================
   CLIENT: POST /oauth2/token
   =================================================================
                |                                       |
                v                                       |
   +--------------------------+                         |
   | 1. Build JWT payload:    |                         |
   |    iss: localhost:9000   |                         |
   |    sub: user             |                         |
   |    exp: +3600 sec        |                         |
   |    roles: [ROLE_USER]    |                         |
   |                          |                         |
   | 2. Sign with PRIVATE KEY |                         |
   |    alg: RS256            |                         |
   |    kid: "a1b2c3d4"      |                         |
   |                          |                         |
   | 3. Return JWT token      |                         |
   |    eyJhbGci.eyJpc3.Sig  |                         |
   +----------+---------------+                         |
              |                                         |
              v                                         |
   CLIENT gets token: eyJhbGci.eyJpc3.Sig               |
              |                                         |
   =================================================================
   CLIENT: GET /api/data, Authorization: Bearer eyJhbGci.eyJpc3.Sig
   =================================================================
              |                                         |
              |                                         v
              |                        +------------------------------+
              |                        | 4a. Decode header:           |
              |                        |     kid = "a1b2c3d4"        |
              |                        |     alg = "RS256"           |
              |                        |                              |
              |                        | 4b. Fetch JWKS:              |
              |    +-------------------+----- GET /oauth2/jwks        |
              |    |                   |                              |
              |    v                   |                              |
   +----------------------+           |                              |
   | Return PUBLIC keys:  |           |                              |
   | {                    |           |                              |
   |  "keys": [{          |           |                              |
   |   "kid":"a1b2c3d4",  |---------->| 4c. Match kid               |
   |   "n": "0vx7a...",   |           |     "a1b2c3d4" == "a1b2c3d4"|
   |   "e": "AQAB"        |           |     FOUND!                   |
   |  }]                  |           |                              |
   | }                    |           | 4d. Verify signature          |
   +----------------------+           |      with PUBLIC KEY          |
                                      |      VALID                    |
                                      |                              |
                                      | 4e. Check claims:            |
                                      |      iss match?  YES         |
                                      |      exp valid?  YES         |
                                      |      aud valid?  YES         |
                                      |                              |
                                      | --> REQUEST ALLOWED           |
                                      +------------------------------+
```

---

## Private Key vs Public Key - Role Summary

```
+-------------------------+----------------------------------+
|     PRIVATE KEY         |         PUBLIC KEY               |
|  (Auth Server ke paas)  |  (JWKS se sabko milti hai)       |
+-------------------------+----------------------------------+
| Token SIGN karta hai    | Token VERIFY karta hai           |
| Kabhi share nahi hoti   | /oauth2/jwks pe publicly exposed |
| Ek hi server pe rehti   | Koi bhi resource server le sakta |
| Forgery impossible      | Signature match = token genuine  |
| without this            | Signature mismatch = REJECT      |
+-------------------------+----------------------------------+
```
