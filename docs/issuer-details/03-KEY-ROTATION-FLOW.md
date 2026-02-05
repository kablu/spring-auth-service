# Key Rotation - Kya Hota Hai aur Kaise Kaam Karta Hai

## Key Rotation Kyun Zaroori Hai?

Agar ek hi key hamesha use hoti rahe toh:
- Key compromise hone ka risk badhta hai
- Agar key leak ho gayi toh sabhi tokens forge ho sakte hain
- Security best practice: keys regularly rotate karo

---

## Aapke Project Mein Key Rotation

### Configuration

**File:** `src/main/java/com/corp/authserver/config/AuthServerProperties.java`

```java
@Data
public static class KeyRotationProperties {
    private boolean enabled = true;
    private int rotationDays = 90;       // 90 din baad rotate
    private int gracePeriodDays = 7;     // Purani key 7 din aur valid
}
```

**File:** `src/main/resources/application.yml`

```yaml
authserver:
  key-rotation:
    enabled: true
    rotation-days: 90
    grace-period-days: 7
```

---

## Manual Key Rotation Flow

### API Call:

```
POST http://localhost:9000/api/keys/rotate
Authorization: Basic YWRtaW46YWRtaW4=    (admin:admin)
```

### Code Flow:

**File:** `src/main/java/com/corp/authserver/controller/KeyManagementController.java`

```
KeyManagementController.rotateKeys()
         |
         v
KeyRotationService.rotateKeys()
         |
         v
JwkConfig.rotateKey()
```

**File:** `src/main/java/com/corp/authserver/config/JwkConfig.java` (Line 65-71)

```java
public void rotateKey() {
    RSAKey newKey = generateRsaKey();          // Nayi key generate
    String newKeyId = newKey.getKeyID();
    keyMap.put(newKeyId, newKey);              // Add karo (purani bhi rehti hai!)
    log.info("Rotated RSA key. New kid: {}, total keys: {}", newKeyId, keyMap.size());
    currentKeyId = newKeyId;                  // Active key change
}
```

### Response:

```json
{
  "status": "rotated",
  "activeKeyId": "x9y8z7w6-new-uuid",
  "totalKeys": 2
}
```

---

## Rotation ke Baad Memory Mein Kya Hota Hai

### Before Rotation:
```
keyMap = {
  "a1b2c3d4-...": RSAKey { old key pair }     <-- ACTIVE
}
currentKeyId = "a1b2c3d4-..."
```

### After Rotation:
```
keyMap = {
  "a1b2c3d4-...": RSAKey { old key pair },    <-- PURANI (still present)
  "x9y8z7w6-...": RSAKey { new key pair }     <-- NAYI (now active)
}
currentKeyId = "x9y8z7w6-..."
```

### JWKS Endpoint ab 2 keys return karega:

```
GET /oauth2/jwks

{
  "keys": [
    { "kid": "a1b2c3d4-...", "n": "old_modulus...", "e": "AQAB" },
    { "kid": "x9y8z7w6-...", "n": "new_modulus...", "e": "AQAB" }
  ]
}
```

### Token Verification After Rotation:

```
Purane tokens (kid: "a1b2c3d4"):
  -> JWKS mein purani key abhi bhi hai
  -> Verify ho jaayenge  VALID

Naye tokens (kid: "x9y8z7w6"):
  -> Nayi active key se sign honge
  -> Nayi key se verify honge  VALID
```

> **Dono keys kaam karti hain** rotation ke baad — isliye koi downtime nahi hota!

---

## Automatic Key Rotation (Scheduled)

**File:** `src/main/java/com/corp/authserver/service/KeyRotationService.java`

```java
@Scheduled(cron = "0 0 2 * * ?")    // Roz raat 2 AM pe chalta hai
public void checkAndRotateKeys() {
    if (!properties.getKeyRotation().isEnabled()) {
        return;    // Disabled hai toh kuch mat karo
    }

    Instant keyCreationTime = jwkConfig.getKeyCreationTime(
        jwkConfig.getCurrentKeyId()
    );
    long keyAgeDays = Duration.between(keyCreationTime, Instant.now()).toDays();

    if (keyAgeDays >= properties.getKeyRotation().getRotationDays()) {
        // 90 din se zyada purani hai -> rotate karo
        rotateKeys();
        cleanupExpiredKeys();
    }
}
```

### Timeline:

```
Day 0:    Key "a1b2c3d4" generated (server start)
          keyMap: { "a1b2c3d4": key1 }
          JWKS:   [key1]

Day 90:   Automatic rotation triggers at 2 AM
          New key "x9y8z7w6" generated
          keyMap: { "a1b2c3d4": key1, "x9y8z7w6": key2 }
          JWKS:   [key1, key2]
          New tokens signed with key2

Day 97:   Grace period over (90 + 7 days)
          cleanupExpiredKeys() removes key1
          keyMap: { "x9y8z7w6": key2 }
          JWKS:   [key2]
          Purane tokens (key1 se signed) ab verify NAHI honge

Day 180:  Next rotation
          New key "m3n4o5p6" generated
          keyMap: { "x9y8z7w6": key2, "m3n4o5p6": key3 }
          ...cycle repeats
```

---

## Key Cleanup - Expired Keys Remove Karna

**File:** `src/main/java/com/corp/authserver/service/KeyRotationService.java`

```java
public void cleanupExpiredKeys() {
    int gracePeriodDays = properties.getKeyRotation().getGracePeriodDays();
    int rotationDays = properties.getKeyRotation().getRotationDays();

    jwkConfig.getKeyMap().forEach((keyId, rsaKey) -> {
        Instant keyCreationTime = jwkConfig.getKeyCreationTime(keyId);
        long keyAgeDays = Duration.between(keyCreationTime, Instant.now()).toDays();

        if (keyAgeDays > (rotationDays + gracePeriodDays)) {
            // 90 + 7 = 97 din se purani key -> remove
            jwkConfig.removeKey(keyId);
        }
    });
}
```

**File:** `src/main/java/com/corp/authserver/config/JwkConfig.java` (Line 73-78)

```java
public void removeKey(String keyId) {
    if (!keyId.equals(currentKeyId)) {   // Active key kabhi remove nahi hogi
        keyMap.remove(keyId);
        log.info("Removed expired key: {}", keyId);
    }
}
```

> **Safety:** `currentKeyId` wali key kabhi remove nahi hoti, chahe kitni bhi purani ho.

---

## Visual: Key Rotation Lifecycle

```
  Day 0                Day 90              Day 97              Day 180
   |                     |                   |                    |
   v                     v                   v                    v
+--------+         +-----------+       +-----------+       +-----------+
| key1   |         | key1+key2 |       | key2 only |       | key2+key3 |
| ACTIVE |         | key2=NEW  |       | key1      |       | key3=NEW  |
|        |         | ACTIVE    |       | REMOVED   |       | ACTIVE    |
+--------+         +-----------+       +-----------+       +-----------+

JWKS:              JWKS:               JWKS:               JWKS:
[key1]             [key1, key2]        [key2]              [key2, key3]

Tokens signed      New tokens:key2     Old key1 tokens     New tokens:key3
with key1          Old tokens:key1     NOW INVALID!        Old tokens:key2
                   still valid                             still valid
                   (grace period)
```

---

## Key Status Check

### API Call:

```
GET http://localhost:9000/api/keys/status
Authorization: Basic YWRtaW46YWRtaW4=
```

### Response:

```json
{
  "activeKeyId": "x9y8z7w6-current-key-uuid",
  "totalKeys": 2
}
```

`totalKeys: 2` matlab rotation hui hai aur purani key abhi grace period mein hai.
`totalKeys: 1` matlab sirf ek active key hai.
