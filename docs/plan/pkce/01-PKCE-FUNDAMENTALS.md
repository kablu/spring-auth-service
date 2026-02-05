# 01 - PKCE Fundamentals

## PKCE Kya Hai?

**PKCE = Proof Key for Code Exchange** (pronounced "pixy")

RFC 7636 mein define hua hai. Originally mobile apps ke liye bana tha, ab **sabhi public clients** (SPA, mobile, desktop) ke liye **mandatory** maana jaata hai.

## Problem: Authorization Code Interception Attack

```
WITHOUT PKCE:

Angular App                    Auth Server                  Attacker
     │                              │                          │
     │── GET /authorize ──────────>│                          │
     │                              │                          │
     │<─── 302 ?code=ABC123 ───────│                          │
     │                              │                          │
     │ ┌─────────────────────────────────────────────────────┐│
     │ │ PROBLEM: Authorization code travels through browser ││
     │ │ Attacker can intercept via:                         ││
     │ │ - Browser history                                   ││
     │ │ - Malicious browser extension                       ││
     │ │ - Referer header leakage                            ││
     │ │ - Shared device                                     ││
     │ └─────────────────────────────────────────────────────┘│
     │                              │                          │
     │                              │   Attacker got code=ABC123
     │                              │          │
     │                              │<─── POST /token ────────│
     │                              │     code=ABC123          │
     │                              │                          │
     │                              │─── access_token ───────>│
     │                              │                          │
     │                    ATTACKER HAS ACCESS TOKEN!          │
```

## Solution: PKCE

```
WITH PKCE:

Angular App                    Auth Server                  Attacker
     │                              │                          │
     │ Generate:                    │                          │
     │ code_verifier = random(43-128 chars)                   │
     │ code_challenge = BASE64URL(SHA256(code_verifier))      │
     │                              │                          │
     │── GET /authorize ──────────>│                          │
     │   + code_challenge          │                          │
     │   + code_challenge_method   │                          │
     │                              │                          │
     │     Server stores:           │                          │
     │     code_challenge           │                          │
     │     linked to auth code      │                          │
     │                              │                          │
     │<─── 302 ?code=ABC123 ───────│                          │
     │                              │                          │
     │                              │   Attacker got code=ABC123
     │                              │          │
     │                              │<─── POST /token ────────│
     │                              │     code=ABC123          │
     │                              │     (NO code_verifier!)  │
     │                              │                          │
     │                              │─── 400 Bad Request ────>│
     │                              │     "invalid_grant"      │
     │                              │                          │
     │── POST /token ─────────────>│   ATTACKER BLOCKED!      │
     │   code=ABC123                │                          │
     │   code_verifier=original     │                          │
     │                              │                          │
     │   Server verifies:           │                          │
     │   SHA256(code_verifier) ==   │                          │
     │   stored code_challenge?     │                          │
     │   YES ✓                      │                          │
     │                              │                          │
     │<─── access_token ───────────│                          │
     │                              │                          │
     │   ONLY ORIGINAL APP GETS TOKEN!                        │
```

## PKCE Values Explained

### 1. code_verifier

- **Kya hai:** Random cryptographic string
- **Length:** 43 to 128 characters
- **Allowed chars:** `[A-Z] [a-z] [0-9] - . _ ~`
- **Kab generate:** Authorization request se pehle
- **Kahan store:** Browser memory (sessionStorage recommended)
- **Kab use:** Token request mein

```javascript
// Generate code_verifier
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

// Example output:
// "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

### 2. code_challenge

- **Kya hai:** Hash of code_verifier
- **Formula:** `BASE64URL(SHA256(code_verifier))`
- **Kab generate:** code_verifier ke saath, same time
- **Kahan send:** Authorization request mein
- **Server stores:** Links to authorization code

```javascript
// Generate code_challenge from code_verifier
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return base64UrlEncode(new Uint8Array(digest));
}

// Example:
// verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
// challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

### 3. code_challenge_method

- **Value:** `S256` (SHA-256 hashing)
- **Alternative:** `plain` (code_challenge = code_verifier, NOT RECOMMENDED)
- **Server must support:** `S256` minimum

```
code_challenge_method=S256

Means:
code_challenge = BASE64URL(SHA256(code_verifier))
```

## Base64URL Encoding

Standard Base64 se different hai:

| Standard Base64 | Base64URL |
|-----------------|-----------|
| `+` | `-` |
| `/` | `_` |
| `=` padding | No padding |

```javascript
function base64UrlEncode(buffer) {
    return btoa(String.fromCharCode(...buffer))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}
```

## Security: Why SHA-256?

```
Attack scenario without SHA-256 (plain method):

1. Attacker intercepts: code_challenge = "ABC123"
2. Attacker knows: code_verifier = "ABC123" (same value!)
3. Attacker can complete token request ❌

With SHA-256:

1. Attacker intercepts: code_challenge = "E9Melhoa2OwvF..."
2. Attacker needs: code_verifier = ???
3. SHA-256 is ONE-WAY — cannot reverse ✓
4. Attacker cannot guess verifier ✓
5. Attack blocked ✓
```

## PKCE Flow Timeline

```
T0:  User clicks "Login" in Angular app

T1:  Angular generates:
     - code_verifier (keep in browser memory)
     - code_challenge (send to server)
     - state (CSRF protection)

T2:  Browser redirects to:
     /oauth2/authorize?...&code_challenge=XYZ

T3:  User sees login page, enters credentials

T4:  Server validates credentials
     Server generates authorization code
     Server stores: { code: ABC, challenge: XYZ }

T5:  Browser redirects back:
     /callback?code=ABC&state=...

T6:  Angular extracts code from URL
     Angular retrieves stored code_verifier

T7:  Angular sends POST /token:
     - code=ABC
     - code_verifier=original_value

T8:  Server receives request:
     - Looks up stored challenge for code ABC
     - Calculates: SHA256(received_verifier)
     - Compares: calculated == stored_challenge?
     - If YES → issue tokens
     - If NO → reject with invalid_grant

T9:  Angular receives tokens
     Angular stores tokens securely
     User is logged in
```

## Summary

| Component | Who Generates | Who Stores | Who Verifies |
|-----------|--------------|------------|--------------|
| code_verifier | Client (Angular) | Client (browser) | — |
| code_challenge | Client (Angular) | Server (temp, with auth code) | Server |
| authorization_code | Server | Server (temp) | Server |
| access_token | Server | Client (browser) | Resource Server |
