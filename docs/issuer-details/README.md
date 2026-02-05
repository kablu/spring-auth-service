# Issuer Details - Documentation

This folder contains detailed documentation about JWT issuer validation, JWKS (JSON Web Key Set), and key rotation in the Spring Authorization Server.

## Documents

| # | File | Topic |
|---|------|-------|
| 1 | [01-ISSUER-VALIDATION.md](01-ISSUER-VALIDATION.md) | Issuer kya hai, sample token se validation flow, kab fail hota hai |
| 2 | [02-JWKS-BUILD-AND-ROLE.md](02-JWKS-BUILD-AND-ROLE.md) | JWKS kaise build hota hai, Private/Public key ka role, complete verification flow with code references |
| 3 | [03-KEY-ROTATION-FLOW.md](03-KEY-ROTATION-FLOW.md) | Key rotation kya hai, manual + automatic rotation, grace period, cleanup lifecycle |

## Reading Order

Start from `01` and go sequentially - each document builds on the previous one:

```
01-ISSUER-VALIDATION    -->  Issuer kya hai, kaise validate hota hai
        |
        v
02-JWKS-BUILD-AND-ROLE  -->  JWKS kaise banta hai, token sign/verify flow
        |
        v
03-KEY-ROTATION-FLOW    -->  Keys rotate kaise hoti hain, lifecycle
```
