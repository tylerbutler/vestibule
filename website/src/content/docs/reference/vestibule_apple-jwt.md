---
title: "vestibule_apple/jwt"
description: "JWT verification using ywt_core with a custom Erlang FFI backend."
nav:
  group: Reference
  groupOrder: 20
  order: 25
  label: "vestibule_apple/jwt"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_apple/jwt
---

# `vestibule_apple/jwt`

JWT verification using ywt_core with a custom Erlang FFI backend.

This replaces ywt_erlang to avoid an OTP 27 compatibility issue in
its EC key generation. We only need verification (not key generation)
for production use; the HMAC signing counterpart used by tests lives
in `test/vestibule_apple/jwt_signing.gleam`.

## Types

### `ParseError`

Detailed error information for JWT parsing failures.

```gleam
pub type ParseError {
  MalformedToken
  InvalidHeaderEncoding
  InvalidPayloadEncoding
  InvalidSignatureEncoding
  InvalidHeaderJson(json.DecodeError)
  InvalidPayloadJson(json.DecodeError)
  NoMatchingKey
  InvalidSignature
  TokenExpired(expired_at: timestamp.Timestamp)
  TokenNotYetValid(not_before: timestamp.Timestamp)
  InvalidIssuer(
    expected: List(String),
    actual: String
  )
  InvalidAudience(
    expected: List(String),
    actual: String
  )
  InvalidSubject(
    expected: List(String),
    actual: String
  )
  InvalidId(
    expected: List(String),
    actual: String
  )
  MissingClaim(claim_name: String)
  ClaimDecodingError(
    claim_name: String,
    error: List(decode.DecodeError)
  )
  InvalidCustomClaim(claim_name: String)
  PayloadDecodingError(List(decode.DecodeError))
}
```

## Functions

### `decode`

Verify a JWT signature and validate claims.

```gleam
pub fn decode(
  jwt: String,
  using: decode.Decoder(a),
  claims: List(claim.Claim),
  keys: List(verify_key.VerifyKey)
) -> Result(a, ParseError)
```
