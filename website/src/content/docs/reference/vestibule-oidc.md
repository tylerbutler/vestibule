---
title: "vestibule/oidc"
description: "Shared OpenID Connect ID-token verification."
nav:
  group: Reference
  groupOrder: 20
  order: 18
  label: "vestibule/oidc"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/oidc
---

# `vestibule/oidc`

Shared OpenID Connect ID-token verification.

This module verifies RS256 signatures and the identity claims used by
OIDC provider strategies. It does not fetch keys or retain tokens.

## Types

### `Jwks`

A validated set of RS256 RSA signing keys.

```gleam
pub type Jwks
```

### `VerificationError`

A token-free ID-token verification failure.

```gleam
pub type VerificationError {
  InvalidJwks
  MalformedToken
  UnsupportedAlgorithm
  UnknownKey
  InvalidSignature
  InvalidIssuer
  InvalidAudience
  InvalidAuthorizedParty
  Expired
  NotYetValid
  InvalidIssuedAt
  InvalidNonce
  MissingClaim(name: String)
  InvalidClaim(name: String)
}
```

### `VerifiedIdToken`

Claims from a verified OIDC ID token.

```gleam
pub type VerifiedIdToken
```

## Functions

### `audiences`

Return the verified audiences.

```gleam
pub fn audiences(VerifiedIdToken) -> List(String)
```

### `authorized_party`

Return the verified authorized party.

```gleam
pub fn authorized_party(VerifiedIdToken) -> option.Option(String)
```

### `error_message`

Return a short token-free description suitable for an authentication error.

```gleam
pub fn error_message(VerificationError) -> String
```

### `hosted_domain`

Return the verified Google Workspace hosted domain.

```gleam
pub fn hosted_domain(VerifiedIdToken) -> option.Option(String)
```

### `nonce`

Return the verified nonce.

```gleam
pub fn nonce(VerifiedIdToken) -> option.Option(String)
```

### `object_id`

Return the verified Microsoft object ID.

```gleam
pub fn object_id(VerifiedIdToken) -> option.Option(String)
```

### `parse_jwks`

Parse a JWKS document, retaining only RSA signing keys pinned to RS256.

Vestibule limits the document to 16 keys, accepts only RSA signing keys
whose `alg` is absent or `RS256`, and requires unique non-empty key IDs when
the set contains multiple eligible keys.

RSA integer decoding and signature verification are delegated to `ywt` so
Vestibule does not maintain cryptographic key parsing. `ywt` validates the
JWK encoding, but it does not enforce a minimum or maximum RSA modulus size
or restrict the public exponent. Applications that require those key-strength
policies must validate the provider JWKS separately.

```gleam
pub fn parse_jwks(String) -> Result(Jwks, VerificationError)
```

### `subject`

Return the verified subject.

```gleam
pub fn subject(VerifiedIdToken) -> String
```

### `tenant_id`

Return the verified Microsoft tenant ID.

```gleam
pub fn tenant_id(VerifiedIdToken) -> option.Option(String)
```

### `verify_rs256`

Verify an RS256 ID token and validate its OIDC identity claims.

`expected_nonce` can be `None` when the callback layer will compare the
nonce from this exact verified token before it accepts the identity.
Provider implementations should otherwise pass the nonce stored for the
authorization request.

```gleam
pub fn verify_rs256(
  token: String,
  using: Jwks,
  issuer: String,
  audience: String,
  expected_nonce: option.Option(String)
) -> Result(VerifiedIdToken, VerificationError)
```
