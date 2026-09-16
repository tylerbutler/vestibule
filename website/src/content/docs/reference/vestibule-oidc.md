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

### `bool_claim`

Return a required boolean claim from the verified payload.

```gleam
pub fn bool_claim(
  VerifiedIdToken,
  String
) -> Result(Bool, VerificationError)
```

### `error_message`

Return a short token-free description suitable for an authentication error.

```gleam
pub fn error_message(VerificationError) -> String
```

### `hosted_domain`

Return Google's verified hosted-domain claim, when present.

```gleam
pub fn hosted_domain(VerifiedIdToken) -> option.Option(String)
```

### `nonce`

Return the verified nonce.

```gleam
pub fn nonce(VerifiedIdToken) -> option.Option(String)
```

### `object_id`

Return Microsoft's verified object identifier claim, when present.

```gleam
pub fn object_id(VerifiedIdToken) -> option.Option(String)
```

### `optional_bool_claim`

Return an optional boolean claim from the verified payload.

```gleam
pub fn optional_bool_claim(
  VerifiedIdToken,
  String
) -> Result(option.Option(Bool), VerificationError)
```

### `optional_string_claim`

Return an optional string claim from the verified payload.

This is useful for provider-specific claims such as Google's `hd` or
Microsoft's `tid`. A present non-string claim is rejected.

```gleam
pub fn optional_string_claim(
  VerifiedIdToken,
  String
) -> Result(option.Option(String), VerificationError)
```

### `parse_jwks`

Parse a JWKS document, retaining only RSA signing keys pinned to RS256.

```gleam
pub fn parse_jwks(String) -> Result(Jwks, VerificationError)
```

### `string_claim`

Return a required string claim from the verified payload.

```gleam
pub fn string_claim(
  VerifiedIdToken,
  String
) -> Result(String, VerificationError)
```

### `subject`

Return the verified subject.

```gleam
pub fn subject(VerifiedIdToken) -> String
```

### `tenant_id`

Return Microsoft's verified tenant identifier claim, when present.

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
