---
title: "vestibule/nonce"
description: "OIDC `nonce` generation and constant-time validation. A fresh 256-bit base64url nonce is minted for every OIDC authorization request, sent as the `nonce` authorize-request parameter, and echoed back by the provider in the signed `id_token`. On callback the value read from the id_token is compared against the stored value to bind the token to this browser session, preventing id_token replay/injection."
nav:
  group: Reference
  groupOrder: 20
  order: 17
  label: "vestibule/nonce"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/nonce
---

# `vestibule/nonce`

OIDC `nonce` generation and constant-time validation. A fresh 256-bit
base64url nonce is minted for every OIDC authorization request, sent as
the `nonce` authorize-request parameter, and echoed back by the provider
in the signed `id_token`. On callback the value read from the id_token is
compared against the stored value to bind the token to this browser
session, preventing id_token replay/injection.

## Functions

### `generate`

Generate a cryptographically random nonce.
Returns 32 bytes of random data, base64url-encoded (no padding).

```gleam
pub fn generate() -> String
```

### `validate`

Validate a received nonce against the expected value.
Uses constant-time comparison to prevent timing attacks.

```gleam
pub fn validate(
  received: String,
  expected: String
) -> Result(Nil, error.AuthError(a))
```
