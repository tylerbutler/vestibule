---
title: "vestibule_mist/signed_cookie"
description: "HMAC-SHA256 signed cookie payload helpers."
nav:
  group: Reference
  groupOrder: 20
  order: 34
  label: "vestibule_mist/signed_cookie"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_mist/signed_cookie
---

# `vestibule_mist/signed_cookie`

HMAC-SHA256 signed cookie payload helpers.

Thin wrapper over `gleam_crypto`'s `sign_message`/`verify_signed_message`
to standardize the signing algorithm and produce a String token suitable
for use as a cookie value.

## Functions

### `sign`

Sign `payload` with `secret_key_base` using HMAC-SHA256 and return a
URL-safe token (`protected.payload.signature`) suitable for use as a
cookie value.

```gleam
pub fn sign(
  payload: String,
  secret_key_base: BitArray
) -> String
```

### `verify`

Verify a token previously produced by `sign/2`. Returns the original
payload string, or `Error(Nil)` if the token is malformed, the
signature does not match, or the payload is not valid UTF-8.

```gleam
pub fn verify(
  token: String,
  secret_key_base: BitArray
) -> Result(String, Nil)
```
