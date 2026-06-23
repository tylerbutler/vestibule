---
title: "vestibule_apple/jwks"
description: "Apple JWKS (JSON Web Key Set) fetching and caching."
nav:
  group: Reference
  groupOrder: 20
  order: 25
  label: "vestibule_apple/jwks"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_apple/jwks
---

# `vestibule_apple/jwks`

Apple JWKS (JSON Web Key Set) fetching and caching.

Fetches Apple's public keys from `https://appleid.apple.com/auth/keys`
and caches them in a bravo ETS table for reuse. Keys are used to verify
the signature of Apple's ID token JWTs.

## Types

### `JwksCache`

Opaque cache for Apple's JWKS keys.

Backed by a bravo `USet` ETS table, but the underlying storage is hidden
so the dependency can be swapped without breaking consumers.

```gleam
pub type JwksCache
```

### `JwksCacheError`

Errors returned by checked JWKS cache operations.

```gleam
pub type JwksCacheError {
  JwksTableCreateFailed
}
```

## Functions

### `get_keys`

Get Apple's public verification keys, using cached keys if available.
Falls back to fetching from Apple's JWKS endpoint.

```gleam
pub fn get_keys(JwksCache) -> Result(List(verify_key.VerifyKey), error.AuthError(a))
```

### `init`

Initialize the JWKS cache. Call once per VM at application startup.

```gleam
pub fn init() -> JwksCache
```

### `init_named`

Initialize a named JWKS cache. Useful for testing.

```gleam
pub fn init_named(String) -> JwksCache
```

### `parse_jwks`

Parse a JWKS JSON response into a list of verification keys.

```gleam
pub fn parse_jwks(String) -> Result(List(verify_key.VerifyKey), error.AuthError(a))
```

### `refresh_keys`

Force refresh the cached keys from Apple's endpoint.

```gleam
pub fn refresh_keys(JwksCache) -> Result(List(verify_key.VerifyKey), error.AuthError(a))
```

### `try_init`

Try to initialize the JWKS cache.

```gleam
pub fn try_init() -> Result(JwksCache, JwksCacheError)
```

### `try_init_named`

Try to initialize a named JWKS cache. Returns an error if the table already
exists or cannot be created.

```gleam
pub fn try_init_named(String) -> Result(JwksCache, JwksCacheError)
```
