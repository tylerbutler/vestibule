---
title: "vestibule_apple/jwks"
description: "Apple JWKS (JSON Web Key Set) fetching and caching."
nav:
  group: Reference
  groupOrder: 20
  order: 24
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
  JwksTableCreationFailed(reason: String)
}
```

#### Constructors

##### `JwksTableCreationFailed(reason: String)`

The ETS table backing the cache could not be created (for example
because it already exists). `reason` describes the underlying storage
error to aid debugging.

## Functions

### `build_jwks_request`

Build the request for Apple's JWKS endpoint without sending it.

```gleam
pub fn build_jwks_request() -> Result(request.Request(String), error.AuthError(a))
```

### `get_keys`

Get Apple's public verification keys, using cached keys if available.
Falls back to fetching from Apple's JWKS endpoint.

```gleam
pub fn get_keys(JwksCache) -> Result(List(verify_key.VerifyKey), error.AuthError(a))
```

### `initialize`

Initialize the JWKS cache. Call once per VM at application startup.

```gleam
pub fn initialize() -> Result(JwksCache, JwksCacheError)
```

### `initialize_named`

Initialize a named JWKS cache. Returns an error if the table already
exists or cannot be created.

```gleam
pub fn initialize_named(String) -> Result(JwksCache, JwksCacheError)
```

### `parse_jwks`

Parse a JWKS JSON response into a list of verification keys.

```gleam
pub fn parse_jwks(String) -> Result(List(verify_key.VerifyKey), error.AuthError(a))
```

### `parse_jwks_response`

Parse an Apple JWKS HTTP response without performing I/O.

```gleam
pub fn parse_jwks_response(response.Response(String)) -> Result(List(verify_key.VerifyKey), error.AuthError(a))
```

### `refresh_keys`

Force refresh the cached keys from Apple's endpoint.

```gleam
pub fn refresh_keys(JwksCache) -> Result(List(verify_key.VerifyKey), error.AuthError(a))
```
