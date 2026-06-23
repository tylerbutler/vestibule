---
title: "vestibule/error"
description: "Authentication error types."
nav:
  group: Reference
  groupOrder: 20
  order: 15
  label: "vestibule/error"
toc:
  - href: "#types"
    label: "Types"
searchTerms:
  - api
  - reference
  - module
  - vestibule/error
---

# `vestibule/error`

Authentication error types.

The type parameter `e` allows third-party providers to define custom
error variants via the `Custom(e)` constructor. Built-in strategies
that only use standard variants are polymorphic in `e`.

## Types

### `AuthError`

```gleam
pub type AuthError(a) {
  StateMismatch
  InvalidNonce
  MissingCallbackParam(name: String)
  CodeExchangeFailed(reason: String)
  UserInfoFailed(reason: String)
  ProviderError(
    code: String,
    description: String,
    uri: option.Option(String)
  )
  HttpError(
    status: Int,
    body: String
  )
  DecodeError(
    context: String,
    reason: String
  )
  NetworkError(reason: String)
  ConfigError(reason: String)
  RefreshUnsupported
  Custom(a)
}
```

#### Constructors

##### `StateMismatch`

State parameter mismatch — possible CSRF attack.

##### `InvalidNonce`

OIDC `nonce` mismatch or missing-but-expected — possible id_token
replay/injection attack.

##### `MissingCallbackParam(name: String)`

Required OAuth callback parameter was missing.

##### `CodeExchangeFailed(reason: String)`

Failed to exchange authorization code for tokens.

##### `UserInfoFailed(reason: String)`

Failed to fetch user info from provider.

##### `ProviderError(
  code: String,
  description: String,
  uri: option.Option(String)
)`

Provider returned an error response.

##### `HttpError(
  status: Int,
  body: String
)`

Provider returned a non-success HTTP response.

##### `DecodeError(
  context: String,
  reason: String
)`

Provider response body could not be decoded.

##### `NetworkError(reason: String)`

HTTP request failed.

##### `ConfigError(reason: String)`

Invalid configuration.

##### `RefreshUnsupported`

The strategy does not support refreshing access tokens.

Returned when `strategy.refresh_token` is called on a strategy that was
built without a refresh capability (no `with_refresh`).

##### `Custom(a)`

Provider-specific custom error.
