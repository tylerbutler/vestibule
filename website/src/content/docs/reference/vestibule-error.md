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
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/error
---

# `vestibule/error`

Authentication error types.

`AuthError(e)` is an **opaque** error value. Instead of pattern matching on
public variants, classify and inspect errors through the accessor functions
in this module:

- [`kind`](#kind) returns an [`ErrorKind`](#ErrorKind) classifier. It carries
  an `OtherKind` catch-all so future error kinds can be added without breaking
  exhaustive `case` expressions in consuming code.
- [`phase`](#phase) returns the coarse [`Phase`](#Phase) the error occurred in.
- [`message`](#message) returns a human-readable summary, safe to log.
- [`provider_error`](#provider_error) returns structured provider error data
  (code / description / uri) when the provider returned a standard OAuth error.
- [`http_status`](#http_status) and [`missing_param`](#missing_param) expose
  the few additional structured fields some errors carry.
- [`custom`](#custom) returns the provider-defined payload for custom errors.

Construct errors with the constructor functions ([`config`](#config),
[`network`](#network), [`provider`](#provider), and friends). The type
parameter `e` lets third-party providers attach custom error payloads via
[`custom`](#custom); built-in strategies stay polymorphic in `e`.

## Types

### `AuthError`

An opaque authentication error.

Inspect values of this type with [`kind`](#kind), [`phase`](#phase),
[`message`](#message), [`provider_error`](#provider_error),
[`http_status`](#http_status), [`missing_param`](#missing_param), and
[`custom`](#custom).

```gleam
pub type AuthError(a)
```

### `ErrorKind`

A stable, machine-readable error classifier.

`OtherKind` is a catch-all: matching on it keeps consumer `case` expressions
exhaustive even as new kinds are introduced. Always include an `OtherKind`
(or `_`) arm when matching on this type.

```gleam
pub type ErrorKind {
  StateMismatchKind
  InvalidNonceKind
  MissingCallbackParamKind
  CodeExchangeKind
  UserInfoKind
  ProviderKind
  HttpKind
  DecodeKind
  NetworkKind
  ConfigKind
  RefreshUnsupportedKind
  CustomKind
  OtherKind
}
```

#### Constructors

##### `StateMismatchKind`

State parameter mismatch — possible CSRF attack.

##### `InvalidNonceKind`

OIDC `nonce` mismatch or missing-but-expected — possible id_token
replay/injection attack.

##### `MissingCallbackParamKind`

A required OAuth callback parameter was missing.

##### `CodeExchangeKind`

Failed to exchange the authorization code for tokens.

##### `UserInfoKind`

Failed to fetch user info from the provider.

##### `ProviderKind`

The provider returned a standard OAuth error response.

##### `HttpKind`

The provider returned a non-success HTTP response.

##### `DecodeKind`

A provider response body could not be decoded.

##### `NetworkKind`

An HTTP request failed at the network level.

##### `ConfigKind`

Invalid configuration.

##### `RefreshUnsupportedKind`

The strategy does not support refreshing access tokens.

##### `CustomKind`

A provider-specific custom error (see [`custom`](#custom)).

##### `OtherKind`

Catch-all for kinds added in future releases.

### `Phase`

A coarse classification of where in the OAuth flow an error occurred.

```gleam
pub type Phase {
  CallbackPhase
  TokenExchangePhase
  UserInfoPhase
  ConfigPhase
  ProviderPhase
  TransportPhase
  RefreshPhase
}
```

#### Constructors

##### `CallbackPhase`

Validating or parsing the OAuth callback request.

##### `TokenExchangePhase`

Exchanging the authorization code for tokens.

##### `UserInfoPhase`

Fetching user info from the provider.

##### `ConfigPhase`

Reading or validating configuration.

##### `ProviderPhase`

The provider returned an explicit error response.

##### `TransportPhase`

Network / HTTP transport.

##### `RefreshPhase`

Refreshing an access token.

### `ProviderError`

Structured data from a standard OAuth provider error response.

This deliberately excludes raw response bodies; only the standard
`error`, `error_description`, and `error_uri` fields are exposed.

```gleam
pub type ProviderError
```

## Functions

### `code_exchange`

Failed to exchange the authorization code for tokens.

```gleam
pub fn code_exchange(reason: String) -> AuthError(a)
```

### `config`

Invalid configuration.

```gleam
pub fn config(reason: String) -> AuthError(a)
```

### `custom`

A provider-specific custom error carrying a payload of type `e`.

```gleam
pub fn custom(a) -> AuthError(a)
```

### `custom_payload`

The provider-defined custom payload, for `CustomKind` errors.

```gleam
pub fn custom_payload(AuthError(a)) -> option.Option(a)
```

### `decode`

A provider response body could not be decoded.

```gleam
pub fn decode(
  context: String,
  reason: String
) -> AuthError(a)
```

### `http`

The provider returned a non-success HTTP response.

`summary` should be a short, sanitized description — never a raw response
body — so the error is safe to surface and log.

```gleam
pub fn http(
  status: Int,
  summary: String
) -> AuthError(a)
```

### `http_status`

The HTTP status code, for errors that carry one.

```gleam
pub fn http_status(AuthError(a)) -> option.Option(Int)
```

### `http_summary`

The sanitized HTTP error summary, for `HttpKind` errors. Never a raw body.

```gleam
pub fn http_summary(AuthError(a)) -> option.Option(String)
```

### `invalid_nonce`

OIDC `nonce` mismatch or missing-but-expected — possible id_token replay.

```gleam
pub fn invalid_nonce() -> AuthError(a)
```

### `kind`

The machine-readable [`ErrorKind`](#ErrorKind) classifier for this error.

```gleam
pub fn kind(AuthError(a)) -> ErrorKind
```

### `message`

A human-readable, log-safe summary of this error.

```gleam
pub fn message(AuthError(a)) -> String
```

### `missing_callback_param`

A required OAuth callback parameter was missing.

```gleam
pub fn missing_callback_param(String) -> AuthError(a)
```

### `missing_param`

The name of the missing callback parameter, for `MissingCallbackParamKind`.

```gleam
pub fn missing_param(AuthError(a)) -> option.Option(String)
```

### `network`

An HTTP request failed at the network level.

```gleam
pub fn network(reason: String) -> AuthError(a)
```

### `phase`

The coarse [`Phase`](#Phase) this error occurred in.

```gleam
pub fn phase(AuthError(a)) -> Phase
```

### `provider`

The provider returned a standard OAuth error response.

```gleam
pub fn provider(
  code: String,
  description: String,
  uri: option.Option(String)
) -> AuthError(a)
```

### `provider_code`

The standard OAuth `error` code.

```gleam
pub fn provider_code(ProviderError) -> String
```

### `provider_description`

The standard OAuth `error_description`.

```gleam
pub fn provider_description(ProviderError) -> String
```

### `provider_error`

Structured provider error data, when the provider returned a standard OAuth
error response.

```gleam
pub fn provider_error(AuthError(a)) -> option.Option(ProviderError)
```

### `provider_uri`

The standard OAuth `error_uri`, when present.

```gleam
pub fn provider_uri(ProviderError) -> option.Option(String)
```

### `refresh_unsupported`

The strategy does not support refreshing access tokens.

Returned when `strategy.refresh_token` is called on a strategy that was built
without a refresh capability (no `with_refresh`).

```gleam
pub fn refresh_unsupported() -> AuthError(a)
```

### `state_mismatch`

State parameter mismatch — possible CSRF attack.

```gleam
pub fn state_mismatch() -> AuthError(a)
```

### `user_info`

Failed to fetch user info from the provider.

```gleam
pub fn user_info(reason: String) -> AuthError(a)
```
