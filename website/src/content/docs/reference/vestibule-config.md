---
title: "vestibule/config"
description: "OAuth client configuration and per-authorization request options."
nav:
  group: Reference
  groupOrder: 20
  order: 13
  label: "vestibule/config"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/config
---

# `vestibule/config`

OAuth client configuration and per-authorization request options.

## Types

### `AuthorizeOptions`

Per-authorization request options.

```gleam
pub type AuthorizeOptions
```

### `ClientAuth`

OAuth client authentication method.

Opaque so client credentials cannot appear in inspected configuration or
registry terms. Construct values with `public_client`,
`client_secret_auth`, or `client_assertion_auth`.

```gleam
pub type ClientAuth
```

### `ClientAuthKind`

The non-sensitive kind of client authentication.

```gleam
pub type ClientAuthKind {
  PublicClientAuth
  ClientSecretAuth
  ClientAssertionAuth
}
```

### `ClientConfig`

Durable OAuth client configuration.

```gleam
pub type ClientConfig
```

### `ValidationError`

An actionable client-configuration validation error.

```gleam
pub type ValidationError {
  ValidationError(
    field: String,
    reason: String
  )
}
```

## Functions

### `authorize_options`

Create empty per-authorization request options.

```gleam
pub fn authorize_options() -> AuthorizeOptions
```

### `client_assertion`

Return a client assertion when the authentication method provides one.

Call this only while constructing the token endpoint request.

```gleam
pub fn client_assertion(ClientConfig) -> Result(String, error.AuthError(a))
```

### `client_assertion_auth`

Configure client-assertion authentication.

```gleam
pub fn client_assertion_auth(String) -> ClientAuth
```

### `client_auth`

Return the configured OAuth client authentication method.

```gleam
pub fn client_auth(ClientConfig) -> ClientAuth
```

### `client_auth_kind`

Return the configured client authentication kind without exposing its
credential.

```gleam
pub fn client_auth_kind(ClientAuth) -> ClientAuthKind
```

### `client_id`

Return the configured OAuth client ID.

```gleam
pub fn client_id(ClientConfig) -> String
```

### `client_secret`

Return a client secret value when the authentication method provides one.

Call this only while constructing the token endpoint request.

```gleam
pub fn client_secret(ClientConfig) -> Result(String, error.AuthError(a))
```

### `client_secret_auth`

Configure client-secret authentication.

```gleam
pub fn client_secret_auth(String) -> ClientAuth
```

### `extra_parameters`

Return configured extra authorization query parameters.

```gleam
pub fn extra_parameters(AuthorizeOptions) -> dict.Dict(String, String)
```

### `new`

Create durable client configuration without validating it.

This function remains infallible for compatibility. New applications should
use `try_new`, and existing applications can validate all registrations at
startup with `registry.validate`.

```gleam
pub fn new(
  client_id: String,
  redirect_uri: String,
  auth: ClientAuth
) -> ClientConfig
```

### `public_client`

Configure a public client that has no client credential.

```gleam
pub fn public_client() -> ClientAuth
```

### `redirect_uri`

Return the redirect URI registered with the provider.

```gleam
pub fn redirect_uri(ClientConfig) -> String
```

### `require_auth_kind`

Return a provider-specific authentication-method error when incompatible.

```gleam
pub fn require_auth_kind(
  ClientConfig,
  List(ClientAuthKind),
  String
) -> Result(Nil, List(ValidationError))
```

### `scopes`

Return configured per-request scopes.

```gleam
pub fn scopes(AuthorizeOptions) -> List(String)
```

### `try_new`

Create durable client configuration after validating local requirements.

This performs no network requests. Provider-specific compatibility is
checked by `strategy.validate_config` or, for all registrations at once,
`registry.validate`.

```gleam
pub fn try_new(
  client_id: String,
  redirect_uri: String,
  auth: ClientAuth
) -> Result(ClientConfig, List(ValidationError))
```

### `validate`

Validate provider-independent client configuration without network access.

```gleam
pub fn validate(ClientConfig) -> Result(Nil, List(ValidationError))
```

### `validate_redirect_uri`

Validate a redirect URI without performing network access.

HTTPS is required except for `http://localhost` and
`http://127.0.0.1`, which remain supported for local demos.

```gleam
pub fn validate_redirect_uri(String) -> Result(Nil, ValidationError)
```

### `validation_error_field`

Return the field associated with a validation error.

```gleam
pub fn validation_error_field(ValidationError) -> String
```

### `validation_error_reason`

Return the actionable reason associated with a validation error.

```gleam
pub fn validation_error_reason(ValidationError) -> String
```

### `with_extra_parameters`

Add extra query parameters to an authorization request, merging them into
any previously added parameters. Later values win on duplicate keys.

Reserved OAuth authorization parameters are rejected so callers cannot
override values generated by Vestibule or provider strategies.

```gleam
pub fn with_extra_parameters(
  AuthorizeOptions,
  List(#(String, String))
) -> Result(AuthorizeOptions, error.AuthError(a))
```

### `with_scopes`

Set custom scopes for an authorization request, replacing any defaults.

```gleam
pub fn with_scopes(
  AuthorizeOptions,
  List(String)
) -> AuthorizeOptions
```
