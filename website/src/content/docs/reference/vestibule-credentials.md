---
title: "vestibule/credentials"
description: "Bearer credentials returned by a provider after a successful token exchange or refresh."
nav:
  group: Reference
  groupOrder: 20
  order: 14
  label: "vestibule/credentials"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/credentials
---

# `vestibule/credentials`

Bearer credentials returned by a provider after a successful token
exchange or refresh.

> **Security**: `Credentials` values contain access/refresh/id tokens.
> Treat them like passwords — never log them, never include them in
> error reports, and store them encrypted at rest.

## Types

### `Credentials`

OAuth credentials from the provider.

Opaque so raw access and refresh tokens are not exposed through pattern
matching or casual field access. The access and refresh tokens are wrapped
in `Secret`, so `string.inspect`, Erlang `~p` formatting, logs, and crash
reports redact them even when a caller accidentally renders a `Credentials`
(or an `Auth` containing one) directly. Use `new` to construct credentials
in strategies and accessors to read fields when needed.

```gleam
pub opaque type Credentials
```

## Functions

### `expires_in`

Return the provider-reported lifetime in seconds.

```gleam
pub fn expires_in(Credentials) -> option.Option(Int)
```

### `new`

Construct OAuth credentials from a provider token response.

```gleam
pub fn new(
  token: String,
  refresh_token: option.Option(String),
  token_type: String,
  expires_in: option.Option(Int),
  scopes: List(String)
) -> Credentials
```

### `refresh_token`

Return the refresh token, when the provider supplied one.

```gleam
pub fn refresh_token(Credentials) -> option.Option(String)
```

### `scopes`

Return the scopes granted by the provider.

```gleam
pub fn scopes(Credentials) -> List(String)
```

### `token`

Return the access token.

```gleam
pub fn token(Credentials) -> String
```

### `token_type`

Return the token type, usually `Bearer`.

```gleam
pub fn token_type(Credentials) -> String
```
