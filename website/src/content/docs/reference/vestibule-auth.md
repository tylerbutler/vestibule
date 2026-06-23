---
title: "vestibule/auth"
description: "Authentication result types returned to the calling application after a successful OAuth/OIDC flow."
nav:
  group: Reference
  groupOrder: 20
  order: 11
  label: "vestibule/auth"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/auth
---

# `vestibule/auth`

Authentication result types returned to the calling application after a
successful OAuth/OIDC flow.

## Types

### `Auth`

The normalized result of a successful authentication.

Opaque so the field set can grow in future releases without breaking
callers that construct or pattern-match the value. Build instances with
`new` and read fields with the accessors.

```gleam
pub type Auth
```

## Functions

### `credentials`

Return the OAuth credentials (tokens, expiry).

```gleam
pub fn credentials(Auth) -> credentials.Credentials
```

### `extra`

Return the provider-specific extra data.

```gleam
pub fn extra(Auth) -> dict.Dict(String, dynamic.Dynamic)
```

### `info`

Return the normalized user information.

```gleam
pub fn info(Auth) -> user_info.UserInfo
```

### `new`

Construct an authentication result.

```gleam
pub fn new(
  uid: String,
  provider: String,
  info: user_info.UserInfo,
  credentials: credentials.Credentials,
  extra: dict.Dict(String, dynamic.Dynamic)
) -> Auth
```

### `provider`

Return the provider name matching the strategy.

```gleam
pub fn provider(Auth) -> String
```

### `uid`

Return the unique identifier from the provider (e.g., GitHub user ID).

```gleam
pub fn uid(Auth) -> String
```
