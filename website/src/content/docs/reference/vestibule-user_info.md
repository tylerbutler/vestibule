---
title: "vestibule/user_info"
description: "Normalized user profile returned by a provider's userinfo endpoint or extracted from an ID token. Provider-specific fields land in `extra`."
nav:
  group: Reference
  groupOrder: 20
  order: 23
  label: "vestibule/user_info"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/user_info
---

# `vestibule/user_info`

Normalized user profile returned by a provider's userinfo endpoint or
extracted from an ID token. Provider-specific fields land in `extra`.

## Types

### `UserInfo`

Normalized user information across all providers.

Opaque so the field set can grow in future releases without breaking
callers that construct or pattern-match the value. Build instances with
`new` plus the `with_*` helpers, and read fields with the accessors.

```gleam
pub opaque type UserInfo
```

## Functions

### `description`

Return the profile description, when the provider supplied one.

```gleam
pub fn description(UserInfo) -> option.Option(String)
```

### `email`

Return the verified email address, when one is available.

```gleam
pub fn email(UserInfo) -> option.Option(String)
```

### `image`

Return the avatar image URL, when the provider supplied one.

```gleam
pub fn image(UserInfo) -> option.Option(String)
```

### `name`

Return the display name, when the provider supplied one.

```gleam
pub fn name(UserInfo) -> option.Option(String)
```

### `new`

Construct empty user information. Add fields with the `with_*` helpers.

```gleam
pub fn new() -> UserInfo
```

### `nickname`

Return the nickname or handle, when the provider supplied one.

```gleam
pub fn nickname(UserInfo) -> option.Option(String)
```

### `urls`

Return the map of named profile URLs.

```gleam
pub fn urls(UserInfo) -> dict.Dict(String, String)
```

### `with_description`

Set the profile description or bio.

```gleam
pub fn with_description(
  UserInfo,
  option.Option(String)
) -> UserInfo
```

### `with_email`

Set the verified email address.

Strategies should only set this when the provider has verified the
address; otherwise leave it unset.

```gleam
pub fn with_email(
  UserInfo,
  option.Option(String)
) -> UserInfo
```

### `with_image`

Set the avatar image URL.

```gleam
pub fn with_image(
  UserInfo,
  option.Option(String)
) -> UserInfo
```

### `with_name`

Set the display name.

```gleam
pub fn with_name(
  UserInfo,
  option.Option(String)
) -> UserInfo
```

### `with_nickname`

Set the nickname or handle.

```gleam
pub fn with_nickname(
  UserInfo,
  option.Option(String)
) -> UserInfo
```

### `with_urls`

Set the map of named profile URLs.

```gleam
pub fn with_urls(
  UserInfo,
  dict.Dict(String, String)
) -> UserInfo
```
