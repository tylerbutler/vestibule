---
title: "vestibule_indieauth/token"
description: "Reference for vestibule_indieauth/token."
nav:
  group: Reference
  groupOrder: 20
  order: 30
  label: "vestibule_indieauth/token"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_indieauth/token
---

# `vestibule_indieauth/token`

Reference for vestibule_indieauth/token.

## Types

### `IndieAuthProfile`

Profile information from an IndieAuth token response.

```gleam
pub type IndieAuthProfile {
  IndieAuthProfile(
    me: String,
    name: option.Option(String),
    url: option.Option(String),
    photo: option.Option(String),
    email: option.Option(String)
  )
}
```

## Functions

### `exchange_code`

Exchange an authorization code for credentials at the token endpoint.

IndieAuth uses public client semantics — no `client_secret` is sent.
The `client_id` is the application's URL.

```gleam
pub fn exchange_code(
  String,
  String,
  String,
  String,
  option.Option(String)
) -> Result(credentials.Credentials, error.AuthError(a))
```

### `fetch_userinfo`

Fetch user info from the IndieAuth userinfo endpoint.

```gleam
pub fn fetch_userinfo(
  String,
  credentials.Credentials
) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `parse_profile_from_token_response`

Parse the `me` and `profile` from an IndieAuth token response.

Exported for testing.

```gleam
pub fn parse_profile_from_token_response(String) -> Result(IndieAuthProfile, error.AuthError(a))
```

### `parse_token_response`

Parse an IndieAuth token response into Credentials.

IndieAuth token responses include:
- `access_token` (required)
- `token_type` (required, typically "Bearer")
- `me` (required, canonical user URL)
- `scope` (required)
- `profile` (optional, object with name/url/photo/email)
- `expires_in` (optional)
- `refresh_token` (optional)

Exported for testing.

```gleam
pub fn parse_token_response(String) -> Result(credentials.Credentials, error.AuthError(a))
```

### `parse_userinfo_response`

Parse a userinfo endpoint response.
Exported for testing.

```gleam
pub fn parse_userinfo_response(String) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `refresh`

Exchange a refresh token for fresh credentials at the token endpoint.

IndieAuth uses public client semantics — no `client_secret` is sent.
The `client_id` is the application's URL.

```gleam
pub fn refresh(
  String,
  String,
  String
) -> Result(credentials.Credentials, error.AuthError(a))
```
