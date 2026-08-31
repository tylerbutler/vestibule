---
title: "vestibule_indieauth/token"
description: "IndieAuth token exchange and response parsing."
nav:
  group: Reference
  groupOrder: 20
  order: 31
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

IndieAuth token exchange and response parsing.

Handles the token exchange step of the IndieAuth flow where
the authorization code is exchanged for an access token and
the user's canonical profile URL.

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

### `build_authorization_code_request`

Build an IndieAuth authorization-code request without sending it.

The returned request is opaque and can only be sent with
`provider_support.send_public`, which performs DNS validation and address
pinning immediately before connecting.

```gleam
pub fn build_authorization_code_request(
  String,
  String,
  String,
  String,
  option.Option(String)
) -> Result(provider_support.SecureRequest, error.AuthError(a))
```

### `build_refresh_token_request`

Build an IndieAuth refresh-token request without sending it.

The returned request is opaque and must be sent with
`provider_support.send_public`.

```gleam
pub fn build_refresh_token_request(
  String,
  String,
  String
) -> Result(provider_support.SecureRequest, error.AuthError(a))
```

### `build_user_info_request`

Build an IndieAuth userinfo request without sending it.

The returned request is opaque and must be sent with
`provider_support.send_public`.

```gleam
pub fn build_user_info_request(
  String,
  credential.Credentials
) -> Result(provider_support.SecureRequest, error.AuthError(a))
```

### `exchange_code`

Exchange an authorization code for credentials at the token endpoint.

IndieAuth uses public client semantics — no `client_secret` is sent.
The `client_id` is the application's URL.

Returns the credentials together with the profile the server asserted
(whose `me` is required). The caller must confirm that `me` before
treating it as the user's identity — see `vestibule_indieauth/profile`.

```gleam
pub fn exchange_code(
  String,
  String,
  String,
  String,
  option.Option(String)
) -> Result(#(credential.Credentials, IndieAuthProfile), error.AuthError(a))
```

### `fetch_userinfo`

Fetch user info from the IndieAuth userinfo endpoint.

```gleam
pub fn fetch_userinfo(
  String,
  credential.Credentials
) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `parse_authorization_code_response`

Parse an IndieAuth authorization-code HTTP response without performing I/O.

```gleam
pub fn parse_authorization_code_response(response.Response(String)) -> Result(#(credential.Credentials, IndieAuthProfile), error.AuthError(a))
```

### `parse_profile_from_token_response`

Parse the `me` and `profile` from an IndieAuth token response.

Exported for testing.

```gleam
pub fn parse_profile_from_token_response(String) -> Result(IndieAuthProfile, error.AuthError(a))
```

### `parse_refresh_token_response`

Parse an IndieAuth refresh-token HTTP response without performing I/O.

```gleam
pub fn parse_refresh_token_response(response.Response(String)) -> Result(credential.Credentials, error.AuthError(a))
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
pub fn parse_token_response(String) -> Result(credential.Credentials, error.AuthError(a))
```

### `parse_user_info_response`

Parse an IndieAuth userinfo HTTP response without performing I/O.

```gleam
pub fn parse_user_info_response(response.Response(String)) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
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
) -> Result(credential.Credentials, error.AuthError(a))
```
