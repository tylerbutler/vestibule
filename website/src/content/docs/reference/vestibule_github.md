---
title: "vestibule_github"
description: "Reference for vestibule_github."
nav:
  group: Reference
  groupOrder: 20
  order: 26
  label: "vestibule_github"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_github
---

# `vestibule_github`

Reference for vestibule_github.

## Functions

### `build_authorization_code_request`

Build GitHub's authorization-code token request without sending it.

```gleam
pub fn build_authorization_code_request(
  config.ClientConfig,
  String,
  option.Option(String)
) -> Result(request.Request(String), error.AuthError(a))
```

### `build_refresh_token_request`

Build GitHub's refresh-token request without sending it.

```gleam
pub fn build_refresh_token_request(
  config.ClientConfig,
  String
) -> Result(request.Request(String), error.AuthError(a))
```

### `build_user_email_request`

Build GitHub's `/user/emails` request without sending it.

```gleam
pub fn build_user_email_request(credential.Credentials) -> Result(request.Request(String), error.AuthError(a))
```

### `build_user_info_request`

Build GitHub's `/user` request without sending it.

```gleam
pub fn build_user_info_request(credential.Credentials) -> Result(request.Request(String), error.AuthError(a))
```

### `parse_authorization_code_response`

Parse GitHub's authorization-code HTTP response without performing I/O.

```gleam
pub fn parse_authorization_code_response(response.Response(String)) -> Result(strategy.ExchangeResult, error.AuthError(a))
```

### `parse_primary_email`

Parse the primary verified email from GitHub /user/emails response.
Supported parsing helper for GitHub strategy integrations.

Returns `Ok(None)` when no primary verified email exists, and an error
when the response body cannot be parsed.

```gleam
pub fn parse_primary_email(String) -> Result(option.Option(String), error.AuthError(a))
```

### `parse_refresh_token_response`

Parse GitHub's refresh-token HTTP response without performing I/O.

```gleam
pub fn parse_refresh_token_response(response.Response(String)) -> Result(credential.Credentials, error.AuthError(a))
```

### `parse_token_response`

Parse a GitHub token exchange response into Credentials.
Supported parsing helper for GitHub strategy integrations.

```gleam
pub fn parse_token_response(String) -> Result(credential.Credentials, error.AuthError(a))
```

### `parse_user_email_response`

Parse GitHub's `/user/emails` HTTP response without performing I/O.

```gleam
pub fn parse_user_email_response(response.Response(String)) -> Result(option.Option(String), error.AuthError(a))
```

### `parse_user_info_response`

Parse GitHub's `/user` HTTP response without performing I/O.

```gleam
pub fn parse_user_info_response(response.Response(String)) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `parse_user_response`

Parse a GitHub /user API response into a user ID and UserInfo.
Supported parsing helper for GitHub strategy integrations.

```gleam
pub fn parse_user_response(String) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `strategy`

Create a GitHub authentication strategy.

```gleam
pub fn strategy() -> strategy.Strategy(a)
```
