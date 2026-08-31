---
title: "vestibule_google"
description: "Google OAuth 2.0 / OIDC strategy."
nav:
  group: Reference
  groupOrder: 20
  order: 27
  label: "vestibule_google"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_google
---

# `vestibule_google`

Google OAuth 2.0 / OIDC strategy.

Uses Google's discovery document to build authorize/token/userinfo
endpoints, requests `openid email profile` by default, and validates
`email_verified` before populating the user's email (`user_info.email`).

## Functions

### `build_authorization_code_request`

Build Google's authorization-code token request without sending it.

```gleam
pub fn build_authorization_code_request(
  config.ClientConfig,
  String,
  option.Option(String)
) -> Result(request.Request(String), error.AuthError(a))
```

### `build_refresh_token_request`

Build Google's refresh-token request without sending it.

```gleam
pub fn build_refresh_token_request(
  config.ClientConfig,
  String
) -> Result(request.Request(String), error.AuthError(a))
```

### `build_user_info_request`

Build Google's userinfo request without sending it.

```gleam
pub fn build_user_info_request(credential.Credentials) -> Result(request.Request(String), error.AuthError(a))
```

### `parse_authorization_code_response`

Parse Google's authorization-code HTTP response without performing I/O.

```gleam
pub fn parse_authorization_code_response(response.Response(String)) -> Result(strategy.ExchangeResult, error.AuthError(a))
```

### `parse_refresh_token_response`

Parse Google's refresh-token HTTP response without performing I/O.

```gleam
pub fn parse_refresh_token_response(response.Response(String)) -> Result(credential.Credentials, error.AuthError(a))
```

### `parse_token_response`

Parse Google token response JSON.

```gleam
pub fn parse_token_response(String) -> Result(credential.Credentials, error.AuthError(a))
```

### `parse_user_info_response`

Parse Google's userinfo HTTP response without performing I/O.

```gleam
pub fn parse_user_info_response(response.Response(String)) -> Result(#(String, user_info.UserInfo, option.Option(String)), error.AuthError(a))
```

### `parse_user_response`

Parse Google /oauth2/v3/userinfo response JSON.

```gleam
pub fn parse_user_response(String) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `parse_user_response_with_hosted_domain`

Parse Google userinfo JSON, also extracting the optional `hd`
(hosted-domain) claim used for Workspace domain enforcement.

The third tuple element is the raw `hd` claim, or `None` when the account
is a consumer (gmail.com) account or Google omits the claim.

```gleam
pub fn parse_user_response_with_hosted_domain(String) -> Result(#(String, user_info.UserInfo, option.Option(String)), error.AuthError(a))
```

### `strategy`

Create a Google authentication strategy.

This strategy does not enforce a Google Workspace hosted domain. If the
userinfo response includes an `hd` claim it is surfaced under the `"hd"`
key of `UserResult`'s `extra` dict, but no domain restriction is applied.
To restrict sign-in to a single Workspace domain, use
`strategy_for_hosted_domain`.

```gleam
pub fn strategy() -> strategy.Strategy(a)
```

### `strategy_for_hosted_domain`

Create a Google strategy that enforces a Workspace hosted domain.

Authentication fails unless Google's userinfo response carries an `hd`
(hosted-domain) claim exactly matching `hosted_domain`. A missing or
mismatched `hd` yields `error.user_info`. The validated domain is
surfaced under the `"hd"` key of `UserResult`'s `extra` dict.

`hosted_domain` is also added to the authorization URL as an account-picker
hint, but that hint is advisory only — enforcement happens server-side when
the userinfo response is validated. Setting `hd` via
`config.authorize_options() |> config.with_extra_params([#("hd", ...)])` is purely a UI hint and must not
be relied on for authorization.

```gleam
pub fn strategy_for_hosted_domain(String) -> strategy.Strategy(a)
```

### `validate_hosted_domain`

Validate the returned hosted-domain claim against the required domain.

When `required` is `None` the returned claim (if any) passes through
unchanged. When a domain is required, the claim must be present and match
exactly, otherwise authentication fails with `error.user_info`. This
is the enforcement primitive behind `strategy_for_hosted_domain`.

```gleam
pub fn validate_hosted_domain(
  required: option.Option(String),
  returned: option.Option(String)
) -> Result(option.Option(String), error.AuthError(a))
```
