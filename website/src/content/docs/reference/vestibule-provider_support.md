---
title: "vestibule/provider_support"
description: "Stable helpers for OAuth provider implementations."
nav:
  group: Reference
  groupOrder: 20
  order: 17
  label: "vestibule/provider_support"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/provider_support
---

# `vestibule/provider_support`

Stable helpers for OAuth provider implementations.

## Types

### `ScopeParsing`

Scope parsing behavior for OAuth token responses.

```gleam
pub type ScopeParsing {
  RequiredScope(separator: String)
  OptionalScope(separator: String)
  NoScope
}
```

## Functions

### `append_query_params`

Append additional query params to a URL.

```gleam
pub fn append_query_params(
  String,
  List(#(String, String))
) -> String
```

### `check_response_status`

Check that an HTTP response has a 2xx status code.
Returns the response body on success, or an HttpError on failure.

```gleam
pub fn check_response_status(response.Response(String)) -> Result(String, error.AuthError(a))
```

### `check_response_status_for_endpoint`

Check that an HTTP response has a 2xx status code, emitting structured log
events with the given provider name and endpoint label.
Returns the response body on success, or an HttpError on failure.

```gleam
pub fn check_response_status_for_endpoint(
  response.Response(String),
  provider_name: String,
  endpoint: String
) -> Result(String, error.AuthError(a))
```

### `check_token_error`

Check a JSON response body for an OAuth2 error response.

If the body contains `{"error": "...", "error_description": "..."}`,
returns `Error(ProviderError(...))`. Otherwise returns `Ok(body)`
so the caller can proceed with success parsing.

This pattern is used by every token endpoint response parser
(GitHub, Google, Microsoft, Apple, OIDC, refresh).

```gleam
pub fn check_token_error(String) -> Result(String, error.AuthError(a))
```

### `fetch_json_with_auth`

Fetch JSON from a URL with Bearer token authentication.

Builds a GET request with Authorization and Accept headers,
checks the response status, and passes the body to the provided
parser function. Used by provider strategies that need to call
a userinfo or similar API endpoint.

```gleam
pub fn fetch_json_with_auth(
  String,
  String,
  fn(String) -> Result(a, error.AuthError(b)),
  String
) -> Result(a, error.AuthError(b))
```

### `parse_oauth_token_response`

Parse a standard OAuth token response JSON into credentials.

Checks for OAuth error responses before parsing success responses.

```gleam
pub fn parse_oauth_token_response(
  String,
  ScopeParsing
) -> Result(credentials.Credentials, error.AuthError(a))
```

### `parse_redirect_uri`

Parse and validate a redirect URI.

Redirect URIs must be valid URLs and use HTTPS, except localhost/127.0.0.1
which are allowed for local development.

```gleam
pub fn parse_redirect_uri(String) -> Result(uri.Uri, error.AuthError(a))
```

### `require_https`

Validate that a URL uses HTTPS.
HTTP is allowed for localhost and 127.0.0.1 (development use).
Returns Ok(Nil) if valid, or a ConfigError describing the issue.

```gleam
pub fn require_https(String) -> Result(Nil, error.AuthError(a))
```

### `require_public_https`

Validate that a URL uses HTTPS *and* targets a publicly-routable host.

Unlike `require_https`, this rejects `http` entirely (no localhost
exception) and also rejects loopback, private, link-local, and other
non-publicly-routable hosts. Use it for values supplied by a provider's
discovery document — such as the OIDC issuer and discovered
token/userinfo endpoints — where an attacker-controlled issuer could
otherwise publish an internal URL and trigger Server-Side Request
Forgery (SSRF) against loopback or internal services.

Returns Ok(Nil) if valid, or a ConfigError describing the issue.

```gleam
pub fn require_public_https(String) -> Result(Nil, error.AuthError(a))
```
