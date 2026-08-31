---
title: "vestibule/provider_support"
description: "Stable helpers for OAuth provider implementations."
nav:
  group: Reference
  groupOrder: 20
  order: 18
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

### `SecureRequest`

An opaque HTTP request for an untrusted, dynamically selected destination.

The wrapped `gleam_http` request cannot be extracted or sent with an
arbitrary HTTP client. It can only be passed to `send_public`, which
validates every DNS answer, pins the selected address, preserves the
original HTTPS hostname for SNI and `Host`, and disables redirects.

```gleam
pub type SecureRequest
```

### `SecureResponseLimit`

A bounded response class for a request sent through the secure transport.

Each class maps to a fixed conservative cap. Callers cannot provide an
arbitrary byte count:
- `ProfileHtmlResponse`: 1 MiB
- `DiscoveryResponse`: 256 KiB (including JWKS documents)
- `TokenResponse`: 64 KiB
- `UserInfoResponse`: 256 KiB

```gleam
pub type SecureResponseLimit {
  ProfileHtmlResponse
  DiscoveryResponse
  TokenResponse
  UserInfoResponse
}
```

## Functions

### `append_query_params`

Append additional query parameters to a URL.

```gleam
pub fn append_query_params(
  String,
  List(#(String, String))
) -> String
```

### `build_json_request_with_auth`

Build a JSON GET request with an Authorization header.

The URL is validated before the request is returned. This function performs
no network I/O; send the request with any HTTP client and pass its response
to `parse_json_response`.

```gleam
pub fn build_json_request_with_auth(
  String,
  String,
  String
) -> Result(request.Request(String), error.AuthError(a))
```

### `check_response_status`

Check that an HTTP response has a 2xx status code.
Returns the response body on success, or an AuthError of kind `HttpKind` on
failure. The error's summary carries the first 120 characters of the
response body, so it may contain provider response content.

```gleam
pub fn check_response_status(response.Response(String)) -> Result(String, error.AuthError(a))
```

### `check_response_status_for_endpoint`

Check that an HTTP response has a 2xx status code, emitting structured log
events with the given provider name and endpoint label.
Returns the response body on success, or an AuthError of kind `HttpKind` on
failure.

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
returns an AuthError of kind `ProviderKind`. Otherwise returns `Ok(body)` so
the caller can proceed with success parsing.

This pattern is used by every token endpoint response parser
(GitHub, Google, Microsoft, Apple, OIDC, refresh).

```gleam
pub fn check_token_error(String) -> Result(String, error.AuthError(a))
```

### `fetch_json_with_auth`

Fetch JSON from a URL with Authorization authentication.

This convenience wrapper uses Vestibule’s public-destination transport. To
supply a different HTTP client, build the request with
`build_json_request_with_auth`, send it, and parse the response with
`parse_json_response`.

```gleam
pub fn fetch_json_with_auth(
  String,
  String,
  fn(String) -> Result(a, error.AuthError(b)),
  String
) -> Result(a, error.AuthError(b))
```

### `parse_json_response`

Parse a JSON HTTP response after it has been sent by the caller.

Checks the HTTP status and passes the successful response body to `parse`.
This function performs no network I/O.

```gleam
pub fn parse_json_response(
  response.Response(String),
  fn(String) -> Result(a, error.AuthError(b))
) -> Result(a, error.AuthError(b))
```

### `parse_oauth_token_response`

Parse a standard OAuth token response JSON into credentials.

Checks for OAuth error responses before parsing success responses.

```gleam
pub fn parse_oauth_token_response(
  String,
  ScopeParsing
) -> Result(credential.Credentials, error.AuthError(a))
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
Returns Ok(Nil) if valid, or an AuthError of kind `ConfigKind` describing
the issue.

```gleam
pub fn require_https(String) -> Result(Nil, error.AuthError(a))
```

### `require_public_host`

Validate that a URL targets a publicly-routable host, whatever its scheme.

This is the host half of `require_public_https`, for URLs that are fetched
server-side but where plain `http` is legitimately allowed — for example
an IndieAuth profile URL supplied by the person logging in. Loopback,
private, link-local, shared (CGNAT), multicast, and reserved IPv4/IPv6
literals are rejected, as are `localhost`, `*.localhost`, and `*.local`
names. DNS names are resolved and rejected if any returned IPv4 or IPv6
address is not globally routable. Alternate numeric spellings accepted by
Erlang's resolver (`127.1`, `2130706433`, `0177.0.0.1`) and IPv4 embedded
in IPv6 are classified after parsing, rather than by textual prefix.

Returns Ok(Nil) if valid, or an AuthError of kind `ConfigKind` describing
the issue.

```gleam
pub fn require_public_host(String) -> Result(Nil, error.AuthError(a))
```

### `require_public_host_format`

Validate a server-side URL's literal host without performing DNS
resolution. See `require_public_https_format`.

```gleam
pub fn require_public_host_format(String) -> Result(Nil, error.AuthError(a))
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

Returns Ok(Nil) if valid, or an AuthError of kind `ConfigKind` describing
the issue.

```gleam
pub fn require_public_https(String) -> Result(Nil, error.AuthError(a))
```

### `require_public_https_format`

Validate the scheme and literal host of a server-side HTTPS URL without
performing DNS resolution.

This exists for sans-I/O request builders and parsers. Any request accepted
here must be sent with `send_public`, which performs the authoritative DNS
validation and address pinning immediately before connecting.

```gleam
pub fn require_public_https_format(String) -> Result(Nil, error.AuthError(a))
```

### `secure_request`

Wrap an HTTPS request to an untrusted dynamic destination.

This performs the format-only checks that are safe in a sans-I/O builder.
DNS validation is deliberately deferred until `send_public`, immediately
before the connection is made. The default 256 KiB discovery cap is
conservative; endpoint builders should use `secure_request_with_limit`.

```gleam
pub fn secure_request(request.Request(String)) -> Result(SecureRequest, error.AuthError(a))
```

### `secure_request_body`

Return the body of an opaque secure request for deterministic testing.

```gleam
pub fn secure_request_body(SecureRequest) -> String
```

### `secure_request_header`

Read a header from an opaque secure request for deterministic testing.

```gleam
pub fn secure_request_header(
  SecureRequest,
  String
) -> Result(String, Nil)
```

### `secure_request_method`

Return the method of an opaque secure request for deterministic testing.

```gleam
pub fn secure_request_method(SecureRequest) -> http.Method
```

### `secure_request_response_limit`

Return the response limit class of an opaque request for testing.

```gleam
pub fn secure_request_response_limit(SecureRequest) -> SecureResponseLimit
```

### `secure_request_uri`

Return the URI of an opaque secure request for deterministic testing.

This does not expose the underlying sendable `gleam_http` request.

```gleam
pub fn secure_request_uri(SecureRequest) -> uri.Uri
```

### `secure_request_with_limit`

Wrap an HTTPS request with an endpoint-appropriate response body cap.

The cap is enforced while bytes are read, for both fixed-length and chunked
responses. Oversized responses are aborted before their bodies can be
buffered in full.

```gleam
pub fn secure_request_with_limit(
  request.Request(String),
  SecureResponseLimit
) -> Result(SecureRequest, error.AuthError(a))
```

### `send_public`

Send an opaque request only to a globally-routable destination.

The hostname is resolved once, every returned address is checked, and the
selected validated address is placed directly in the connection URL. HTTPS
requests retain the original hostname in both SNI/certificate verification
and the Host header. Redirects are disabled so every subsequent URL must be
independently validated and pinned. The response body is counted while it
is read and the connection is closed immediately if the request's fixed
endpoint cap is exceeded.

```gleam
pub fn send_public(SecureRequest) -> Result(response.Response(String), error.AuthError(a))
```
