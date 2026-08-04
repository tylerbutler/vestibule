---
title: "vestibule_mist"
description: "Mist middleware that wires a `Registry` of `Strategy` values into HTTP endpoints."
nav:
  group: Reference
  groupOrder: 20
  order: 33
  label: "vestibule_mist"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_mist
---

# `vestibule_mist`

Mist middleware that wires a `Registry` of `Strategy` values into HTTP
endpoints.

Provides `request_phase` (start an authorization flow, persist `state`
and `code_verifier`) and `callback_phase` (validate state, exchange
code, fetch user, invoke caller's success handler). Uses the shared
`vestibule/state_store` for single-use storage of in-flight flow state
and an HMAC-SHA256 signed cookie to bind a browser session to a stored
state entry.

Unlike `vestibule_wisp`, mist has no built-in signed cookie helper, so
the secret key base must be supplied via `new_options/1`. There is no
`default_options` — callers must start from `new_options` so the type
system enforces a conscious secret choice.

## Types

### `CallbackError`

Structured errors that can occur during the OAuth callback phase.

```gleam
pub type CallbackError(a) {
  UnknownProvider(provider: String)
  MissingOrInvalidSessionCookie
  SessionUnavailable
  InvalidCallbackParams(reason: CallbackParamsError)
  AuthFailed(error.AuthError(a))
}
```

#### Constructors

##### `UnknownProvider(provider: String)`

The requested provider is not registered.

##### `MissingOrInvalidSessionCookie`

The signed session cookie set during the request phase is missing or
invalid (no cookie present, signature mismatch, wrong secret, tampered
payload).

##### `SessionUnavailable`

The session state was not found, expired, or already used.

##### `InvalidCallbackParams(reason: CallbackParamsError)`

Callback parameters could not be extracted from the request; `reason`
says why.

##### `AuthFailed(error.AuthError(a))`

Provider authentication failed.

### `CallbackParamsError`

Why callback parameters could not be extracted from a POST callback body.

```gleam
pub type CallbackParamsError {
  BodyReadFailed
  BodyNotUtf8
  BodyNotFormEncoded
}
```

#### Constructors

##### `BodyReadFailed`

The request body could not be read (e.g. larger than the 64 KiB limit,
or a transport failure).

##### `BodyNotUtf8`

The request body was not valid UTF-8.

##### `BodyNotFormEncoded`

The request body was not valid form/query encoding.

### `CookieSecurity`

Whether the session cookie is set with the `Secure` attribute.

```gleam
pub type CookieSecurity {
  SecureOnly
  AllowInsecure
}
```

#### Constructors

##### `SecureOnly`

Set `Secure` so the cookie is only sent over HTTPS, and use a host-bound
(`__Host-` prefixed) cookie name. Use in production.

##### `AllowInsecure`

Omit `Secure` so the cookie also works over plain HTTP, e.g. local
development without TLS. The cookie name is not host-bound, since
browsers reject `__Host-` cookies that are not `Secure`.

### `Options`

Middleware configuration options.

Construct with `new_options` — the HMAC `secret_key_base` is mandatory and
has no safe default — then customize with `with_cookie_name`,
`with_session_ttl_seconds`, and `with_cookie_security`. The type is opaque
so the effective cookie name always matches the cookie security: host-bound
(`__Host-` prefixed) under `SecureOnly`, unprefixed under `AllowInsecure`
(browsers reject `__Host-` cookies that are not `Secure`). A host-bound
name prevents a sibling subdomain from overwriting the session cookie with
a `Domain=.example.com` cookie of the same name (cookie tossing / session
fixation). Read the effective name with `cookie_name`.

```gleam
pub type Options
```

## Functions

### `callback_phase`

Phase 2: Handle the OAuth callback and return the `Auth` result to the
provided callback function.

Supports both GET callbacks (query parameters) and POST callbacks
(form-encoded body), as required by providers like Apple that use
`response_mode=form_post`. For POST requests, form body parameters take
precedence over query parameters.

On success, calls `on_success` with the `Auth`. On error, returns a
generic HTML error page. Returns 404 if the provider is not registered.

```gleam
pub fn callback_phase(
  request.Request(http.Connection),
  registry.Registry(a),
  String,
  state_store.StateStore,
  Options,
  fn(auth.Auth) -> response.Response(mist.ResponseData)
) -> response.Response(mist.ResponseData)
```

### `callback_phase_auth_result`

Phase 2 (structured Result variant): Handle the OAuth callback and return
either the `Auth` result or a structured `CallbackError`.

Use this when you want to distinguish provider lookup, session, callback
parameter, and provider authentication failures without parsing responses.

Callback parameters are parsed and state is validated before the stored
session is consumed, so malformed or wrong-state callbacks do not burn a
valid in-flight login.

```gleam
pub fn callback_phase_auth_result(
  request.Request(http.Connection),
  registry: registry.Registry(a),
  provider: String,
  store: state_store.StateStore,
  options: Options
) -> Result(auth.Auth, CallbackError(a))
```

### `callback_phase_auth_result_with_params`

Phase 2 with pre-extracted callback parameters.

Useful when the caller has already read the request body (or otherwise
resolved the form/query parameters) and wants to hand them in directly.
Generic over the request body type so it can be used in unit tests with
`Request(BitArray)` or any other body.

```gleam
pub fn callback_phase_auth_result_with_params(
  request.Request(a),
  params: dict.Dict(String, String),
  registry: registry.Registry(b),
  provider: String,
  store: state_store.StateStore,
  options: Options
) -> Result(auth.Auth, CallbackError(b))
```

### `callback_phase_result`

Phase 2 (Result variant): Handle the OAuth callback and return either the
`Auth` result or an error `Response`.

Use this instead of `callback_phase` when you want to decide how to use the
success value or generated error response yourself.

```gleam
pub fn callback_phase_result(
  request.Request(http.Connection),
  registry: registry.Registry(a),
  provider: String,
  store: state_store.StateStore,
  options: Options
) -> Result(auth.Auth, response.Response(mist.ResponseData))
```

### `cookie_name`

The effective session cookie name: host-bound (`__Host-` prefixed) under
`SecureOnly` cookie security, the unprefixed base name under
`AllowInsecure`.

```gleam
pub fn cookie_name(Options) -> String
```

### `cookie_security`

The cookie security for these options.

```gleam
pub fn cookie_security(Options) -> CookieSecurity
```

### `new_options`

Build middleware options with the given HMAC `secret_key_base`.

Defaults: host-bound cookie name `__Host-vestibule_session`, session TTL
600 seconds, `SecureOnly` cookies. Customize with `with_cookie_name`,
`with_session_ttl_seconds`, and `with_cookie_security`.

```gleam
pub fn new_options(BitArray) -> Options
```

### `request_phase`

Phase 1: Redirect the user to the OAuth provider.

Looks up the provider in the registry, generates an authorization URL with
PKCE parameters, stores the CSRF state and code verifier in `store`, sets
a signed session cookie, and returns a 302 response.

Returns 404 if the provider is not registered, or a generic 400 HTML error
if URL generation or state persistence fails.

Generic over the request body type: the body is never read, only request
metadata (scheme, cookies) is inspected.

```gleam
pub fn request_phase(
  request.Request(a),
  registry: registry.Registry(b),
  provider: String,
  store: state_store.StateStore,
  authorize_options: config.AuthorizeOptions,
  options: Options
) -> response.Response(mist.ResponseData)
```

### `session_ttl_seconds`

The session TTL in seconds for these options.

```gleam
pub fn session_ttl_seconds(Options) -> Int
```

### `with_cookie_name`

Set a custom session cookie name.

The name is stored without any `__Host-` prefix (one is stripped when
present); the prefix is applied automatically under `SecureOnly` cookie
security. See the `Options` docs.

```gleam
pub fn with_cookie_name(
  Options,
  String
) -> Options
```

### `with_cookie_security`

Set whether the session cookie requires HTTPS. See `CookieSecurity`.

```gleam
pub fn with_cookie_security(
  Options,
  CookieSecurity
) -> Options
```

### `with_session_ttl_seconds`

Set how long an in-flight authorization flow (and its session cookie)
stays valid.

```gleam
pub fn with_session_ttl_seconds(
  Options,
  Int
) -> Options
```
