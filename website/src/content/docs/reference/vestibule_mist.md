---
title: "vestibule_mist"
description: "Mist middleware that wires a `Registry` of `Strategy` values into HTTP endpoints."
nav:
  group: Reference
  groupOrder: 20
  order: 34
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
`default_options` — callers must construct `Options` explicitly so the
type system enforces a conscious secret choice.

## Types

### `CallbackError`

Structured errors that can occur during the OAuth callback phase.

```gleam
pub type CallbackError(a) {
  UnknownProvider(provider: String)
  MissingOrInvalidSessionCookie
  SessionUnavailable
  InvalidCallbackParams
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

##### `InvalidCallbackParams`

Callback parameters could not be extracted from the request (e.g.
malformed POST body, body too large, non-UTF-8 body).

##### `AuthFailed(error.AuthError(a))`

Provider authentication failed.

### `Options`

Middleware configuration options.

Construct with `new_options/1`. There is no `default_options` because the
HMAC `secret_key_base` is mandatory and has no safe default.

```gleam
pub type Options {
  Options(
    secret_key_base: BitArray,
    cookie_name: String,
    session_ttl_seconds: Int,
    secure_cookie: Bool
  )
}
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
  reg: registry.Registry(a),
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
  reg: registry.Registry(b),
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
  reg: registry.Registry(a),
  provider: String,
  store: state_store.StateStore,
  options: Options
) -> Result(auth.Auth, response.Response(mist.ResponseData))
```

### `new_options`

Build middleware options with the given HMAC `secret_key_base`.

Defaults: cookie name `vestibule_session`, session TTL 600 seconds. Update
fields directly to customize (`Options(..options, session_ttl_seconds: 300)`).

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
  registry.Registry(b),
  String,
  state_store.StateStore,
  authorize_options: config.AuthorizeOptions,
  Options
) -> response.Response(mist.ResponseData)
```
