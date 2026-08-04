---
title: "vestibule_wisp"
description: "Wisp middleware that wires a `Registry` of `Strategy` values into HTTP endpoints."
nav:
  group: Reference
  groupOrder: 20
  order: 36
  label: "vestibule_wisp"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_wisp
---

# `vestibule_wisp`

Wisp middleware that wires a `Registry` of `Strategy` values into HTTP
endpoints.

Provides `request_phase` (start an authorization flow, persist `state`
and `code_verifier`) and `callback_phase` (validate state, exchange
code, fetch user, invoke caller's success handler). Uses a `StateStore`
for single-use storage of in-flight flow state.

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
invalid (no cookie present, signature mismatch, tampered payload).

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

The request body could not be read.

##### `BodyNotUtf8`

The request body was not valid UTF-8.

##### `BodyNotFormEncoded`

The request body was not valid form/query encoding.

### `Options`

Middleware configuration options.

Construct with `default_options` and customize with `with_cookie_name`
and `with_session_ttl_seconds`. The type is opaque so the session cookie
name is always host-bound (`__Host-` prefixed): a non-host-bound name such
as `vestibule_session` can be overwritten by a sibling subdomain setting a
`Domain=.example.com` cookie of the same name, which lets an attacker plant
their own in-flight flow state and fixate the victim's session — especially
dangerous in account-linking flows. Read the effective name with
`cookie_name`.

```gleam
pub type Options
```

## Functions

### `callback_phase`

Phase 2: Handle the OAuth callback and return the Auth result
to the provided callback function.

Supports both GET callbacks (query parameters) and POST callbacks
(form-encoded body), as required by providers like Apple that use
`response_mode=form_post`. For POST requests, form body parameters
take precedence over query parameters.

On success, calls `on_success` with the Auth result.
On error, returns an HTML error page.
Returns 404 if the provider is not registered.

```gleam
pub fn callback_phase(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  on_success: fn(auth.Auth) -> response.Response(wisp.Body)
) -> response.Response(wisp.Body)
```

### `callback_phase_auth_result`

Phase 2 (structured Result variant): Handle the OAuth callback and return
either the Auth result or a structured callback error.

Use this when you want to distinguish provider lookup, session, callback
parameter, and provider authentication failures without parsing responses.

```gleam
pub fn callback_phase_auth_result(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore
) -> Result(auth.Auth, CallbackError(a))
```

### `callback_phase_auth_result_with_options`

Phase 2 (structured Result variant): Handle the OAuth callback using custom
middleware options.

Callback parameters are parsed and state is validated before the stored
session is consumed, so malformed or wrong-state callbacks do not burn a
valid in-flight login.

```gleam
pub fn callback_phase_auth_result_with_options(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  options: Options
) -> Result(auth.Auth, CallbackError(a))
```

### `callback_phase_result`

Phase 2 (Result variant): Handle the OAuth callback and return
either the Auth result or an error Response.

Supports both GET callbacks (query parameters) and POST callbacks
(form-encoded body). See `callback_phase` for details.

Use this instead of `callback_phase` when you want to decide how to use the
success value or generated error response yourself.

```gleam
pub fn callback_phase_result(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore
) -> Result(auth.Auth, response.Response(wisp.Body))
```

### `callback_phase_result_with_options`

Phase 2 (Result variant): Handle the OAuth callback using custom middleware
options.

```gleam
pub fn callback_phase_result_with_options(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  options: Options
) -> Result(auth.Auth, response.Response(wisp.Body))
```

### `callback_phase_with_options`

Phase 2: Handle the OAuth callback using custom middleware options.

```gleam
pub fn callback_phase_with_options(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  on_success: fn(auth.Auth) -> response.Response(wisp.Body),
  options: Options
) -> response.Response(wisp.Body)
```

### `cookie_name`

The effective (host-bound) session cookie name for these options.

```gleam
pub fn cookie_name(Options) -> String
```

### `default_options`

Default middleware options.

Uses the host-bound `__Host-vestibule_session` signed cookie with a
600-second session TTL. The `__Host-` prefix makes browsers reject the
cookie unless it is set with `Secure`, `Path=/`, and no `Domain` attribute,
which prevents a sibling subdomain from tossing/fixating the OAuth session
(see the `Options` docs). `wisp.set_cookie` already sets `Secure` (over
HTTPS), `Path=/`, and no `Domain`, so this cookie meets the `__Host-`
requirements.

```gleam
pub fn default_options() -> Options
```

### `is_host_bound_cookie_name`

Returns `True` when `name` is host-bound (uses the `__Host-` prefix).

Host-bound cookie names resist cookie tossing / session fixation from
sibling subdomains: browsers only accept a `__Host-` cookie when it is set
with `Secure`, `Path=/`, and no `Domain` attribute, so a sibling subdomain
cannot overwrite it with a `Domain=.example.com` cookie of the same name.
`Options` enforces the prefix for its own cookie name; use this to check
names from other sources.

```gleam
pub fn is_host_bound_cookie_name(String) -> Bool
```

### `request_phase`

Phase 1: Redirect user to the OAuth provider.

Looks up the provider in the registry, generates an authorization URL
with PKCE parameters, stores the CSRF state and code verifier in the
state store, sets a signed session cookie, and returns a redirect response.

Returns 404 if the provider is not registered.

```gleam
pub fn request_phase(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  authorize_options: config.AuthorizeOptions
) -> response.Response(wisp.Body)
```

### `request_phase_with_options`

Phase 1: Redirect user to the OAuth provider using custom middleware
options.

```gleam
pub fn request_phase_with_options(
  request.Request(internal.Connection),
  registry: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  authorize_options: config.AuthorizeOptions,
  middleware_options: Options
) -> response.Response(wisp.Body)
```

### `session_ttl_seconds`

The session TTL in seconds for these options.

```gleam
pub fn session_ttl_seconds(Options) -> Int
```

### `with_cookie_name`

Set a custom session cookie name.

The name is always made host-bound: a `__Host-` prefix is added when
`name` does not already carry one, so both `"my_session"` and
`"__Host-my_session"` produce the effective cookie name
`__Host-my_session`. See the `Options` docs for why the prefix is
mandatory.

```gleam
pub fn with_cookie_name(
  Options,
  String
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
