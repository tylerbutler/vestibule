---
title: "vestibule_wisp"
description: "Wisp middleware that wires a `Registry` of `Strategy` values into HTTP endpoints."
nav:
  group: Reference
  groupOrder: 20
  order: 35
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
  MissingSessionCookie
  SessionExpired
  InvalidCallbackParams
  AuthFailed(error.AuthError(a))
}
```

#### Constructors

##### `UnknownProvider(provider: String)`

The requested provider is not registered.

##### `MissingSessionCookie`

The signed session cookie set during the request phase is missing or invalid.

##### `SessionExpired`

The session state was not found, expired, or already used.

##### `InvalidCallbackParams`

Callback parameters could not be extracted from the request.

##### `AuthFailed(error.AuthError(a))`

Provider authentication failed.

### `Options`

Middleware configuration options.

`cookie_name` should be host-bound (use the `__Host-` prefix) to defend
against OAuth session cookie tossing / fixation. A non-host-bound name such
as `vestibule_session` can be overwritten by a sibling subdomain setting a
`Domain=.example.com` cookie of the same name, which lets an attacker plant
their own in-flight flow state and fixate the victim's session — especially
dangerous in account-linking flows. The default options use a host-bound
name; keep the `__Host-` prefix for any custom `cookie_name`. See
`is_host_bound_cookie_name`.

```gleam
pub type Options {
  Options(
    cookie_name: String,
    session_ttl_seconds: Int
  )
}
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
  reg: registry.Registry(a),
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
  reg: registry.Registry(a),
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
  reg: registry.Registry(a),
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
  reg: registry.Registry(a),
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
  reg: registry.Registry(a),
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
  reg: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  on_success: fn(auth.Auth) -> response.Response(wisp.Body),
  options: Options
) -> response.Response(wisp.Body)
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
Prefer keeping the `__Host-` prefix for any custom `Options.cookie_name`;
use this to validate names supplied by callers.

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
  reg: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore
) -> response.Response(wisp.Body)
```

### `request_phase_with_options`

Phase 1: Redirect user to the OAuth provider using custom middleware
options.

```gleam
pub fn request_phase_with_options(
  request.Request(internal.Connection),
  reg: registry.Registry(a),
  provider: String,
  state_store: state_store.StateStore,
  options: Options
) -> response.Response(wisp.Body)
```
