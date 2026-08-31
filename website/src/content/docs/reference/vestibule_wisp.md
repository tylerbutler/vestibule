---
title: "vestibule_wisp"
description: "Wisp middleware that wires a `Registry` of `Strategy` values into HTTP endpoints."
nav:
  group: Reference
  groupOrder: 20
  order: 37
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
  MissingOrInvalidSessionCookie(reason: SessionCookieError)
  SessionUnavailable
  InvalidCallbackParams(reason: CallbackParamsError)
  AuthFailed(error.AuthError(a))
}
```

#### Constructors

##### `UnknownProvider(provider: String)`

The requested provider is not registered.

##### `MissingOrInvalidSessionCookie(reason: SessionCookieError)`

The signed session cookie set during the request phase is missing or
invalid; `reason` says which.

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

### `CookieSameSite`

How the session cookie's `SameSite` attribute is set.

```gleam
pub type CookieSameSite {
  Lax
  CrossSite
}
```

#### Constructors

##### `Lax`

`SameSite=Lax` (default), set via `wisp.set_cookie`. Sent on top-level
GET navigations, which is how every provider that redirects back with
query parameters delivers its callback.

##### `CrossSite`

`SameSite=None; Secure`. Required for providers that deliver the
callback with a cross-site POST (`response_mode=form_post`, e.g. Apple):
browsers do not send `Lax` cookies on cross-site POSTs, so the callback
would fail with `MissingOrInvalidSessionCookie(CookieAbsent)`. Browsers
only honour `SameSite=None` together with `Secure`, so `Secure` is always
set for this mode, even for plain-HTTP localhost requests.

### `CookieSecurity`

Whether the session cookie requires HTTPS.

```gleam
pub type CookieSecurity {
  SecureOnly
  AllowInsecure
}
```

#### Constructors

##### `SecureOnly`

Use a host-bound (`__Host-` prefixed) cookie name. Use in production.

`wisp.set_cookie` sets `Secure`, `Path=/`, and no `Domain` for any request
that is not plain HTTP on localhost, which is exactly what browsers
require before they will accept a `__Host-` cookie.

##### `AllowInsecure`

Use an unprefixed cookie name so the session also works over plain HTTP,
e.g. local development without TLS.

`wisp.set_cookie` omits `Secure` for plain-HTTP localhost requests, and
browsers reject a `__Host-` cookie that is not `Secure` — so under
`SecureOnly` the cookie would be silently dropped and every callback
would fail with `MissingOrInvalidSessionCookie(CookieAbsent)`.

### `Options`

Middleware configuration options.

Construct with `default_options` and customize with `with_cookie_name`,
`with_session_ttl_seconds`, `with_cookie_security`, and `with_same_site`. The type is opaque
so the effective cookie name always matches the cookie security: host-bound
(`__Host-` prefixed) under `SecureOnly`, unprefixed under `AllowInsecure`
(browsers reject `__Host-` cookies that are not `Secure`). A host-bound
name prevents a sibling subdomain from overwriting the session cookie with
a `Domain=.example.com` cookie of the same name, which would let an
attacker plant their own in-flight flow state and fixate the victim's
session — especially dangerous in account-linking flows. Read the effective
name with `cookie_name`.

```gleam
pub type Options
```

### `SessionCookieError`

Why the signed session cookie could not be used.

The distinction matters operationally: `CookieAbsent` is ordinary user
behaviour (a bookmarked callback URL, a cleared cookie jar, an expired
cookie), while `CookieSignatureInvalid` means a cookie was presented that
this application's secret key base did not sign, which may indicate
tampering or a secret rotation that invalidated in-flight logins.

```gleam
pub type SessionCookieError {
  CookieAbsent
  CookieSignatureInvalid
}
```

#### Constructors

##### `CookieAbsent`

No cookie with the configured name was present on the request.

##### `CookieSignatureInvalid`

A cookie was present but Wisp could not verify its signature: tampered
payload, a malformed token, or a different secret key base.

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

### `default_options`

Default middleware options.

Uses the host-bound `__Host-vestibule_session` signed cookie with a
600-second session TTL and `SecureOnly` cookie security. The `__Host-`
prefix makes browsers reject the cookie unless it is set with `Secure`,
`Path=/`, and no `Domain` attribute, which prevents a sibling subdomain
from tossing/fixating the OAuth session (see the `Options` docs).

`wisp.set_cookie` sets `Path=/` and no `Domain` always, and `Secure` for
every request except plain HTTP on localhost — so these defaults meet the
`__Host-` requirements in production but not when developing over
`http://localhost`. For that case use
`with_cookie_security(AllowInsecure)`.

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

### `same_site`

The session cookie's `SameSite` setting for these options.

```gleam
pub fn same_site(Options) -> CookieSameSite
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

### `with_same_site`

Set the session cookie's `SameSite` attribute. See `CookieSameSite`.

```gleam
pub fn with_same_site(
  Options,
  CookieSameSite
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
