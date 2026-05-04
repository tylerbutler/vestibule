# vestibule_wisp

Wisp middleware for vestibule's OAuth request and callback phases.

## Install

```sh
gleam add vestibule
gleam add vestibule_wisp
gleam add wisp
gleam add mist
gleam add vestibule_google # or another vestibule provider package
```

`vestibule_wisp` depends on `vestibule` and `wisp`, but a typical application
also uses a Wisp server runtime such as `mist` and at least one provider package.

## Configure Wisp signed cookies

`vestibule_wisp` stores the OAuth session ID in a signed Wisp cookie. Configure
your Wisp handler with a strong, stable secret key base:

```gleam
wisp_mist.handler(router.handle_request, secret_key_base)
```

If the secret changes, existing OAuth callbacks cannot read the signed session
cookie and will return `MissingSessionCookie`.

## What it does

- redirects users to the configured provider
- stores CSRF state and PKCE verifier for the callback
- handles both `GET` and `POST` callbacks
- sets a signed session cookie with a default 600-second TTL
- enforces server-side state-store expiry with the same TTL
- exposes default response helpers and structured callback errors

## Router shape

Initialize the state store once per BEAM VM at application startup:

```gleam
let assert Ok(store) = state_store.try_init()
```

Then pass that store to the request and callback phases:

```gleam
case wisp.path_segments(req), req.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase(req, reg, provider, store)

  ["auth", provider, "callback"], http.Get
  | ["auth", provider, "callback"], http.Post ->
    vestibule_wisp.callback_phase(req, reg, provider, store, on_success)

  _ ->
    wisp.not_found()
}
```

For a runnable app, see `example/`.

## Options

The default options preserve the existing cookie contract:

```gleam
vestibule_wisp.default_options()
// -> Options(cookie_name: "vestibule_session", session_ttl_seconds: 600)
```

Use the `_with_options` functions to customize the cookie name or session TTL:

```gleam
let options =
  vestibule_wisp.Options(
    cookie_name: "my_app_oauth_session",
    session_ttl_seconds: 300,
  )

vestibule_wisp.request_phase_with_options(req, reg, provider, store, options)
vestibule_wisp.callback_phase_with_options(
  req,
  reg,
  provider,
  store,
  on_success,
  options,
)
```

The cookie TTL and server-side state-store TTL use the same
`session_ttl_seconds` value. Users must complete the provider callback before
that TTL expires. If the signed cookie is missing, invalid, or expired, the
structured API returns `MissingSessionCookie`; if the cookie is valid but the
stored state is missing, expired, or already used, it returns `SessionExpired`.

## Callback error handling

`vestibule_wisp` exposes three callback helpers:

- `callback_phase` returns a Wisp `Response`; failures use the default HTML
  error response.
- `callback_phase_result` returns `Result(Auth, Response)`; failures are still
  generated Wisp responses.
- `callback_phase_auth_result` returns `Result(Auth, CallbackError(e))`; use
  this for structured/custom error handling.

```gleam
case vestibule_wisp.callback_phase_auth_result(req, reg, provider, store) {
  Ok(auth) -> on_success(auth)
  Error(vestibule_wisp.UnknownProvider(provider)) -> handle_unknown(provider)
  Error(vestibule_wisp.MissingSessionCookie) -> handle_missing_cookie()
  Error(vestibule_wisp.SessionExpired) -> handle_expired_session()
  Error(vestibule_wisp.InvalidCallbackParams) -> handle_bad_callback()
  Error(vestibule_wisp.AuthFailed(err)) -> handle_auth_failure(err)
}
```

Malformed provider responses and missing `state` or `code` parameters are
reported through `AuthFailed`. `InvalidCallbackParams` is returned when callback
parameters cannot be extracted from the request, such as malformed POST form
data.

## POST callbacks

`GET` callbacks read query parameters. `POST` callbacks read
`application/x-www-form-urlencoded` body parameters and merge them over query
parameters, so body values take precedence. If a POST body cannot be read,
decoded as UTF-8, or parsed as form data, callback handling returns
`InvalidCallbackParams` instead of falling back to query parameters.

## State store

`vestibule_wisp/state_store` provides the default in-memory state store backed
by Erlang ETS. The public `StateStore` type is opaque; applications should
create and use stores through the module functions.

- Use `try_init` or `try_init_named` when you want to handle duplicate table
  errors explicitly.
- `init`, `init_named`, and `store` are panic-on-error convenience wrappers for
  application startup and simple examples.
- `retrieve` consumes state exactly once.
- Expired sessions are treated as missing and removed from the store.
