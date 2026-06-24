# vestibule_mist

Mist middleware for vestibule's OAuth request and callback phases.

## Install

```sh
gleam add vestibule
gleam add vestibule_mist
gleam add mist
gleam add vestibule_google # or another vestibule provider package
```

`vestibule_mist` depends on `vestibule` and `mist`, plus at least one
provider package.

## Configure a signed-cookie secret

Mist has no built-in signed-cookie helper, so `vestibule_mist` ships its own
HMAC-SHA256 cookie signing. You **must** supply a strong, stable secret key
base when building `Options`:

```gleam
let options = vestibule_mist.new_options(secret_key_base)
```

There is no `default_options/0` — the secret has no safe default. Use a
high-entropy value (e.g. 64+ random bytes) and load it from configuration or
a secrets manager.

If the secret changes, existing OAuth callbacks cannot read the signed
session cookie and will return `MissingOrInvalidSessionCookie`.

## What it does

- redirects users to the configured provider
- stores CSRF state and PKCE verifier for the callback
- handles both `GET` and `POST` callbacks
- sets an HMAC-SHA256-signed session cookie with a default 600-second TTL
- enforces server-side state-store expiry with the same TTL
- exposes default response helpers and structured callback errors

## Router shape

Initialize the state store once per BEAM VM at application startup:

```gleam
import vestibule/config
import vestibule/state_store

let assert Ok(store) = state_store.try_init()
let options = vestibule_mist.new_options(secret_key_base)
```

Then dispatch from your mist handler:

```gleam
fn handle_request(req: Request(Connection)) -> Response(ResponseData) {
  case request.path_segments(req), req.method {
    ["auth", provider], http.Get ->
      vestibule_mist.request_phase(
        req,
        reg,
        provider,
        store,
        authorize_options: config.authorize_options(),
        options: options,
      )

    ["auth", provider, "callback"], http.Get
    | ["auth", provider, "callback"], http.Post ->
      vestibule_mist.callback_phase(
        req,
        reg,
        provider,
        store,
        options,
        on_success,
      )

    _, _ -> not_found()
  }
}
```

## Options

`Options` carries the secret plus cookie configuration. Override fields with
record-update syntax:

```gleam
let options =
  vestibule_mist.Options(
    ..vestibule_mist.new_options(secret_key_base),
    cookie_name: "my_app_oauth_session",
    session_ttl_seconds: 300,
  )
```

Defaults match `vestibule_wisp`: cookie name `vestibule_session`, TTL 600
seconds. The cookie TTL and server-side state-store TTL share the same
value. The cookie is set with `HttpOnly`, `SameSite=Lax`, `Path=/`, and
`Secure` by default. For local HTTP development only, set `secure_cookie:
False` with record-update syntax.

If the signed cookie is missing, invalid, or signed with a different
secret, the structured API returns `MissingOrInvalidSessionCookie`. If the
cookie is valid but the stored state is missing, expired, or already used, it
returns `SessionUnavailable`.

## Callback error handling

`vestibule_mist` exposes three callback helpers:

- `callback_phase` returns a mist `Response(ResponseData)`; failures use
  the default HTML error response.
- `callback_phase_result` returns `Result(Auth, Response(ResponseData))`;
  failures are still generated mist responses.
- `callback_phase_auth_result` returns `Result(Auth, CallbackError(e))`;
  use this for structured/custom error handling.

```gleam
case vestibule_mist.callback_phase_auth_result(req, reg, provider, store, options) {
  Ok(auth) -> on_success(auth)
  Error(vestibule_mist.UnknownProvider(provider)) -> handle_unknown(provider)
  Error(vestibule_mist.MissingOrInvalidSessionCookie) -> handle_missing_cookie()
  Error(vestibule_mist.SessionUnavailable) -> handle_expired_session()
  Error(vestibule_mist.InvalidCallbackParams) -> handle_bad_callback()
  Error(vestibule_mist.AuthFailed(err)) -> handle_auth_failure(err)
}
```

`callback_phase` renders a generic authentication failure page on error so
provider-controlled error descriptions are not reflected to users. Use
`callback_phase_auth_result` when the application needs structured error
details for logging or custom rendering.

Malformed provider responses and missing `state` or `code` parameters are
reported through `AuthFailed`. `InvalidCallbackParams` is returned when
callback parameters cannot be extracted from the request, such as malformed
POST form data.

## POST callbacks

`GET` callbacks read query parameters. `POST` callbacks read
`application/x-www-form-urlencoded` body parameters (up to 64 KiB) and
merge them over query parameters, so body values take precedence. If a
POST body cannot be read, decoded as UTF-8, or parsed as form data,
callback handling returns `InvalidCallbackParams` instead of falling back
to query parameters.

## State store

`vestibule_mist` uses the shared `vestibule/state_store` from core
`vestibule`. The same store can be passed to `vestibule_wisp` and
`vestibule_mist` simultaneously; a single ETS owner process is shared
across all transports.

See the `vestibule/state_store` API docs for `try_init`, `init_named`,
`store`, `retrieve`, and TTL semantics.
