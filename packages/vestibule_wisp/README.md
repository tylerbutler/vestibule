# vestibule_wisp

Wisp middleware for vestibule's OAuth request and callback phases.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is intended for demos and prototypes that need real OAuth flows — do not
> use it in production.

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
import vestibule/config

let assert Ok(store) = state_store.create()
```

Then pass that store to the request and callback phases:

```gleam
case wisp.path_segments(request), request.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase_for_client(
      request,
      registry,
      provider,
      store,
      authorize_options: config.authorize_options(),
      client_key: direct_peer_identity,
    )

  ["auth", provider, "callback"], http.Get
  | ["auth", provider, "callback"], http.Post ->
    vestibule_wisp.callback_phase(
      request,
      registry,
      provider,
      store,
      on_success,
    )

  _ ->
    wisp.not_found()
}
```

For a runnable app, see `example/`.

## Options

The default options use a host-bound (`__Host-` prefixed) session cookie:

```gleam
vestibule_wisp.default_options()
// -> Options(cookie_name: "__Host-vestibule_session", session_ttl_seconds: 600)
```

The `__Host-` prefix defends against OAuth session cookie tossing / fixation:
browsers only accept a `__Host-` cookie when it is set with `Secure`, `Path=/`,
and no `Domain` attribute, so a sibling subdomain cannot overwrite it with a
`Domain=.example.com` cookie of the same name. `wisp.set_cookie` sets `Path=/`
and no `Domain` always, and `Secure` for every request except plain HTTP on
localhost, so the default cookie meets the `__Host-` requirements in production.

The cookie is `SameSite=Lax`, which browsers send on the top-level GET
navigation most providers use for the callback but **not** on a cross-site
POST. Providers that use `response_mode=form_post` (e.g. Apple) therefore need
`with_same_site(CrossSite)`, which emits `SameSite=None; Secure` (always
`Secure`, because browsers ignore `SameSite=None` without it).

For local development over `http://localhost` that last point matters: Wisp
omits `Secure`, browsers then reject the `__Host-` cookie, and every callback
fails with `MissingOrInvalidSessionCookie(CookieAbsent)`. Use
`with_cookie_security(AllowInsecure)` there, which drops the prefix so the
cookie survives. Keep the default `SecureOnly` in production.

`Options` is opaque — build it with `default_options` and the `with_*`
functions, which keep the effective cookie name consistent with the cookie
security. Use `vestibule_wisp.is_host_bound_cookie_name/1` to check a
caller-supplied name.

```gleam
let options =
  vestibule_wisp.default_options()
  |> vestibule_wisp.with_cookie_name("my_app_oauth_session")
  |> vestibule_wisp.with_session_ttl_seconds(300)

// Local development without TLS:
let development_options =
  vestibule_wisp.default_options()
  |> vestibule_wisp.with_cookie_security(vestibule_wisp.AllowInsecure)

vestibule_wisp.request_phase_for_client_with_options(
  request,
  registry,
  provider,
  store,
  authorize_options: config.authorize_options(),
  middleware_options: options,
  client_key: direct_peer_identity,
)
vestibule_wisp.callback_phase_with_options(
  request,
  registry,
  provider,
  store,
  on_success,
  options,
)
```

The cookie TTL and server-side state-store TTL use the same
`session_ttl_seconds` value. Users must complete the provider callback before
that TTL expires. If the signed cookie is missing, invalid, or expired, the
structured API returns `MissingOrInvalidSessionCookie(reason)`, where `reason`
is `CookieAbsent` (no cookie was sent — ordinary user behaviour) or
`CookieSignatureInvalid` (a cookie was sent that this secret key base did not
sign — possible tampering, or a secret rotation). If the cookie is valid but
the stored state is missing, expired, or already used, it returns
`SessionUnavailable`. Requests with duplicate session-cookie names are rejected
as invalid instead of choosing one by header order.

## Callback error handling

`vestibule_wisp` exposes three callback helpers:

- `callback_phase` returns a Wisp `Response`; failures use the default HTML
  error response.
- `callback_phase_result` returns `Result(Auth, Response)`; failures are still
  generated Wisp responses.
- `callback_phase_auth_result` returns `Result(Auth, CallbackError(e))`; use
  this for structured/custom error handling.

`callback_phase` expires the in-flight cookie after a successful callback or
terminal failure. With either Result variant, expire the cookie on the final
response with `expire_session_cookie(response, request, options)` after success;
terminal error responses from `callback_phase_result` are already expired.
Malformed or wrong-state callbacks keep the cookie because their stored flow
remains valid.

```gleam
case vestibule_wisp.callback_phase_auth_result(
  request,
  registry,
  provider,
  store,
) {
  Ok(auth) -> on_success(auth)
  Error(vestibule_wisp.UnknownProvider(provider)) -> handle_unknown(provider)
  Error(vestibule_wisp.MissingOrInvalidSessionCookie(reason)) ->
    handle_missing_cookie(reason)
  Error(vestibule_wisp.SessionUnavailable) -> handle_expired_session()
  Error(vestibule_wisp.InvalidCallbackParams(reason)) ->
    handle_bad_callback(reason)
  Error(vestibule_wisp.AuthFailed(auth_error)) ->
    handle_auth_failure(auth_error)
}
```

`callback_phase` renders a generic authentication failure page on error so
provider-controlled error descriptions are not reflected to users. Use
`callback_phase_auth_result` or `callback_phase_auth_result_with_options` when
the application needs structured error details for logging or custom rendering.

Malformed query encoding is rejected before a POST body is parsed, so a valid
body cannot hide ambiguous query input. Malformed provider responses and
missing `state` or `code` parameters are
reported through `AuthFailed`. `InvalidCallbackParams` is returned when callback
parameters cannot be extracted from the request, such as malformed POST form
data.

## POST callbacks

`GET` callbacks read query parameters. `POST` callbacks read at most 64 KiB of
`application/x-www-form-urlencoded` body parameters alongside query
parameters. Repeated parameter names are rejected, including identical values
and names present once in the query and once in the body. The signed session
cookie is verified before a POST body is read. If a body is too large, cannot
be read, decoded as UTF-8, or parsed as form data, callback handling returns
`InvalidCallbackParams` without falling back to query parameters.

## State store

`vestibule_wisp` uses the shared `vestibule/state_store` from core
`vestibule` — the default in-memory state store backed by Erlang ETS. The
public `StateStore` type is opaque; applications should create and use
stores through the module functions.

- Use `create` or `create_named` when you want to handle duplicate table
  errors explicitly.
- `init`, `init_named`, and `store` are panic-on-error convenience wrappers for
  application startup and simple examples.
- `retrieve` consumes state exactly once.
- Expired sessions are treated as missing and removed from the store.
- A store holds at most 4,096 live sessions and eight live sessions per client
  by default. Use `create_with_limits` to change both limits.
- The request helpers without a client identity fail closed with 429. Wisp does
  not expose the direct socket peer, so applications must call
  `request_phase_for_client` or `request_phase_for_client_with_options` with a
  stable direct-peer identifier.
- `request_phase_with_shared_bucket` and
  `request_phase_with_shared_bucket_and_options` are explicit compatibility
  opt-ins. Any eight anonymous starts can fill that bucket, so use them only
  behind an upstream rate limit.
  Do not use `Forwarded` or `X-Forwarded-For` unless a trusted proxy removes
  client-supplied values and validates the complete proxy chain.
- Admission and insertion are atomic. A rejected request returns 429 and stores
  no state; existing callbacks remain usable.
- The same store can be shared with `vestibule_mist`; a single ETS owner
  process is shared across all transports.

## Deployment limits

Vestibule bounds callback bodies to 64 KiB, state lifetime to 600 seconds,
one client to eight live flows, and one store to 4,096 live flows by default.
The application or edge proxy must also limit request rate and concurrent
connections for `/auth/*`, cap request headers, enforce read timeouts, and
rate-limit the callback route. These upstream limits must use the direct peer
or a validated trusted-proxy identity. Vestibule does not trust forwarded
headers.

Run `just test-pkg vestibule_wisp` for the repeatable admission, cookie replay,
duplicate-cookie, SameSite, and 64 KiB boundary checks.
When Chromium, OpenSSL, and Python's `websocket-client` are installed, run
`python test/browser_cookie_matrix.py` from the repository root for the real
browser fixation, SameSite POST, and cookie-expiry matrix.
