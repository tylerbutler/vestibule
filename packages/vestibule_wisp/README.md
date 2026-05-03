# vestibule_wisp

Wisp middleware for vestibule's OAuth request and callback phases.

## Install

```sh
gleam add vestibule_wisp
```

## What it does

- redirects users to the configured provider
- stores CSRF state + PKCE verifier for the callback
- handles both `GET` and `POST` callbacks
- returns either the default HTML error page or a `Result` via `callback_phase_result`
- exposes structured callback failures via `callback_phase_auth_result`
- sets a signed `vestibule_session` cookie with a 600-second TTL

## Minimal shape

```gleam
let store = state_store.init()

case wisp.path_segments(req), req.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase(req, reg, provider, store)
  ["auth", provider, "callback"], http.Get
  | ["auth", provider, "callback"], http.Post
  ->
    vestibule_wisp.callback_phase(req, reg, provider, store, on_success)
}
```

Initialize the state store once per BEAM VM at application startup. For tests
or multiple stores in one VM, use `state_store.init_named("unique_name")`;
use `try_init`/`try_init_named` if you want to handle duplicate-table errors.

`request_phase` stores the generated state and PKCE verifier in the state store
and sets a signed `vestibule_session` cookie that expires after 600 seconds.
Users must complete the provider callback before that TTL expires. If the signed
cookie is missing, invalid, or expired, the structured API returns
`MissingSessionCookie`; if the cookie is valid but the stored state is missing,
expired, or already used, it returns `SessionExpired`.

## Callback error handling

Use `callback_phase` for the default HTML error response, `callback_phase_result`
when you want `Result(Auth, Response)`, or `callback_phase_auth_result` when you
need structured callback errors:

```gleam
case vestibule_wisp.callback_phase_auth_result(req, reg, provider, store) {
  Ok(auth) -> on_success(auth)
  Error(vestibule_wisp.UnknownProvider(provider)) -> handle_unknown(provider)
  Error(vestibule_wisp.MissingSessionCookie) -> handle_missing_cookie()
  Error(vestibule_wisp.SessionExpired) -> handle_expired_session()
  Error(vestibule_wisp.AuthFailed(err)) -> handle_auth_failure(err)
  Error(vestibule_wisp.InvalidCallbackParams) -> handle_bad_callback()
}
```

This lets applications distinguish routing, cookie, session, parameter, and
provider-authentication failures without parsing an HTML response.
Malformed provider responses and missing `state` or `code` parameters are
reported through `AuthFailed`; `InvalidCallbackParams` is reserved for callback
parameter extraction failures.
