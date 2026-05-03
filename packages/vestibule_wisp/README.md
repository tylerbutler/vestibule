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

Use `callback_phase_auth_result` when you need exact error handling for
`UnknownProvider`, `MissingSessionCookie`, `SessionExpired`,
`InvalidCallbackParams`, or `AuthFailed` instead of an HTML error response.
