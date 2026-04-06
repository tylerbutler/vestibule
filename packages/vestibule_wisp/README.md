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
