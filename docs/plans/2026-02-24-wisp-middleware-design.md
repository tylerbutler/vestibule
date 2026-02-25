# Wisp Middleware — Design

## Context

Every app using vestibule with wisp needs the same boilerplate: look up provider in registry, generate authorize URL, store CSRF state, set session cookie, redirect — then on callback, read cookie, retrieve state, call `handle_callback`, handle errors. The example app's `router.gleam` is ~90 lines of this plumbing. A middleware package eliminates this duplication.

## Package

`packages/vestibule_wisp/` — depends on `vestibule` and `wisp`. Keeps the core library framework-agnostic.

## Modules

### `vestibule_wisp` — Middleware

Two main functions that handle the OAuth two-phase flow:

**`request_phase(req, registry, provider) -> Response`**
1. Look up provider in registry (404 if not found)
2. Call `vestibule.authorize_url(strategy, config)`
3. Store CSRF state in ETS via `state_store`
4. Set signed session cookie with session ID
5. Return redirect response to provider

**`callback_phase(req, registry, provider, on_success) -> Response`**
1. Look up provider in registry (404 if not found)
2. Read session cookie
3. Retrieve and consume state from ETS
4. Parse query params and call `vestibule.handle_callback`
5. On success: call `on_success(auth)` — user decides the response
6. On error: return HTML error page

**`callback_phase_result(req, registry, provider) -> Result(Auth, Response)`**
Alternative that returns a Result instead of taking a callback. For users who prefer pattern matching over callbacks.

### `vestibule_wisp/state_store` — ETS-based CSRF State Storage

Moves the example app's `session.gleam` + `session_ffi.erl` into the package:

- `init() -> Nil` — Create ETS table. Call once at startup.
- `store(state: String) -> String` — Store state, return session ID.
- `retrieve(session_id: String) -> Result(String, Nil)` — Get and delete state (one-time use).

## Usage

```gleam
import vestibule_wisp
import vestibule_wisp/state_store

// At startup
state_store.init()

// In router
case wisp.path_segments(req), req.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase(req, registry, provider)

  ["auth", provider, "callback"], http.Get ->
    vestibule_wisp.callback_phase(req, registry, provider, fn(auth) {
      // Create user session, redirect to dashboard, etc.
      wisp.redirect("/dashboard")
    })

  _, _ -> wisp.not_found()
}
```

## Example App Changes

- Delete `session.gleam` and `session_ffi.erl` — replaced by `vestibule_wisp/state_store`
- Simplify `router.gleam` from ~90 lines to ~20 lines
- Add `vestibule_wisp` as a path dependency
- Call `state_store.init()` instead of `session.create_table()` at startup

## Error Handling

Auth errors produce a simple HTML error page with a human-readable message. Users who need custom error pages use `callback_phase_result` and handle `Error(response)` themselves.
