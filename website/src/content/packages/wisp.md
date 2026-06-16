---
name: vestibule_wisp
navLabel: Wisp middleware
kind: Wisp middleware
summary: Wisp request/callback routing for Vestibule, including signed session cookie handling and one-time ETS state storage.
install:
  - gleam add vestibule
  - gleam add vestibule_wisp
  - gleam add wisp
  - gleam add mist
  - gleam add vestibule_github
  - gleam add vestibule_google
useWhen: Use Wisp middleware when your app already routes requests with Wisp and you want the request and callback phases handled for you.
setup:
  - Configure Wisp with a strong, stable secret key base.
  - Initialize the shared state store once per BEAM VM.
  - Register one or more provider strategies in a registry.
  - Route /auth/:provider and /auth/:provider/callback to the middleware.
highlights:
  - Handles both GET and POST callbacks; Apple uses response_mode=form_post.
  - Default cookie name uses the __Host- prefix to defend against cookie tossing.
  - Cookie TTL and server-side state-store TTL share the same value.
  - Structured callback errors are available for custom handling.
code: |
  import gleam/http
  import wisp
  import vestibule/config
  import vestibule/registry
  import vestibule/state_store
  import vestibule_wisp
  import vestibule_github

  let assert Ok(reg) =
    registry.new()
    |> registry.register(
      vestibule_github.strategy(),
      config.new(
        "client_id",
        "client_secret",
        "http://localhost:8000/auth/github/callback",
      ),
    )

  let store = state_store.init()

  case wisp.path_segments(req), req.method {
    ["auth", provider], http.Get ->
      vestibule_wisp.request_phase(req, reg, provider, store)

    ["auth", provider, "callback"], http.Get
    | ["auth", provider, "callback"], http.Post ->
      vestibule_wisp.callback_phase(req, reg, provider, store, on_success)

    _, _ ->
      wisp.not_found()
  }
notes:
  - Keep the __Host- prefix on custom cookie names.
  - Use callback_phase_auth_result when your app needs structured logging or custom user-facing error recovery.
navOrder: 20
searchTerms:
  - routing
  - signed session cookie
  - ets
  - callback errors
---
