---
name: vestibule_wisp
navLabel: Wisp middleware
kind: Wisp middleware
summary: Wisp request and callback routing with signed session cookies and single-use ETS state storage.
install:
  - "[dependencies]"
  - 'vestibule = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0" }'
  - 'vestibule_wisp = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_wisp" }'
  - 'vestibule_github = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_github" }'
useWhen: Use Wisp middleware if your app routes requests with Wisp. The middleware handles the request and callback phases.
setup:
  - Configure Wisp with a strong, stable secret key base.
  - Initialize the shared state store once per BEAM VM.
  - Register one or more provider strategies in a registry.
  - Route /auth/:provider and /auth/:provider/callback to the middleware.
highlights:
  - Handles GET and POST callbacks. Apple uses response_mode=form_post.
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

  let assert Ok(registry) =
    registry.new()
    |> registry.register(
      vestibule_github.strategy(),
      config.new(
        client_id: "client_id",
        redirect_uri: "http://localhost:8000/auth/github/callback",
        auth: config.ClientSecret("client_secret"),
      ),
    )

  let assert Ok(store) = state_store.create()

  case wisp.path_segments(request), request.method {
    ["auth", provider], http.Get ->
      vestibule_wisp.request_phase(
        request,
        registry,
        provider,
        store,
        authorize_options: config.authorize_options(),
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

    _, _ ->
      wisp.not_found()
  }
notes:
  - Custom cookie names are automatically given the __Host- prefix under the default SecureOnly cookie security.
  - Use with_cookie_security(AllowInsecure) for local development over plain HTTP, where browsers reject __Host- cookies.
  - Use callback_phase_auth_result for structured logging or custom error recovery.
navOrder: 20
searchTerms:
  - routing
  - signed session cookie
  - ets
  - callback errors
---
