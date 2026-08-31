---
name: vestibule_mist
navLabel: Mist middleware
kind: Mist middleware
summary: Plain Mist request and callback routing with HMAC-SHA256 signed session cookies and the shared Vestibule state store.
install:
  - "[dependencies]"
  - 'vestibule = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0" }'
  - 'vestibule_mist = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_mist" }'
  - 'vestibule_github = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_github" }'
useWhen: Use Mist middleware if your app runs directly on Mist and does not use Wisp.
setup:
  - Load a high-entropy secret key base from configuration or a secrets manager.
  - Create Options with vestibule_mist.new_options(secret_key_base).
  - Initialize the shared state store once per BEAM VM.
  - Dispatch request and callback paths from your Mist handler.
highlights:
  - Applications must supply a secret. The package has no unsafe default secret.
  - Sets HttpOnly, SameSite=Lax, Path=/, and Secure by default.
  - Supports GET and application/x-www-form-urlencoded POST callbacks.
  - Structured callback errors mirror the Wisp integration.
code: |
  import gleam/http
  import gleam/http/request.{type Request}
  import gleam/http/response.{type Response}
  import mist.{type Connection, type ResponseData}
  import vestibule/state_store
  import vestibule_mist

  let assert Ok(store) = state_store.create()
  let options = vestibule_mist.new_options(secret_key_base)

  fn handle_request(req: Request(Connection)) -> Response(ResponseData) {
    case request.path_segments(req), req.method {
      ["auth", provider], http.Get ->
        vestibule_mist.request_phase(
          req,
          registry,
          provider,
          store,
          authorize_options: config.authorize_options(),
          options: options,
        )

      ["auth", provider, "callback"], http.Get
      | ["auth", provider, "callback"], http.Post ->
        vestibule_mist.callback_phase(req, registry, provider, store, options, on_success)

      _, _ ->
        not_found()
    }
  }
notes:
  - "Use with_cookie_security(AllowInsecure) only for local HTTP development."
  - A cookie-secret change invalidates OAuth callbacks that are in progress.
navOrder: 30
searchTerms:
  - hmac
  - signed cookies
  - plain mist
  - secure cookie
---
