---
name: vestibule_mist
navLabel: Mist middleware
kind: Mist middleware
summary: Plain Mist request/callback routing with HMAC-SHA256 signed session cookies and the shared Vestibule state store.
install:
  - gleam add vestibule
  - gleam add vestibule_mist
  - gleam add mist
  - gleam add vestibule_google
useWhen: Use Mist middleware when you run directly on Mist and want the same auth ergonomics without Wisp.
setup:
  - Load a high-entropy secret key base from configuration or a secrets manager.
  - Create Options with vestibule_mist.new_options(secret_key_base).
  - Initialize the shared state store once per BEAM VM.
  - Dispatch request and callback paths from your Mist handler.
highlights:
  - No unsafe default secret; applications must supply one.
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

  let assert Ok(store) = state_store.try_init()
  let options = vestibule_mist.new_options(secret_key_base)

  fn handle_request(req: Request(Connection)) -> Response(ResponseData) {
    case request.path_segments(req), req.method {
      ["auth", provider], http.Get ->
        vestibule_mist.request_phase(req, reg, provider, store, options)

      ["auth", provider, "callback"], http.Get
      | ["auth", provider, "callback"], http.Post ->
        vestibule_mist.callback_phase(req, reg, provider, store, options, on_success)

      _, _ ->
        not_found()
    }
  }
notes:
  - "Set secure_cookie: False only for local HTTP development."
  - Changing the cookie secret invalidates in-flight OAuth callbacks.
navOrder: 30
searchTerms:
  - hmac
  - signed cookies
  - plain mist
  - secure cookie
---
