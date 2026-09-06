import gleam/option.{Some}
import gleam/string
import vestibule/authorization_request

const authorization_url = "https://provider.example/authorize?state=STATE-SECRET-7f3a&nonce=NONCE-SECRET-9b21"

const state = "STATE-SECRET-7f3a"

const verifier = "VERIFIER-SECRET-4c82"

const nonce = "NONCE-SECRET-9b21"

fn request() -> authorization_request.AuthorizationRequest {
  authorization_request.new(
    url: authorization_url,
    state: state,
    code_verifier: verifier,
    nonce: Some(nonce),
  )
}

pub fn inspection_does_not_expose_authorization_artifacts_test() -> Nil {
  let rendered = string.inspect(request())

  assert !string.contains(rendered, authorization_url)
  assert !string.contains(rendered, state)
  assert !string.contains(rendered, verifier)
  assert !string.contains(rendered, nonce)
}

pub fn erlang_formatting_does_not_expose_authorization_artifacts_test() -> Nil {
  let rendered = erlang_term(request())

  assert !string.contains(rendered, authorization_url)
  assert !string.contains(rendered, state)
  assert !string.contains(rendered, verifier)
  assert !string.contains(rendered, nonce)
}

pub fn accessors_return_authorization_artifacts_test() -> Nil {
  let value = request()

  assert authorization_request.url(value) == authorization_url
  assert authorization_request.state(value) == state
  assert authorization_request.code_verifier(value) == verifier
  assert authorization_request.nonce(value) == Some(nonce)
}

@external(erlang, "vestibule_secret_test_ffi", "format_term")
fn erlang_term(value: a) -> String
