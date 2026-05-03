import gleam/http/request
import gleam/option
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule/strategy

pub fn authorization_header_accepts_mixed_case_bearer_test() {
  Credentials(
    token: "abc",
    refresh_token: option.None,
    token_type: "BeArEr",
    expires_in: option.None,
    scopes: [],
  )
  |> strategy.authorization_header()
  |> expect.to_equal(Ok("Bearer abc"))
}

pub fn authorization_header_rejects_unsupported_token_type_test() {
  let _ =
    Credentials(
      token: "abc",
      refresh_token: option.None,
      token_type: "MAC",
      expires_in: option.None,
      scopes: [],
    )
    |> strategy.authorization_header()
    |> expect.to_be_error()
  Nil
}

pub fn append_code_verifier_appends_to_empty_body_test() {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("")
  |> strategy.append_code_verifier(option.Some("verifier"))
  |> fn(req) { req.body }
  |> expect.to_equal("code_verifier=verifier")
}

pub fn append_code_verifier_appends_to_existing_body_test() {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("grant_type=authorization_code")
  |> strategy.append_code_verifier(option.Some("verifier"))
  |> fn(req) { req.body }
  |> expect.to_equal("grant_type=authorization_code&code_verifier=verifier")
}

pub fn append_code_verifier_encodes_special_chars_test() {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("grant_type=authorization_code")
  |> strategy.append_code_verifier(option.Some("a+b/c="))
  |> fn(req) { req.body }
  |> expect.to_equal("grant_type=authorization_code&code_verifier=a%2Bb%2Fc%3D")
}

pub fn append_code_verifier_none_preserves_body_test() {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("grant_type=authorization_code")
  |> strategy.append_code_verifier(option.None)
  |> fn(req) { req.body }
  |> expect.to_equal("grant_type=authorization_code")
}
