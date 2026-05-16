import gleam/http/request
import gleam/option
import gleam/string
import startest/expect
import vestibule/credentials
import vestibule/strategy

pub fn authorization_header_accepts_mixed_case_bearer_test() {
  credentials.new(
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
    credentials.new(
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

pub fn credentials_accessors_return_token_fields_test() {
  let creds =
    credentials.new(
      token: "access-token",
      refresh_token: option.Some("refresh-token"),
      token_type: "Bearer",
      expires_in: option.Some(3600),
      scopes: ["read:user"],
    )

  credentials.token(creds) |> expect.to_equal("access-token")
  credentials.refresh_token(creds)
  |> expect.to_equal(option.Some("refresh-token"))
  credentials.token_type(creds) |> expect.to_equal("Bearer")
  credentials.expires_in(creds) |> expect.to_equal(option.Some(3600))
  credentials.scopes(creds) |> expect.to_equal(["read:user"])
}

pub fn credentials_redacted_does_not_include_token_values_test() {
  let creds =
    credentials.new(
      token: "secret-access-token",
      refresh_token: option.Some("secret-refresh-token"),
      token_type: "Bearer",
      expires_in: option.Some(3600),
      scopes: ["read:user"],
    )
  let rendered = credentials.redacted(creds)

  { string.contains(rendered, "secret-access-token") } |> expect.to_be_false()
  { string.contains(rendered, "secret-refresh-token") } |> expect.to_be_false()
  { string.contains(rendered, "Bearer") } |> expect.to_be_true()
  { string.contains(rendered, "read:user") } |> expect.to_be_true()
}
