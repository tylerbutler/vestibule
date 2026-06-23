import gleam/http/request
import gleam/option
import startest/expect
import vestibule/config
import vestibule/credentials
import vestibule/error
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

fn test_config() -> config.Config {
  config.new(
    client_id: "id",
    client_secret: "secret",
    redirect_uri: "https://example.com/cb",
  )
}

pub fn refresh_token_unset_returns_refresh_unsupported_test() {
  strategy.new(provider: "no-refresh", default_scopes: [])
  |> strategy.refresh_token(cfg: test_config(), refresh_tok: "tok")
  |> expect.to_equal(Error(error.refresh_unsupported()))
}

pub fn with_refresh_makes_refresh_supported_test() {
  let creds =
    credentials.new(
      token: "fresh",
      refresh_token: option.None,
      token_type: "bearer",
      expires_in: option.None,
      scopes: [],
    )

  strategy.new(provider: "has-refresh", default_scopes: [])
  |> strategy.with_refresh(fn(_cfg, _tok) { Ok(creds) })
  |> strategy.refresh_token(cfg: test_config(), refresh_tok: "tok")
  |> expect.to_equal(Ok(creds))
}

pub fn unset_authorize_url_returns_config_error_test() {
  let _ =
    strategy.new(provider: "bare", default_scopes: [])
    |> strategy.build_authorize_url(cfg: test_config(), scopes: [], state: "s")
    |> expect.to_be_error()
  Nil
}

pub fn unset_exchange_code_returns_config_error_test() {
  let _ =
    strategy.new(provider: "bare", default_scopes: [])
    |> strategy.exchange_code(
      cfg: test_config(),
      code: "c",
      code_verifier: option.None,
    )
    |> expect.to_be_error()
  Nil
}

pub fn with_nonce_enables_uses_nonce_test() {
  strategy.new(provider: "oidc", default_scopes: [])
  |> strategy.with_nonce()
  |> strategy.uses_nonce()
  |> expect.to_be_true()
}

pub fn new_defaults_uses_nonce_to_false_test() {
  strategy.new(provider: "plain", default_scopes: [])
  |> strategy.uses_nonce()
  |> expect.to_be_false()
}
