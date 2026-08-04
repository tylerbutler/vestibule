import gleam/http/request
import gleam/option
import startest/expect
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/strategy

pub fn authorization_header_accepts_mixed_case_bearer_test() -> Nil {
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

pub fn authorization_header_rejects_unsupported_token_type_test() -> Nil {
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

pub fn append_code_verifier_appends_to_empty_body_test() -> Nil {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("")
  |> strategy.append_code_verifier(option.Some("verifier"))
  |> fn(req) { req.body }
  |> expect.to_equal("code_verifier=verifier")
}

pub fn append_code_verifier_appends_to_existing_body_test() -> Nil {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("grant_type=authorization_code")
  |> strategy.append_code_verifier(option.Some("verifier"))
  |> fn(req) { req.body }
  |> expect.to_equal("grant_type=authorization_code&code_verifier=verifier")
}

pub fn append_code_verifier_encodes_special_chars_test() -> Nil {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("grant_type=authorization_code")
  |> strategy.append_code_verifier(option.Some("a+b/c="))
  |> fn(req) { req.body }
  |> expect.to_equal("grant_type=authorization_code&code_verifier=a%2Bb%2Fc%3D")
}

pub fn append_code_verifier_none_preserves_body_test() -> Nil {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("grant_type=authorization_code")
  |> strategy.append_code_verifier(option.None)
  |> fn(req) { req.body }
  |> expect.to_equal("grant_type=authorization_code")
}

pub fn credentials_accessors_return_token_fields_test() -> Nil {
  let oauth_credentials =
    credentials.new(
      token: "access-token",
      refresh_token: option.Some("refresh-token"),
      token_type: "Bearer",
      expires_in: option.Some(3600),
      scopes: ["read:user"],
    )

  credentials.token(oauth_credentials) |> expect.to_equal("access-token")
  credentials.refresh_token(oauth_credentials)
  |> expect.to_equal(option.Some("refresh-token"))
  credentials.token_type(oauth_credentials) |> expect.to_equal("Bearer")
  credentials.expires_in(oauth_credentials)
  |> expect.to_equal(option.Some(3600))
  credentials.scopes(oauth_credentials) |> expect.to_equal(["read:user"])
}

fn test_config() -> config.ClientConfig {
  config.new(
    client_id: "id",
    auth: config.ClientSecret("secret"),
    redirect_uri: "https://example.com/cb",
  )
}

fn bare_strategy(provider: String) -> strategy.Strategy(e) {
  strategy.new(
    provider: provider,
    default_scopes: [],
    authorize_url: fn(_config, _options, _scopes, _state) {
      Ok("https://example.com/auth")
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.config(reason: "exchange not implemented"))
    },
    fetch_user: fn(_config, _exchange) {
      Error(error.config(reason: "fetch_user not implemented"))
    },
  )
}

pub fn refresh_token_unset_returns_refresh_unsupported_test() -> Nil {
  bare_strategy("no-refresh")
  |> strategy.refresh_token(config: test_config(), refresh_token: "tok")
  |> expect.to_equal(Error(error.refresh_unsupported()))
}

pub fn with_refresh_makes_refresh_supported_test() -> Nil {
  let oauth_credentials =
    credentials.new(
      token: "fresh",
      refresh_token: option.None,
      token_type: "bearer",
      expires_in: option.None,
      scopes: [],
    )

  bare_strategy("has-refresh")
  |> strategy.with_refresh(fn(_client_config, _token) { Ok(oauth_credentials) })
  |> strategy.refresh_token(config: test_config(), refresh_token: "tok")
  |> expect.to_equal(Ok(oauth_credentials))
}

pub fn with_nonce_enables_uses_nonce_test() -> Nil {
  bare_strategy("oidc")
  |> strategy.with_nonce()
  |> strategy.uses_nonce()
  |> expect.to_be_true()
}

pub fn new_defaults_uses_nonce_to_false_test() -> Nil {
  bare_strategy("plain")
  |> strategy.uses_nonce()
  |> expect.to_be_false()
}
