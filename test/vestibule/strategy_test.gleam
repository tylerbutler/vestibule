import gleam/http/request
import gleam/option
import vestibule/config
import vestibule/credential
import vestibule/error
import vestibule/strategy

pub fn authorization_header_accepts_mixed_case_bearer_test() -> Nil {
  let header =
    credential.new(
      token: "abc",
      refresh_token: option.None,
      token_type: "BeArEr",
      expires_in: option.None,
      scopes: [],
    )
    |> strategy.authorization_header()
  assert header == Ok("Bearer abc")
}

pub fn authorization_header_rejects_unsupported_token_type_test() -> Nil {
  let assert Error(_) =
    credential.new(
      token: "abc",
      refresh_token: option.None,
      token_type: "MAC",
      expires_in: option.None,
      scopes: [],
    )
    |> strategy.authorization_header()
  Nil
}

pub fn authorization_header_rejects_header_injection_test() -> Nil {
  let assert Error(_) =
    credential.new(
      token: "abc\r\nx-injected: true",
      refresh_token: option.None,
      token_type: "Bearer",
      expires_in: option.None,
      scopes: [],
    )
    |> strategy.authorization_header()
  Nil
}

pub fn append_code_verifier_appends_to_empty_body_test() -> Nil {
  let assert Ok(http_request) = request.to("https://example.com/token")

  let http_request =
    http_request
    |> request.set_body("")
    |> strategy.append_code_verifier(option.Some("verifier"))
  assert http_request.body == "code_verifier=verifier"
}

pub fn append_code_verifier_appends_to_existing_body_test() -> Nil {
  let assert Ok(http_request) = request.to("https://example.com/token")

  let http_request =
    http_request
    |> request.set_body("grant_type=authorization_code")
    |> strategy.append_code_verifier(option.Some("verifier"))
  assert http_request.body
    == "grant_type=authorization_code&code_verifier=verifier"
}

pub fn append_code_verifier_encodes_special_chars_test() -> Nil {
  let assert Ok(http_request) = request.to("https://example.com/token")

  let http_request =
    http_request
    |> request.set_body("grant_type=authorization_code")
    |> strategy.append_code_verifier(option.Some("a+b/c="))
  assert http_request.body
    == "grant_type=authorization_code&code_verifier=a%2Bb%2Fc%3D"
}

pub fn append_code_verifier_none_preserves_body_test() -> Nil {
  let assert Ok(http_request) = request.to("https://example.com/token")

  let http_request =
    http_request
    |> request.set_body("grant_type=authorization_code")
    |> strategy.append_code_verifier(option.None)
  assert http_request.body == "grant_type=authorization_code"
}

pub fn credentials_accessors_return_token_fields_test() -> Nil {
  let oauth_credentials =
    credential.new(
      token: "access-token",
      refresh_token: option.Some("refresh-token"),
      token_type: "Bearer",
      expires_in: option.Some(3600),
      scopes: ["read:user"],
    )

  assert credential.token(oauth_credentials) == "access-token"
  assert credential.refresh_token(oauth_credentials)
    == option.Some("refresh-token")
  assert credential.token_type(oauth_credentials) == "Bearer"
  assert credential.expires_in(oauth_credentials) == option.Some(3600)
  assert credential.scopes(oauth_credentials) == ["read:user"]
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
  let result =
    bare_strategy("no-refresh")
    |> strategy.refresh_token(config: test_config(), refresh_token: "tok")
  assert result == Error(error.refresh_unsupported())
}

pub fn with_refresh_makes_refresh_supported_test() -> Nil {
  let oauth_credentials =
    credential.new(
      token: "fresh",
      refresh_token: option.None,
      token_type: "bearer",
      expires_in: option.None,
      scopes: [],
    )

  let result =
    bare_strategy("has-refresh")
    |> strategy.with_refresh(fn(_client_config, _token) {
      Ok(oauth_credentials)
    })
    |> strategy.refresh_token(config: test_config(), refresh_token: "tok")
  assert result == Ok(oauth_credentials)
}

pub fn with_nonce_enables_uses_nonce_test() -> Nil {
  let oidc =
    bare_strategy("oidc")
    |> strategy.with_nonce()
  assert strategy.uses_nonce(oidc)
}

pub fn new_defaults_uses_nonce_to_false_test() -> Nil {
  assert !strategy.uses_nonce(bare_strategy("plain"))
}
