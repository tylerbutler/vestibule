import gleam/dict
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import vestibule/config
import vestibule/credential
import vestibule/strategy
import vestibule_apple
import vestibule_apple/jwks

pub fn main() -> Nil {
  gleeunit.main()
}

// --- Strategy construction ---

fn test_apple_cache(name: String) -> vestibule_apple.AppleCache {
  let assert Ok(cache) = vestibule_apple.initialize_named("apple_test_" <> name)
  cache
}

pub fn jwks_initialize_named_returns_error_for_duplicate_table_test() -> Nil {
  let name = "apple_test_jwks_duplicate"
  let assert Ok(_) = jwks.initialize_named(name)
  let result = jwks.initialize_named(name)
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn apple_initialize_named_returns_error_for_duplicate_cache_test() -> Nil {
  let name = "apple_test_duplicate"
  let assert Ok(_) = vestibule_apple.initialize_named(name)
  let result = vestibule_apple.initialize_named(name)
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn strategy_provider_test() -> Nil {
  let apple_strategy = vestibule_apple.strategy(test_apple_cache("provider"))
  let _ =
    strategy.provider(apple_strategy)
    |> fn(actual) {
      assert actual == "apple"
    }
  Nil
}

pub fn strategy_default_scopes_test() -> Nil {
  let apple_strategy = vestibule_apple.strategy(test_apple_cache("scopes"))
  let _ =
    strategy.default_scopes(apple_strategy)
    |> fn(actual) {
      assert actual == ["name", "email"]
    }
  Nil
}

// --- Token response parsing ---

pub fn parse_token_response_success_test() -> Nil {
  let body =
    "{\"access_token\":\"a1b2c3.test_access_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"r4e5f6.test_refresh\",\"id_token\":\"header.payload.signature\"}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  let _ =
    strategy.exchange_credentials(exchange)
    |> fn(actual) {
      assert actual
        == credential.new(
          token: "a1b2c3.test_access_token",
          refresh_token: Some("r4e5f6.test_refresh"),
          token_type: "Bearer",
          expires_in: Some(3600),
          scopes: [],
        )
    }
  let assert Ok(id_token) =
    dict.get(strategy.exchange_artifacts(exchange), "id_token")
  let _ =
    decode.run(id_token, decode.string)
    |> fn(actual) {
      assert actual == Ok("header.payload.signature")
    }
  Nil
}

pub fn parse_token_response_without_refresh_token_test() -> Nil {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"h.p.s\"}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  let _ =
    strategy.exchange_credentials(exchange)
    |> credential.token()
    |> fn(actual) {
      assert actual == "test_token"
    }
  let _ =
    strategy.exchange_credentials(exchange)
    |> credential.refresh_token()
    |> fn(actual) {
      assert actual == None
    }
  let assert Ok(id_token) =
    dict.get(strategy.exchange_artifacts(exchange), "id_token")
  let _ =
    decode.run(id_token, decode.string)
    |> fn(actual) {
      assert actual == Ok("h.p.s")
    }
  Nil
}

pub fn parse_token_response_without_id_token_test() -> Nil {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  let _ =
    strategy.exchange_credentials(exchange)
    |> credential.token()
    |> fn(actual) {
      assert actual == "test_token"
    }
  let _ =
    dict.get(strategy.exchange_artifacts(exchange), "id_token")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_token_response_empty_scope_test() -> Nil {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"\"}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  let _ =
    strategy.exchange_credentials(exchange)
    |> credential.scopes()
    |> fn(actual) {
      assert actual == []
    }
  Nil
}

pub fn parse_token_response_error_test() -> Nil {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The code has expired.\"}"
  let _ =
    vestibule_apple.parse_token_response(body)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_token_response_error_without_description_test() -> Nil {
  let body = "{\"error\":\"invalid_client\"}"
  let _ =
    vestibule_apple.parse_token_response(body)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() -> Nil {
  let apple_strategy =
    vestibule_apple.strategy(test_apple_cache("invalid_redirect"))
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.ClientSecret("secret"),
    )
  let _ =
    strategy.build_authorize_url(
      apple_strategy,
      config: client_config,
      options: config.authorize_options(),
      scopes: ["name", "email"],
      state: "state",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn sans_io_token_request_and_response_test() -> Nil {
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("client-secret-jwt"),
    )
  let assert Ok(http_request) =
    vestibule_apple.build_authorization_code_request(
      client_config,
      "code-123",
      Some("verifier-123"),
    )
  assert http_request.method == http.Post
  assert http_request.host == "appleid.apple.com"
  assert string.ends_with(http_request.path, "/auth/token")
  assert string.contains(http_request.body, "code=code-123")
  assert string.contains(http_request.body, "code_verifier=verifier-123")
  assert request.get_header(http_request, "accept") == Ok("application/json")

  let http_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"access-123\",\"token_type\":\"Bearer\",\"id_token\":\"header.payload.signature\"}",
    )
  let assert Ok(exchange) =
    vestibule_apple.parse_authorization_code_response(http_response)
  assert exchange
    |> strategy.exchange_credentials
    |> credential.token
    == "access-123"
}

pub fn sans_io_refresh_request_and_response_test() -> Nil {
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("client-secret-jwt"),
    )
  let assert Ok(http_request) =
    vestibule_apple.build_refresh_token_request(client_config, "refresh-123")
  assert string.contains(http_request.body, "grant_type=refresh_token")
  assert string.contains(http_request.body, "refresh_token=refresh-123")

  let http_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"new-access\",\"token_type\":\"Bearer\"}",
    )
  let assert Ok(oauth_credentials) =
    vestibule_apple.parse_refresh_token_response(http_response)
  assert credential.token(oauth_credentials) == "new-access"
}
