import gleam/dict
import gleam/dynamic/decode
import gleam/option.{None, Some}
import startest
import startest/expect
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule_apple
import vestibule_apple/jwks

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// --- Strategy construction ---

fn test_apple_cache(name: String) -> vestibule_apple.AppleCache {
  vestibule_apple.AppleCache(jwks: jwks.init_named("apple_test_jwks_" <> name))
}

pub fn jwks_try_init_named_returns_error_for_duplicate_table_test() {
  let name = "apple_test_jwks_duplicate"
  let assert Ok(_) = jwks.try_init_named(name)
  let result = jwks.try_init_named(name)
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn apple_try_init_named_returns_error_for_duplicate_cache_test() {
  let name = "apple_test_duplicate"
  let assert Ok(_) = vestibule_apple.try_init_named(name)
  let result = vestibule_apple.try_init_named(name)
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn strategy_provider_test() {
  let s = vestibule_apple.strategy(test_apple_cache("provider"))
  s.provider |> expect.to_equal("apple")
}

pub fn strategy_default_scopes_test() {
  let s = vestibule_apple.strategy(test_apple_cache("scopes"))
  s.default_scopes |> expect.to_equal(["name", "email"])
}

// --- Token response parsing ---

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"a1b2c3.test_access_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"r4e5f6.test_refresh\",\"id_token\":\"header.payload.signature\"}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  exchange.credentials
  |> expect.to_equal(
    Credentials(
      token: "a1b2c3.test_access_token",
      refresh_token: Some("r4e5f6.test_refresh"),
      token_type: "Bearer",
      expires_in: Some(3600),
      scopes: [],
    ),
  )
  let assert Ok(id_token) = dict.get(exchange.artifacts, "id_token")
  decode.run(id_token, decode.string)
  |> expect.to_equal(Ok("header.payload.signature"))
}

pub fn parse_token_response_without_refresh_token_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"h.p.s\"}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  exchange.credentials.token |> expect.to_equal("test_token")
  exchange.credentials.refresh_token |> expect.to_equal(None)
  let assert Ok(id_token) = dict.get(exchange.artifacts, "id_token")
  decode.run(id_token, decode.string) |> expect.to_equal(Ok("h.p.s"))
}

pub fn parse_token_response_without_id_token_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  exchange.credentials.token |> expect.to_equal("test_token")
  dict.get(exchange.artifacts, "id_token") |> expect.to_be_error()
}

pub fn parse_token_response_empty_scope_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"\"}"
  let assert Ok(exchange) = vestibule_apple.parse_token_response(body)
  exchange.credentials.scopes |> expect.to_equal([])
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The code has expired.\"}"
  let _ =
    vestibule_apple.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn parse_token_response_error_without_description_test() {
  let body = "{\"error\":\"invalid_client\"}"
  let _ =
    vestibule_apple.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() {
  let strat = vestibule_apple.strategy(test_apple_cache("invalid_redirect"))
  let conf = config.new("client-id", "secret", "not a uri")
  let _ =
    strat.authorize_url(conf, ["name", "email"], "state")
    |> expect.to_be_error()
  Nil
}
