import gleam/option.{None, Some}
import startest
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule_apple
import vestibule_apple/id_token_cache
import vestibule_apple/jwks

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// --- Strategy construction ---

fn test_apple_cache(name: String) -> vestibule_apple.AppleCache {
  vestibule_apple.AppleCache(
    id_tokens: id_token_cache.init_named("apple_test_idtok_" <> name),
    jwks: jwks.init_named("apple_test_jwks_" <> name),
  )
}

pub fn strategy_provider_test() {
  let s = vestibule_apple.strategy(test_apple_cache("provider"))
  s.provider |> expect.to_equal("apple")
}

pub fn strategy_default_scopes_test() {
  let s = vestibule_apple.strategy(test_apple_cache("scopes"))
  s.default_scopes |> expect.to_equal(["name", "email"])
}

pub fn strategy_token_url_test() {
  let s = vestibule_apple.strategy(test_apple_cache("url"))
  s.token_url |> expect.to_equal("https://appleid.apple.com/auth/token")
}

// --- Token response parsing ---

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"a1b2c3.test_access_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"r4e5f6.test_refresh\",\"id_token\":\"header.payload.signature\"}"
  let assert Ok(#(creds, id_token)) = vestibule_apple.parse_token_response(body)
  creds
  |> expect.to_equal(
    Credentials(
      token: "a1b2c3.test_access_token",
      refresh_token: Some("r4e5f6.test_refresh"),
      token_type: "Bearer",
      expires_at: Some(3600),
      scopes: [],
    ),
  )
  id_token |> expect.to_equal(Some("header.payload.signature"))
}

pub fn parse_token_response_without_refresh_token_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"h.p.s\"}"
  let assert Ok(#(creds, id_token)) = vestibule_apple.parse_token_response(body)
  creds.token |> expect.to_equal("test_token")
  creds.refresh_token |> expect.to_equal(None)
  id_token |> expect.to_equal(Some("h.p.s"))
}

pub fn parse_token_response_without_id_token_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
  let assert Ok(#(creds, id_token)) = vestibule_apple.parse_token_response(body)
  creds.token |> expect.to_equal("test_token")
  id_token |> expect.to_equal(None)
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
