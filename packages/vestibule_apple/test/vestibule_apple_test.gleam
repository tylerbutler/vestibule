import bravo
import bravo/uset
import gleam/option.{None, Some}
import startest
import startest/expect
import vestibule/config
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

pub fn id_token_cache_try_init_named_returns_error_for_duplicate_table_test() {
  let name = "apple_test_idtok_duplicate"
  let assert Ok(_) = id_token_cache.try_init_named(name)
  let result = id_token_cache.try_init_named(name)
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn id_token_cache_try_init_named_cleans_up_tokens_when_keys_fail_test() {
  let name = "apple_test_idtok_partial"
  let assert Ok(keys) = uset.new(name: name <> "_keys", access: bravo.Private)
  let _ = id_token_cache.try_init_named(name) |> expect.to_be_error()
  let _ = uset.delete(keys)
  let _ = id_token_cache.try_init_named(name) |> expect.to_be_ok()
  Nil
}

pub fn id_token_cache_try_store_cleans_up_token_when_key_store_fails_test() {
  let assert Ok(tokens) =
    uset.new(name: "apple_test_store_partial_tokens", access: bravo.Protected)
  let assert Ok(keys) =
    uset.new(name: "apple_test_store_partial_keys", access: bravo.Private)
  let _ = uset.delete(keys)
  let cache = id_token_cache.IdTokenCache(tokens: tokens, keys: keys)

  let _ = id_token_cache.try_store(cache, "access-token", "id-token")
  let assert Ok(token_entries) = uset.tab2list(tokens)
  token_entries |> expect.to_equal([])
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

pub fn apple_try_init_named_cleans_up_jwks_when_id_token_cache_fails_test() {
  let name = "apple_test_partial"
  let assert Ok(tokens_table) =
    uset.new(name: name <> "_id_token_tokens", access: bravo.Protected)
  let _ = vestibule_apple.try_init_named(name) |> expect.to_be_error()
  let _ = uset.delete(tokens_table)
  let _ = vestibule_apple.try_init_named(name) |> expect.to_be_ok()
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
      expires_in: Some(3600),
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

pub fn parse_token_response_empty_scope_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"\"}"
  let assert Ok(#(credentials, _id_token)) =
    vestibule_apple.parse_token_response(body)
  credentials.scopes |> expect.to_equal([])
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
