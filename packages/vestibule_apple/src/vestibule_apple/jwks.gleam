/// Apple JWKS (JSON Web Key Set) fetching and caching.
///
/// Fetches Apple's public keys from `https://appleid.apple.com/auth/keys`
/// and caches them in a bravo ETS table for reuse. Keys are used to verify
/// the signature of Apple's ID token JWTs.
import bravo
import bravo/uset.{type USet}
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/result

import vestibule/error.{type AuthError}
import ywt/verify_key.{type VerifyKey}

const apple_jwks_url = "https://appleid.apple.com/auth/keys"

/// Opaque cache for Apple's JWKS keys.
pub type JwksCache =
  USet(String, List(VerifyKey))

const cache_key = "apple_jwks"

/// Initialize the JWKS cache. Call once at application startup.
pub fn init() -> JwksCache {
  let assert Ok(table) =
    uset.new(name: "vestibule_apple_jwks", access: bravo.Protected)
  table
}

/// Initialize a named JWKS cache. Useful for testing.
pub fn init_named(name: String) -> JwksCache {
  let assert Ok(table) = uset.new(name: name, access: bravo.Protected)
  table
}

/// Get Apple's public verification keys, using cached keys if available.
/// Falls back to fetching from Apple's JWKS endpoint.
pub fn get_keys(cache: JwksCache) -> Result(List(VerifyKey), AuthError(e)) {
  case uset.lookup(from: cache, at: cache_key) {
    Ok(keys) -> Ok(keys)
    Error(_) -> {
      use keys <- result.try(fetch_keys())
      let _ = uset.insert(into: cache, key: cache_key, value: keys)
      Ok(keys)
    }
  }
}

/// Force refresh the cached keys from Apple's endpoint.
pub fn refresh_keys(cache: JwksCache) -> Result(List(VerifyKey), AuthError(e)) {
  use keys <- result.try(fetch_keys())
  let _ = uset.insert(into: cache, key: cache_key, value: keys)
  Ok(keys)
}

/// Fetch Apple's public keys from the JWKS endpoint.
fn fetch_keys() -> Result(List(VerifyKey), AuthError(e)) {
  let assert Ok(req) = request.to(apple_jwks_url)
  let req = req |> request.set_header("accept", "application/json")
  case httpc.send(req) {
    Ok(response) -> parse_jwks(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to fetch Apple JWKS from " <> apple_jwks_url,
      ))
  }
}

/// Parse a JWKS JSON response into a list of verification keys.
pub fn parse_jwks(body: String) -> Result(List(VerifyKey), AuthError(e)) {
  case json.parse(body, verify_key.set_decoder()) {
    Ok(keys) -> Ok(keys)
    Error(_) ->
      Error(error.ConfigError(reason: "Failed to parse Apple JWKS response"))
  }
}
