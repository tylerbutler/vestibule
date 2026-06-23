//// Apple JWKS (JSON Web Key Set) fetching and caching.
////
//// Fetches Apple's public keys from `https://appleid.apple.com/auth/keys`
//// and caches them in a bravo ETS table for reuse. Keys are used to verify
//// the signature of Apple's ID token JWTs.

import bravo
import bravo/uset.{type USet}
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/option
import gleam/result
import gleam/string

import vestibule/error.{type AuthError}
import vestibule/logger
import vestibule/provider_support
import ywt/verify_key.{type VerifyKey}

const apple_jwks_url = "https://appleid.apple.com/auth/keys"

/// Opaque cache for Apple's JWKS keys.
///
/// Backed by a bravo `USet` ETS table, but the underlying storage is hidden
/// so the dependency can be swapped without breaking consumers.
pub opaque type JwksCache {
  JwksCache(table: USet(String, List(VerifyKey)))
}

const cache_key = "apple_jwks"

/// Errors returned by checked JWKS cache operations.
pub type JwksCacheError {
  JwksTableCreateFailed
}

/// Initialize the JWKS cache. Call once per VM at application startup.
pub fn init() -> JwksCache {
  let assert Ok(table) = try_init()
    as "vestibule_apple JWKS cache must be initialized once per VM"
  table
}

/// Initialize a named JWKS cache. Useful for testing.
pub fn init_named(name: String) -> JwksCache {
  let assert Ok(table) = try_init_named(name)
    as "vestibule_apple named JWKS cache must be initialized once per VM"
  table
}

/// Try to initialize the JWKS cache.
pub fn try_init() -> Result(JwksCache, JwksCacheError) {
  try_init_named("vestibule_apple_jwks")
}

/// Try to initialize a named JWKS cache. Returns an error if the table already
/// exists or cannot be created.
pub fn try_init_named(name: String) -> Result(JwksCache, JwksCacheError) {
  case uset.new(name: name, access: bravo.Protected) {
    Ok(table) -> Ok(JwksCache(table: table))
    Error(_) -> Error(JwksTableCreateFailed)
  }
}

/// Get Apple's public verification keys, using cached keys if available.
/// Falls back to fetching from Apple's JWKS endpoint.
pub fn get_keys(cache: JwksCache) -> Result(List(VerifyKey), AuthError(e)) {
  case uset.lookup(from: cache.table, at: cache_key) {
    Ok(keys) -> Ok(keys)
    Error(_) -> {
      use keys <- result.try(fetch_keys())
      let _inserted =
        uset.insert(into: cache.table, key: cache_key, value: keys)
      Ok(keys)
    }
  }
}

/// Force refresh the cached keys from Apple's endpoint.
pub fn refresh_keys(cache: JwksCache) -> Result(List(VerifyKey), AuthError(e)) {
  use keys <- result.try(fetch_keys())
  let _inserted = uset.insert(into: cache.table, key: cache_key, value: keys)
  Ok(keys)
}

/// Fetch Apple's public keys from the JWKS endpoint.
fn fetch_keys() -> Result(List(VerifyKey), AuthError(e)) {
  use req <- result.try(
    request.to(apple_jwks_url)
    |> result.map_error(fn(_) {
      error.config(reason: "Invalid Apple JWKS URL: " <> apple_jwks_url)
    }),
  )
  let req = req |> request.set_header("accept", "application/json")
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("apple"),
    fields: [logger.field("endpoint", "jwks")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(resp) -> {
      use body <- result.try(
        provider_support.check_response_status_for_endpoint(
          resp,
          provider_name: "apple",
          endpoint: "jwks",
        )
        |> result.map_error(fn(err) {
          case error.kind(err) {
            error.HttpKind -> error.network(reason: error.message(err))
            _ -> err
          }
        }),
      )
      parse_jwks(body)
    }
    Error(_) -> {
      logger.new(
        level: logger.Error,
        event: "vestibule.provider.request.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: option.Some("apple"),
        fields: [
          logger.field("endpoint", "jwks"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.network(
        reason: "Failed to fetch Apple JWKS from " <> apple_jwks_url,
      ))
    }
  }
}

/// Parse a JWKS JSON response into a list of verification keys.
pub fn parse_jwks(body: String) -> Result(List(VerifyKey), AuthError(e)) {
  case json.parse(body, verify_key.set_decoder()) {
    Ok(keys) -> Ok(keys)
    Error(err) ->
      Error(error.config(
        reason: "Failed to parse Apple JWKS response: " <> string.inspect(err),
      ))
  }
}
