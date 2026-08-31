//// Apple JWKS (JSON Web Key Set) fetching and caching.
////
//// Fetches Apple's public keys from `https://appleid.apple.com/auth/keys`
//// and caches them in a bravo ETS table for reuse. Keys are used to verify
//// the signature of Apple's ID token JWTs.

import bravo
import bravo/uset.{type USet}
import gleam/dynamic/decode
import gleam/http/request
import gleam/http/response
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
  /// The ETS table backing the cache could not be created (for example
  /// because it already exists). `reason` describes the underlying storage
  /// error to aid debugging.
  JwksTableCreationFailed(reason: String)
}

/// Initialize the JWKS cache. Call once per VM at application startup.
pub fn initialize() -> Result(JwksCache, JwksCacheError) {
  initialize_named("vestibule_apple_jwks")
}

/// Initialize a named JWKS cache. Returns an error if the table already
/// exists or cannot be created.
pub fn initialize_named(name: String) -> Result(JwksCache, JwksCacheError) {
  case uset.new(name: name, access: bravo.Protected) {
    Ok(table) -> Ok(JwksCache(table: table))
    Error(storage_error) ->
      Error(JwksTableCreationFailed(reason: string.inspect(storage_error)))
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

/// Build the request for Apple's JWKS endpoint without sending it.
pub fn build_jwks_request() -> Result(request.Request(String), AuthError(e)) {
  use apple_request <- result.try(
    request.to(apple_jwks_url)
    |> result.map_error(fn(_) {
      error.config(reason: "Invalid Apple JWKS URL: " <> apple_jwks_url)
    }),
  )
  Ok(request.set_header(apple_request, "accept", "application/json"))
}

/// Parse an Apple JWKS HTTP response without performing I/O.
pub fn parse_jwks_response(
  apple_response: response.Response(String),
) -> Result(List(VerifyKey), AuthError(e)) {
  use body <- result.try(
    provider_support.check_response_status(apple_response)
    |> result.map_error(fn(authentication_error) {
      case error.kind(authentication_error) {
        error.HttpKind ->
          error.network(reason: error.message(authentication_error))
        error.StateMismatchKind
        | error.InvalidNonceKind
        | error.MissingCallbackParamKind
        | error.CodeExchangeKind
        | error.UserInfoKind
        | error.ProviderKind
        | error.DecodeKind
        | error.NetworkKind
        | error.ConfigKind
        | error.RefreshUnsupportedKind
        | error.CustomKind
        | error.OtherKind -> authentication_error
      }
    }),
  )
  parse_jwks(body)
}

/// Fetch Apple's public keys from the JWKS endpoint.
fn fetch_keys() -> Result(List(VerifyKey), AuthError(e)) {
  use apple_request <- result.try(build_jwks_request())
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("apple"),
    fields: [logger.field("endpoint", "jwks")],
  )
  |> logger.emit()
  case httpc.send(apple_request) {
    Ok(apple_response) -> parse_jwks_response(apple_response)
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
  case json.parse(body, apple_jwks_decoder()) {
    Ok(Nil) ->
      json.parse(body, verify_key.set_decoder())
      |> result.map_error(fn(decode_error) {
        error.config(
          reason: "Failed to parse Apple JWKS response: "
          <> string.inspect(decode_error),
        )
      })
    Error(decode_error) ->
      Error(error.config(
        reason: "Failed to parse Apple JWKS response: "
        <> string.inspect(decode_error),
      ))
  }
}

fn apple_jwks_decoder() -> decode.Decoder(Nil) {
  use _keys <- decode.field("keys", decode.list(apple_jwk_decoder()))
  decode.success(Nil)
}

fn apple_jwk_decoder() -> decode.Decoder(Nil) {
  use key_type <- decode.field("kty", decode.string)
  use algorithm <- decode.field("alg", decode.string)
  use usage <- decode.optional_field("use", "sig", decode.string)
  case key_type, algorithm, usage {
    "RSA", "RS256", "sig" -> decode.success(Nil)
    _, _, _ ->
      decode.failure(
        Nil,
        "Apple JWKS keys must be RSA signing keys using RS256",
      )
  }
}
