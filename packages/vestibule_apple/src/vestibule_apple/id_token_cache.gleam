/// Internal ETS-backed cache for passing Apple ID tokens from
/// exchange_code to fetch_user.
///
/// Apple's token response includes an `id_token` JWT that contains user info,
/// but the Strategy type's fetch_user only receives Credentials. This cache
/// bridges the gap by storing the id_token during exchange_code so fetch_user
/// can retrieve and decode it.
///
/// Security: Uses a cryptographically random cache key (not the access token)
/// to prevent cache manipulation by anyone who obtains the access token.
/// A Private key-mapping table ensures only the owning process can resolve
/// access tokens to cache keys. Uses atomic `uset.take` for one-time
/// retrieval (no TOCTOU race).
import gleam/bit_array
import gleam/crypto

import bravo
import bravo/uset.{type USet}

/// The cache table type. Stores (random_key -> id_token) mappings.
pub type IdTokenCache {
  IdTokenCache(
    /// Stores id_token data keyed by random cache key.
    tokens: USet(String, String),
    /// Maps access_token -> random cache key. Private access so only
    /// the owning process can read/write.
    keys: USet(String, String),
  )
}

/// Errors returned by checked ID token cache operations.
pub type CacheError {
  TokenTableCreateFailed
  KeyTableCreateFailed
  TokenStoreFailed
  KeyStoreFailed
}

/// Initialize the ID token cache. Call once per VM at application startup.
/// Returns the cache handle needed by store/retrieve.
pub fn init() -> IdTokenCache {
  let assert Ok(cache) = try_init()
    as "vestibule_apple ID token cache must be initialized once per VM"
  cache
}

/// Initialize a named ID token cache. Useful for testing with isolated tables.
pub fn init_named(name: String) -> IdTokenCache {
  let assert Ok(cache) = try_init_named(name)
    as "vestibule_apple named ID token cache must be initialized once per VM"
  cache
}

/// Try to initialize the ID token cache.
pub fn try_init() -> Result(IdTokenCache, CacheError) {
  try_init_named("vestibule_apple_id_token")
}

/// Try to initialize a named ID token cache. Returns an error if either
/// backing table already exists or cannot be created.
pub fn try_init_named(name: String) -> Result(IdTokenCache, CacheError) {
  case uset.new(name: name <> "_tokens", access: bravo.Protected) {
    Ok(tokens) -> {
      case uset.new(name: name <> "_keys", access: bravo.Private) {
        Ok(keys) -> Ok(IdTokenCache(tokens: tokens, keys: keys))
        Error(_) -> {
          let _ = uset.delete(tokens)
          Error(KeyTableCreateFailed)
        }
      }
    }
    Error(_) -> Error(TokenTableCreateFailed)
  }
}

/// Generate a cryptographically random cache key.
fn generate_cache_key() -> String {
  crypto.strong_random_bytes(32)
  |> bit_array.base64_url_encode(False)
}

/// Store an ID token under a random cache key, mapped from the access token.
/// Returns Nil.
pub fn store(
  cache: IdTokenCache,
  access_token: String,
  id_token: String,
) -> Nil {
  let assert Ok(_) = try_store(cache, access_token, id_token)
    as "vestibule_apple failed to store ID token"
  Nil
}

/// Try to store an ID token under a random cache key, mapped from the access token.
pub fn try_store(
  cache: IdTokenCache,
  access_token: String,
  id_token: String,
) -> Result(Nil, CacheError) {
  let cache_key = generate_cache_key()
  case uset.insert(into: cache.tokens, key: cache_key, value: id_token) {
    Ok(Nil) -> {
      case uset.insert(into: cache.keys, key: access_token, value: cache_key) {
        Ok(Nil) -> Ok(Nil)
        Error(_) -> {
          let _ = uset.delete_key(from: cache.tokens, at: cache_key)
          Error(KeyStoreFailed)
        }
      }
    }
    Error(_) -> Error(TokenStoreFailed)
  }
}

/// Retrieve and consume an ID token by access token.
/// Returns Error(Nil) if not found or already consumed.
/// Uses atomic take to prevent TOCTOU race conditions.
pub fn retrieve(
  cache: IdTokenCache,
  access_token: String,
) -> Result(String, Nil) {
  // Look up the random cache key from the access token (Private table)
  case uset.take(from: cache.keys, at: access_token) {
    Ok(cache_key) -> {
      // Use the random cache key to retrieve the id_token
      case uset.take(from: cache.tokens, at: cache_key) {
        Ok(value) -> Ok(value)
        Error(_) -> Error(Nil)
      }
    }
    Error(_) -> Error(Nil)
  }
}
