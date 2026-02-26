/// Internal ETS-backed cache for passing Apple ID tokens from
/// exchange_code to fetch_user.
///
/// Apple's token response includes an `id_token` JWT that contains user info,
/// but the Strategy type's fetch_user only receives Credentials. This cache
/// bridges the gap by storing the id_token during exchange_code, keyed by
/// the access_token, so fetch_user can retrieve and decode it.
///
/// Security: Uses bravo with Protected access (only the owning process can
/// write) and atomic `uset.take` for one-time retrieval (no TOCTOU race).
import bravo
import bravo/uset.{type USet}

/// The cache table type. Stores (access_token -> id_token) mappings.
pub type IdTokenCache =
  USet(String, String)

/// Initialize the ID token cache. Call once at application startup.
/// Returns the cache handle needed by store/retrieve.
pub fn init() -> IdTokenCache {
  let assert Ok(table) =
    uset.new(name: "vestibule_apple_id_tokens", access: bravo.Protected)
  table
}

/// Initialize a named ID token cache. Useful for testing with isolated tables.
pub fn init_named(name: String) -> IdTokenCache {
  let assert Ok(table) = uset.new(name: name, access: bravo.Protected)
  table
}

/// Store an ID token, keyed by access token.
pub fn store(cache: IdTokenCache, access_token: String, id_token: String) -> Nil {
  let _ = uset.insert(into: cache, key: access_token, value: id_token)
  Nil
}

/// Retrieve and consume an ID token by access token.
/// Returns Error(Nil) if not found or already consumed.
/// Uses atomic take to prevent TOCTOU race conditions.
pub fn retrieve(
  cache: IdTokenCache,
  access_token: String,
) -> Result(String, Nil) {
  case uset.take(from: cache, at: access_token) {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Nil)
  }
}
