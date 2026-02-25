/// Internal ETS-backed cache for passing Apple ID tokens from
/// exchange_code to fetch_user.
///
/// Apple's token response includes an `id_token` JWT that contains user info,
/// but the Strategy type's fetch_user only receives Credentials. This cache
/// bridges the gap by storing the id_token during exchange_code, keyed by
/// the access_token, so fetch_user can retrieve and decode it.
const table_name = "vestibule_apple_id_tokens"

/// Initialize the ID token cache. Call once at application startup.
/// Safe to call multiple times.
pub fn init() -> Nil {
  do_create_table(table_name)
}

/// Store an ID token, keyed by access token.
pub fn store(access_token: String, id_token: String) -> Nil {
  do_insert(table_name, access_token, id_token)
}

/// Retrieve and consume an ID token by access token.
/// Returns Error(Nil) if not found or already consumed (one-time use).
pub fn retrieve(access_token: String) -> Result(String, Nil) {
  case do_lookup(table_name, access_token) {
    Ok(value) -> {
      do_delete(table_name, access_token)
      Ok(value)
    }
    Error(Nil) -> Error(Nil)
  }
}

@external(erlang, "vestibule_apple_id_token_cache_ffi", "create_table")
fn do_create_table(name: String) -> Nil

@external(erlang, "vestibule_apple_id_token_cache_ffi", "insert")
fn do_insert(name: String, key: String, value: String) -> Nil

@external(erlang, "vestibule_apple_id_token_cache_ffi", "lookup")
fn do_lookup(name: String, key: String) -> Result(String, Nil)

@external(erlang, "vestibule_apple_id_token_cache_ffi", "delete_key")
fn do_delete(name: String, key: String) -> Nil
