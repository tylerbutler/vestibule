import bravo
import bravo/uset.{type USet}
import gleam/bit_array
import gleam/crypto

/// The type alias for the state store table.
pub type StateStore =
  USet(String, #(String, String))

/// Initialize the state store. Call once at application startup.
/// Returns the table handle needed by store/retrieve.
pub fn init() -> StateStore {
  let assert Ok(table) =
    uset.new(name: "vestibule_wisp_sessions", access: bravo.Public)
  table
}

/// Initialize a named state store. Useful for testing with isolated tables.
pub fn init_named(name: String) -> StateStore {
  let assert Ok(table) = uset.new(name: name, access: bravo.Public)
  table
}

/// Store a CSRF state value and PKCE code verifier, returning a session ID.
pub fn store(table: StateStore, state: String, code_verifier: String) -> String {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  let assert Ok(Nil) =
    uset.insert(into: table, key: session_id, value: #(state, code_verifier))
  session_id
}

/// Retrieve and consume a CSRF state and code verifier by session ID.
/// Returns Error(Nil) if not found or already consumed (one-time use).
pub fn retrieve(
  table: StateStore,
  session_id: String,
) -> Result(#(String, String), Nil) {
  case uset.take(from: table, at: session_id) {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Nil)
  }
}
