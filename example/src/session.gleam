import gleam/bit_array
import gleam/crypto

const table_name = "vestibule_sessions"

/// Create the ETS table for session storage.
/// Call once at app startup. Safe to call multiple times.
pub fn create_table() -> Nil {
  do_create_table(table_name)
}

/// Store a CSRF state value and return the session ID.
pub fn store_state(state: String) -> String {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  do_insert(table_name, session_id, state)
  session_id
}

/// Retrieve and delete a CSRF state by session ID.
/// Returns Error(Nil) if not found (one-time use).
pub fn get_state(session_id: String) -> Result(String, Nil) {
  case do_lookup(table_name, session_id) {
    Ok(value) -> {
      do_delete(table_name, session_id)
      Ok(value)
    }
    Error(Nil) -> Error(Nil)
  }
}

@external(erlang, "session_ffi", "create_table")
fn do_create_table(name: String) -> Nil

@external(erlang, "session_ffi", "insert")
fn do_insert(name: String, key: String, value: String) -> Nil

@external(erlang, "session_ffi", "lookup")
fn do_lookup(name: String, key: String) -> Result(String, Nil)

@external(erlang, "session_ffi", "delete_key")
fn do_delete(name: String, key: String) -> Nil
