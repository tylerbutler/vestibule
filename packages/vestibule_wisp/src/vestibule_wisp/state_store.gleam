import gleam/bit_array
import gleam/crypto

const table_name = "vestibule_wisp_sessions"

/// Initialize the state store. Call once at application startup.
/// Safe to call multiple times.
pub fn init() -> Nil {
  do_create_table(table_name)
}

/// Store a CSRF state value and return a session ID.
pub fn store(state: String) -> String {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  do_insert(table_name, session_id, state)
  session_id
}

/// Retrieve and consume a CSRF state by session ID.
/// Returns Error(Nil) if not found or already consumed (one-time use).
pub fn retrieve(session_id: String) -> Result(String, Nil) {
  case do_lookup(table_name, session_id) {
    Ok(value) -> {
      do_delete(table_name, session_id)
      Ok(value)
    }
    Error(Nil) -> Error(Nil)
  }
}

@external(erlang, "vestibule_wisp_state_store_ffi", "create_table")
fn do_create_table(name: String) -> Nil

@external(erlang, "vestibule_wisp_state_store_ffi", "insert")
fn do_insert(name: String, key: String, value: String) -> Nil

@external(erlang, "vestibule_wisp_state_store_ffi", "lookup")
fn do_lookup(name: String, key: String) -> Result(String, Nil)

@external(erlang, "vestibule_wisp_state_store_ffi", "delete_key")
fn do_delete(name: String, key: String) -> Nil
