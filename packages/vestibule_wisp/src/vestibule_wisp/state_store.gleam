import bravo
import bravo/uset.{type USet}
import gleam/bit_array
import gleam/crypto

/// The type alias for the state store table.
pub type StateStore =
  USet(String, #(String, String))

/// Errors returned by checked state store operations.
pub type StateStoreError {
  TableCreateFailed
  InsertFailed
}

/// Initialize the state store. Call once per VM at application startup.
/// Returns the table handle needed by store/retrieve.
pub fn init() -> StateStore {
  let assert Ok(table) = try_init()
    as "vestibule_wisp state store must be initialized once per VM"
  table
}

/// Initialize a named state store. Useful for testing with isolated tables.
pub fn init_named(name: String) -> StateStore {
  let assert Ok(table) = try_init_named(name)
    as "vestibule_wisp named state store must be initialized once per VM"
  table
}

/// Try to initialize the state store.
pub fn try_init() -> Result(StateStore, StateStoreError) {
  try_init_named("vestibule_wisp_sessions")
}

/// Try to initialize a named state store. Returns `Error(TableCreateFailed)`
/// if the table already exists or cannot be created.
pub fn try_init_named(name: String) -> Result(StateStore, StateStoreError) {
  case uset.new(name: name, access: bravo.Protected) {
    Ok(table) -> Ok(table)
    Error(_) -> Error(TableCreateFailed)
  }
}

/// Store a CSRF state value and PKCE code verifier, returning a session ID.
pub fn store(
  table: StateStore,
  state: String,
  code_verifier: String,
) -> String {
  let assert Ok(session_id) = try_store(table, state, code_verifier)
    as "vestibule_wisp failed to store OAuth session state"
  session_id
}

/// Try to store a CSRF state value and PKCE code verifier, returning a session ID.
pub fn try_store(
  table: StateStore,
  state: String,
  code_verifier: String,
) -> Result(String, StateStoreError) {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  case
    uset.insert(into: table, key: session_id, value: #(state, code_verifier))
  {
    Ok(Nil) -> Ok(session_id)
    Error(_) -> Error(InsertFailed)
  }
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
