import bravo
import bravo/uset
import gleam/bit_array
import gleam/crypto
import gleam/order
import gleam/time/duration
import gleam/time/timestamp

const default_ttl_seconds = 600

/// The state store table.
///
/// The concrete storage implementation is intentionally opaque so the public
/// API can evolve without exposing the underlying table representation.
pub opaque type StateStore {
  StateStore(table: uset.USet(String, SessionState))
}

type SessionState {
  SessionState(
    state: String,
    code_verifier: String,
    expires_at: timestamp.Timestamp,
  )
}

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
    Ok(table) -> Ok(StateStore(table))
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
  try_store_with_ttl(table, state, code_verifier, default_ttl_seconds)
}

/// Try to store a CSRF state value and PKCE verifier with a TTL, returning a
/// session ID.
pub fn try_store_with_ttl(
  table: StateStore,
  state: String,
  code_verifier: String,
  ttl_seconds: Int,
) -> Result(String, StateStoreError) {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  let expires_at =
    timestamp.system_time()
    |> timestamp.add(duration.seconds(ttl_seconds))
  case
    uset.insert(
      into: table.table,
      key: session_id,
      value: SessionState(state:, code_verifier:, expires_at:),
    )
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
  case uset.take(from: table.table, at: session_id) {
    Ok(session) -> validate_session(session)
    Error(_) -> Error(Nil)
  }
}

/// Look up a CSRF state and code verifier by session ID without consuming it.
///
/// Expired sessions are treated as missing and removed from the store.
pub fn peek(
  table: StateStore,
  session_id: String,
) -> Result(#(String, String), Nil) {
  case uset.lookup(from: table.table, at: session_id) {
    Ok(session) -> {
      case validate_session(session) {
        Ok(value) -> Ok(value)
        Error(Nil) -> {
          let _ = uset.delete_key(from: table.table, at: session_id)
          Error(Nil)
        }
      }
    }
    Error(_) -> Error(Nil)
  }
}

fn validate_session(session: SessionState) -> Result(#(String, String), Nil) {
  let SessionState(state:, code_verifier:, expires_at:) = session
  case timestamp.compare(timestamp.system_time(), expires_at) {
    order.Lt -> Ok(#(state, code_verifier))
    _ -> Error(Nil)
  }
}
