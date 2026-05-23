//// Single-use storage for in-flight OAuth flow state (CSRF `state` and
//// PKCE `code_verifier`). Entries are deleted on first read to prevent
//// replay.
////
//// This is the shared store used by transport packages (`vestibule_wisp`,
//// `vestibule_mist`, etc.). Applications that load more than one
//// transport share a single ETS owner process and may share a store.

import gleam/bit_array
import gleam/crypto
import gleam/order
import gleam/result
import gleam/time/duration
import gleam/time/timestamp

const default_ttl_seconds = 600

/// The state store table.
///
/// The concrete storage implementation is intentionally opaque so the public
/// API can evolve without exposing the underlying table representation.
pub opaque type StateStore {
  StateStore(table: EtsTable)
}

type EtsTable

type SessionState {
  SessionState(
    state: String,
    code_verifier: String,
    expires_at: timestamp.Timestamp,
  )
}

/// Errors returned by checked state store operations.
pub type StateStoreError {
  OwnerUnavailable
  OperationTimedOut
  TableAlreadyExists
  TableCreateFailed
  TableNotFound
  InsertFailed
  CleanupFailed
}

/// Initialize the state store. Call once per VM at application startup.
/// Returns the table handle needed by store/retrieve.
pub fn init() -> StateStore {
  let assert Ok(table) = try_init()
    as "vestibule state store must be initialized once per VM"
  table
}

/// Initialize a named state store. Useful for testing with isolated tables.
pub fn init_named(name: String) -> StateStore {
  let assert Ok(table) = try_init_named(name)
    as "vestibule named state store must be initialized once per VM"
  table
}

/// Try to initialize the state store.
pub fn try_init() -> Result(StateStore, StateStoreError) {
  try_init_named("vestibule_sessions")
}

/// Try to initialize a named state store. Returns `Error(TableAlreadyExists)`
/// if the table already exists, or another `StateStoreError` if the owner
/// process or ETS operation fails.
pub fn try_init_named(name: String) -> Result(StateStore, StateStoreError) {
  case create_table(name) {
    Ok(table) -> Ok(StateStore(table))
    Error(reason) -> Error(map_create_error(reason))
  }
}

/// Store a CSRF state value and PKCE code verifier, returning a session ID.
pub fn store(
  table: StateStore,
  state: String,
  code_verifier: String,
) -> String {
  let assert Ok(session_id) = try_store(table, state, code_verifier)
    as "vestibule failed to store OAuth session state"
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
  use _ <- result.try(
    cleanup_expired(table.table, timestamp.system_time())
    |> result.map_error(map_cleanup_error),
  )

  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  let expires_at =
    timestamp.system_time()
    |> timestamp.add(duration.seconds(ttl_seconds))

  case
    insert(
      table.table,
      session_id,
      SessionState(state:, code_verifier:, expires_at:),
    )
  {
    Ok(Nil) -> Ok(session_id)
    Error(reason) -> Error(map_insert_error(reason))
  }
}

/// Consume a CSRF state and code verifier by session ID.
///
/// Returns `Error(Nil)` if not found, expired, or already consumed.
pub fn consume(
  table: StateStore,
  session_id: String,
) -> Result(#(String, String), Nil) {
  case take(table.table, session_id) {
    Ok(session) -> validate_session(session)
    Error(_) -> Error(Nil)
  }
}

/// Retrieve and consume a CSRF state and code verifier by session ID.
///
/// Alias for `consume`. Returns `Error(Nil)` if not found, expired, or already
/// consumed.
pub fn retrieve(
  table: StateStore,
  session_id: String,
) -> Result(#(String, String), Nil) {
  consume(table, session_id)
}

/// Look up a CSRF state and code verifier by session ID without consuming it.
///
/// Expired sessions are treated as missing and removed from the store.
pub fn peek(
  table: StateStore,
  session_id: String,
) -> Result(#(String, String), Nil) {
  case lookup(table.table, session_id) {
    Ok(session) -> {
      case validate_session(session) {
        Ok(value) -> Ok(value)
        Error(Nil) -> {
          let _ = delete_key(table.table, session_id)
          let _ = cleanup_expired(table.table, timestamp.system_time())
          Error(Nil)
        }
      }
    }
    Error(_) -> Error(Nil)
  }
}

fn map_create_error(reason: String) -> StateStoreError {
  case reason {
    "owner_init_failed" | "owner_unavailable" -> OwnerUnavailable
    "timeout" -> OperationTimedOut
    "table_already_exists" -> TableAlreadyExists
    "table_not_found" -> TableNotFound
    _ -> TableCreateFailed
  }
}

fn map_insert_error(reason: String) -> StateStoreError {
  case reason {
    "owner_init_failed" | "owner_unavailable" -> OwnerUnavailable
    "timeout" -> OperationTimedOut
    "table_not_found" -> TableNotFound
    _ -> InsertFailed
  }
}

fn map_cleanup_error(reason: String) -> StateStoreError {
  case reason {
    "owner_init_failed" | "owner_unavailable" -> OwnerUnavailable
    "timeout" -> OperationTimedOut
    "table_not_found" -> TableNotFound
    _ -> CleanupFailed
  }
}

fn validate_session(session: SessionState) -> Result(#(String, String), Nil) {
  let SessionState(state:, code_verifier:, expires_at:) = session
  case timestamp.compare(timestamp.system_time(), expires_at) {
    order.Lt -> Ok(#(state, code_verifier))
    _ -> Error(Nil)
  }
}

// Direct ETS FFI keeps this package Hex-publishable while Bravo's Hex release
// is incompatible with current Gleam dependencies. Prefer replacing this with
// Bravo again once a compatible Bravo version is available on Hex.
@external(erlang, "vestibule_state_store_ffi", "create_table")
fn create_table(name: String) -> Result(EtsTable, String)

@external(erlang, "vestibule_state_store_ffi", "insert")
fn insert(
  table: EtsTable,
  key: String,
  value: SessionState,
) -> Result(Nil, String)

@external(erlang, "vestibule_state_store_ffi", "take")
fn take(table: EtsTable, key: String) -> Result(SessionState, String)

@external(erlang, "vestibule_state_store_ffi", "lookup")
fn lookup(table: EtsTable, key: String) -> Result(SessionState, String)

@external(erlang, "vestibule_state_store_ffi", "delete_key")
fn delete_key(table: EtsTable, key: String) -> Result(Nil, String)

@external(erlang, "vestibule_state_store_ffi", "cleanup_expired")
fn cleanup_expired(
  table: EtsTable,
  now: timestamp.Timestamp,
) -> Result(Int, String)
