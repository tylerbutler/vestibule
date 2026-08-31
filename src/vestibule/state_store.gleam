//// Single-use storage for in-flight OAuth flow state (CSRF `state` and
//// PKCE `code_verifier`). Entries are deleted on first read to prevent
//// replay.
////
//// Every entry is bound to the provider that started the flow, and reading
//// it back requires naming the same provider. Without that binding a
//// session minted for provider A would satisfy provider B's callback,
//// letting an attacker-controlled provider redirect the browser to another
//// provider's callback with the still-valid `state` (an OAuth mix-up attack
//// that ends in login CSRF or account-linking takeover).
////
//// This is the shared store used by transport packages (`vestibule_wisp`,
//// `vestibule_mist`, etc.). Applications that load more than one
//// transport share a single ETS owner process and may share a store.
////
//// The owner process is started lazily and is not supervised. If it dies,
//// every in-flight session is lost (those logins fail and users retry), but
//// the store heals itself: the next operation on an existing handle
//// respawns the owner and recreates the table with the same capacity, so a
//// crash never leaves authentication broken until the VM restarts.
////
//// ## Capacity and expiry
////
//// Starting a flow is an unauthenticated operation, so the store bounds
//// what a client can pin in memory: every store has a maximum number of
//// live entries (`create_with_capacity`, default 100 000), and a store
//// that is full refuses new flows with `StoreFull` rather than growing.
//// Expired entries are rejected on read, reclaimed on demand when the store
//// is at capacity, and swept periodically by the owner process; inserts
//// themselves are O(1). Rate-limit the request endpoint upstream if you
//// need a stronger guarantee than the capacity cap provides.

import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/option.{type Option}
import gleam/order
import gleam/result
import gleam/time/duration
import gleam/time/timestamp

const default_ttl_seconds = 600

/// Default upper bound on live sessions per store. Each entry is a few
/// hundred bytes, so this caps a store at roughly tens of megabytes.
const default_max_entries = 100_000

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
    provider: String,
    state: String,
    code_verifier: String,
    nonce: Option(String),
    expires_at: timestamp.Timestamp,
  )
}

/// Errors returned by checked state store operations.
///
/// The `reason` fields carry the raw failure reason reported by the
/// underlying ETS owner process, to aid debugging failures that do not map
/// to a more specific variant.
pub type StateStoreError {
  OwnerUnavailable
  OperationTimedOut
  TableAlreadyExists
  TableCreateFailed(reason: String)
  TableNotFound
  InsertFailed(reason: String)
  CleanupFailed(reason: String)
  /// The store holds `max_entries` live sessions and no expired ones could
  /// be reclaimed. New flows are refused until sessions are consumed or
  /// expire.
  StoreFull
  /// `create_with_capacity` was given a `max_entries` of zero or less.
  InvalidCapacity
}

/// Create the state store. Call once per VM at application startup; the
/// returned table handle is needed by `store` and `consume`.
pub fn create() -> Result(StateStore, StateStoreError) {
  create_named("vestibule_sessions")
}

/// Create a named state store with the default capacity. Returns
/// `Error(TableAlreadyExists)` if the table already exists, or another
/// `StateStoreError` if the owner process or ETS operation fails.
pub fn create_named(name: String) -> Result(StateStore, StateStoreError) {
  create_with_capacity(name: name, max_entries: default_max_entries)
}

/// Create a named state store that holds at most `max_entries` live
/// sessions. Once full, `store` fails with `StoreFull` until
/// sessions are consumed or expire. Returns `Error(InvalidCapacity)` when
/// `max_entries` is not positive.
pub fn create_with_capacity(
  name name: String,
  max_entries max_entries: Int,
) -> Result(StateStore, StateStoreError) {
  use <- bool.guard(when: max_entries <= 0, return: Error(InvalidCapacity))
  case create_table(name, max_entries) {
    Ok(table) -> Ok(StateStore(table))
    Error(reason) -> Error(map_create_error(reason))
  }
}

/// Remove every expired session from the store now, returning how many were
/// removed. The owner process does this on a timer and on demand when the
/// store is at capacity, so calling it is optional.
pub fn sweep_expired(table: StateStore) -> Result(Int, StateStoreError) {
  cleanup_expired(table.table)
  |> result.map_error(map_cleanup_error)
}

/// Store a CSRF state value, PKCE code verifier, and optional OIDC nonce for
/// a flow started with `provider`, returning a session ID.
///
/// `provider` is the strategy's provider name; `consume` and `peek` must be
/// called with the same value.
pub fn store(
  table: StateStore,
  provider provider: String,
  state state: String,
  code_verifier code_verifier: String,
  nonce nonce: Option(String),
) -> Result(String, StateStoreError) {
  store_with_ttl(
    table,
    provider: provider,
    state: state,
    code_verifier: code_verifier,
    nonce: nonce,
    ttl_seconds: default_ttl_seconds,
  )
}

/// Store a CSRF state value, PKCE verifier, and optional OIDC nonce for a
/// flow started with `provider`, with a TTL, returning a session ID.
pub fn store_with_ttl(
  table: StateStore,
  provider provider: String,
  state state: String,
  code_verifier code_verifier: String,
  nonce nonce: Option(String),
  ttl_seconds ttl_seconds: Int,
) -> Result(String, StateStoreError) {
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
      SessionState(provider:, state:, code_verifier:, nonce:, expires_at:),
    )
  {
    Ok(Nil) -> Ok(session_id)
    Error(reason) -> Error(map_insert_error(reason))
  }
}

/// Consume a CSRF state, code verifier, and optional nonce by session ID.
///
/// Returns `Error(Nil)` if not found, expired, already consumed, or stored
/// for a different `provider`. The entry is removed in every case, so a
/// cross-provider attempt burns the session rather than leaving it usable.
pub fn consume(
  table: StateStore,
  session_id: String,
  provider provider: String,
) -> Result(#(String, String, Option(String)), Nil) {
  case take(table.table, session_id) {
    Ok(session) -> validate_session(session, provider)
    Error(_) -> Error(Nil)
  }
}

/// Look up a CSRF state, code verifier, and optional nonce by session ID
/// without consuming it.
///
/// Expired sessions are treated as missing and removed from the store. A
/// session stored for a different `provider` is treated as missing but left
/// in place, so a wrong-provider probe cannot burn a legitimate in-flight
/// login.
pub fn peek(
  table: StateStore,
  session_id: String,
  provider provider: String,
) -> Result(#(String, String, Option(String)), Nil) {
  case lookup(table.table, session_id) {
    Ok(session) -> {
      case is_expired(session) {
        True -> {
          let _deleted = delete_key(table.table, session_id)
          Error(Nil)
        }
        False -> validate_session(session, provider)
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
    other -> TableCreateFailed(reason: other)
  }
}

fn map_insert_error(reason: String) -> StateStoreError {
  case reason {
    "owner_init_failed" | "owner_unavailable" -> OwnerUnavailable
    "timeout" -> OperationTimedOut
    "table_not_found" -> TableNotFound
    "store_full" -> StoreFull
    other -> InsertFailed(reason: other)
  }
}

fn map_cleanup_error(reason: String) -> StateStoreError {
  case reason {
    "owner_init_failed" | "owner_unavailable" -> OwnerUnavailable
    "timeout" -> OperationTimedOut
    "table_not_found" -> TableNotFound
    other -> CleanupFailed(reason: other)
  }
}

fn validate_session(
  session: SessionState,
  provider: String,
) -> Result(#(String, String, Option(String)), Nil) {
  let SessionState(
    provider: stored_provider,
    state:,
    code_verifier:,
    nonce:,
    ..,
  ) = session
  case is_expired(session) || stored_provider != provider {
    True -> Error(Nil)
    False -> Ok(#(state, code_verifier, nonce))
  }
}

fn is_expired(session: SessionState) -> Bool {
  case timestamp.compare(timestamp.system_time(), session.expires_at) {
    order.Lt -> False
    order.Eq | order.Gt -> True
  }
}

// Direct ETS FFI keeps this package Hex-publishable while Bravo's Hex release
// is incompatible with current Gleam dependencies. Prefer replacing this with
// Bravo again once a compatible Bravo version is available on Hex.
@external(erlang, "vestibule_state_store_ffi", "create_table")
fn create_table(name: String, max_entries: Int) -> Result(EtsTable, String)

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
fn cleanup_expired(table: EtsTable) -> Result(Int, String)
