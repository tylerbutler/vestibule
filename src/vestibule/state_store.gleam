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
//// live entries (`create_with_capacity`, default 4 096), and a store
//// that is full refuses new flows with `StoreFull` rather than growing.
//// Transport integrations also use `store_for_client_with_ttl`, which admits
//// at most eight live flows per direct client by default. Admission and
//// insertion are one owner-process operation: rejected requests store
//// nothing, and existing sessions remain available.
//// Expired entries are rejected on read, reclaimed on demand when the store
//// is at capacity, and swept periodically by the owner process; inserts
//// themselves are O(1). Expiration uses the BEAM monotonic clock, so wall
//// clock corrections cannot revive or prematurely expire a flow. Rate-limit
//// the request endpoint upstream if you need stronger traffic controls.
////
//// State, PKCE verifier, and nonce values are closure-wrapped while stored,
//// so ordinary Gleam inspection and Erlang term formatting do not print
//// them. This reduces accidental disclosure; it does not erase BEAM memory
//// or protect VM dumps.

import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/option.{type Option}
import gleam/result
import vestibule/internal/secret

const default_ttl_seconds = 600

/// Default upper bound on live sessions per store. Each entry is a few
/// hundred bytes, so this keeps the default store within a few megabytes.
pub const default_max_entries = 4096

/// Default upper bound on live sessions attributed to one client.
pub const default_max_entries_per_client = 8

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
    state: secret.Secret,
    code_verifier: secret.Secret,
    nonce: Option(secret.Secret),
    expires_at: Int,
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
  /// `create_with_limits` was given a per-client limit of zero or less.
  InvalidClientCapacity
  /// This client already has the maximum number of live sessions.
  ClientLimitReached
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
  create_with_limits(
    name: name,
    max_entries: max_entries,
    max_entries_per_client: default_max_entries_per_client,
  )
}

/// Create a named store with explicit global and per-client live-session
/// limits. Transport adapters apply both limits before state is inserted.
pub fn create_with_limits(
  name name: String,
  max_entries max_entries: Int,
  max_entries_per_client max_entries_per_client: Int,
) -> Result(StateStore, StateStoreError) {
  use <- bool.guard(when: max_entries <= 0, return: Error(InvalidCapacity))
  use <- bool.guard(
    when: max_entries_per_client <= 0,
    return: Error(InvalidClientCapacity),
  )
  case create_table(name, max_entries, max_entries_per_client) {
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
/// called with the same value. This low-level function applies only the global
/// hard bound. HTTP entry points should use `store_for_client`.
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

/// Store a flow after atomically applying the store's admission limits for
/// `client_key`.
pub fn store_for_client(
  table: StateStore,
  client_key client_key: String,
  provider provider: String,
  state state: String,
  code_verifier code_verifier: String,
  nonce nonce: Option(String),
) -> Result(String, StateStoreError) {
  store_for_client_with_ttl(
    table,
    client_key: client_key,
    provider: provider,
    state: state,
    code_verifier: code_verifier,
    nonce: nonce,
    ttl_seconds: default_ttl_seconds,
  )
}

/// Store a CSRF state value, PKCE verifier, and optional OIDC nonce for a
/// flow started with `provider`, with a TTL, returning a session ID. This
/// low-level function applies only the global hard bound.
pub fn store_with_ttl(
  table: StateStore,
  provider provider: String,
  state state: String,
  code_verifier code_verifier: String,
  nonce nonce: Option(String),
  ttl_seconds ttl_seconds: Int,
) -> Result(String, StateStoreError) {
  do_store(
    table,
    client_key: "",
    provider: provider,
    state: state,
    code_verifier: code_verifier,
    nonce: nonce,
    ttl_seconds: ttl_seconds,
  )
}

/// Store a flow after atomically applying the store's per-client and global
/// admission limits. `client_key` must identify the direct peer, not an
/// untrusted forwarded header. An empty key is treated as an unclassified
/// shared client and is still limited.
pub fn store_for_client_with_ttl(
  table: StateStore,
  client_key client_key: String,
  provider provider: String,
  state state: String,
  code_verifier code_verifier: String,
  nonce nonce: Option(String),
  ttl_seconds ttl_seconds: Int,
) -> Result(String, StateStoreError) {
  let client_key = case client_key {
    "" -> "unidentified"
    key -> key
  }
  do_store(
    table,
    client_key: client_key,
    provider: provider,
    state: state,
    code_verifier: code_verifier,
    nonce: nonce,
    ttl_seconds: ttl_seconds,
  )
}

fn do_store(
  table: StateStore,
  client_key client_key: String,
  provider provider: String,
  state state: String,
  code_verifier code_verifier: String,
  nonce nonce: Option(String),
  ttl_seconds ttl_seconds: Int,
) -> Result(String, StateStoreError) {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  let expires_at = monotonic_seconds() + ttl_seconds
  let state = secret.from_string(state)
  let code_verifier = secret.from_string(code_verifier)
  let nonce = option.map(nonce, secret.from_string)

  case
    insert(
      table.table,
      session_id,
      client_key,
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
/// for a different `provider`. Provider matching, expiration checking, and
/// removal happen in one owner-process operation. A wrong-provider attempt
/// cannot read or consume another provider's session.
pub fn consume(
  table: StateStore,
  session_id: String,
  provider provider: String,
) -> Result(#(String, String, Option(String)), Nil) {
  case take_for_provider(table.table, session_id, provider) {
    Ok(SessionState(state:, code_verifier:, nonce:, ..)) ->
      Ok(#(
        secret.expose(state),
        secret.expose(code_verifier),
        option.map(nonce, secret.expose),
      ))
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
    "client_limit_reached" -> ClientLimitReached
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
    False ->
      Ok(#(
        secret.expose(state),
        secret.expose(code_verifier),
        option.map(nonce, secret.expose),
      ))
  }
}

fn is_expired(session: SessionState) -> Bool {
  monotonic_seconds() >= session.expires_at
}

// Direct ETS FFI keeps this package Hex-publishable while Bravo's Hex release
// is incompatible with current Gleam dependencies. Prefer replacing this with
// Bravo again once a compatible Bravo version is available on Hex.
@external(erlang, "vestibule_state_store_ffi", "create_table")
fn create_table(
  name: String,
  max_entries: Int,
  max_entries_per_client: Int,
) -> Result(EtsTable, String)

@external(erlang, "vestibule_state_store_ffi", "insert")
fn insert(
  table: EtsTable,
  key: String,
  client_key: String,
  value: SessionState,
) -> Result(Nil, String)

@external(erlang, "vestibule_state_store_ffi", "take_for_provider")
fn take_for_provider(
  table: EtsTable,
  key: String,
  provider: String,
) -> Result(SessionState, String)

@external(erlang, "vestibule_state_store_ffi", "lookup")
fn lookup(table: EtsTable, key: String) -> Result(SessionState, String)

@external(erlang, "vestibule_state_store_ffi", "delete_key")
fn delete_key(table: EtsTable, key: String) -> Result(Nil, String)

@external(erlang, "vestibule_state_store_ffi", "cleanup_expired")
fn cleanup_expired(table: EtsTable) -> Result(Int, String)

@external(erlang, "vestibule_state_store_ffi", "monotonic_seconds")
fn monotonic_seconds() -> Int
