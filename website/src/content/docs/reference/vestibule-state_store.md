---
title: "vestibule/state_store"
description: "Single-use storage for in-flight OAuth flow state (CSRF `state` and PKCE `code_verifier`). Entries are deleted on first read to prevent replay."
nav:
  group: Reference
  groupOrder: 20
  order: 21
  label: "vestibule/state_store"
toc:
  - href: "#types"
    label: "Types"
  - href: "#constants"
    label: "Constants"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/state_store
---

# `vestibule/state_store`

Single-use storage for in-flight OAuth flow state (CSRF `state` and
PKCE `code_verifier`). Entries are deleted on first read to prevent
replay.

Every entry is bound to the provider that started the flow, and reading
it back requires naming the same provider. Without that binding a
session minted for provider A would satisfy provider B's callback,
letting an attacker-controlled provider redirect the browser to another
provider's callback with the still-valid `state` (an OAuth mix-up attack
that ends in login CSRF or account-linking takeover).

This is the shared store used by transport packages (`vestibule_wisp`,
`vestibule_mist`, etc.). Applications that load more than one
transport share a single ETS owner process and may share a store.

The owner process is started lazily and is not supervised. If it dies,
every in-flight session is lost (those logins fail and users retry), but
the store heals itself: the next operation on an existing handle
respawns the owner and recreates the table with the same capacity, so a
crash never leaves authentication broken until the VM restarts.

## Capacity and expiry

Starting a flow is an unauthenticated operation, so the store bounds
what a client can pin in memory: every store has a maximum number of
live entries (`create_with_capacity`, default 4 096), and a store
that is full refuses new flows with `StoreFull` rather than growing.
Transport integrations also use `store_for_client_with_ttl`, which admits
at most eight live flows per direct client by default. Admission and
insertion are one owner-process operation: rejected requests store
nothing, and existing sessions remain available.
Expired entries are rejected on read, reclaimed on demand when the store
is at capacity, and swept periodically by the owner process; inserts
themselves are O(1). Expiration uses the BEAM monotonic clock, so wall
clock corrections cannot revive or prematurely expire a flow. Rate-limit
the request endpoint upstream if you need stronger traffic controls.

State, PKCE verifier, and nonce values are closure-wrapped while stored,
so ordinary Gleam inspection and Erlang term formatting do not print
them. This reduces accidental disclosure; it does not erase BEAM memory
or protect VM dumps.

## Types

### `SessionLookupError`

Why a stored browser session could not be returned.

```gleam
pub type SessionLookupError {
  SessionMissing
  SessionProviderMismatch
}
```

#### Constructors

##### `SessionMissing`

No live session exists for this identifier.

##### `SessionProviderMismatch`

The session belongs to a different OAuth provider.

### `StateStore`

The state store table.

The concrete storage implementation is intentionally opaque so the public
API can evolve without exposing the underlying table representation.

```gleam
pub type StateStore
```

### `StateStoreError`

Errors returned by checked state store operations.

The `reason` fields carry the raw failure reason reported by the
underlying ETS owner process, to aid debugging failures that do not map
to a more specific variant.

```gleam
pub type StateStoreError {
  OwnerUnavailable
  OperationTimedOut
  TableAlreadyExists
  TableCreateFailed(reason: String)
  TableNotFound
  InsertFailed(reason: String)
  CleanupFailed(reason: String)
  StoreFull
  InvalidCapacity
  InvalidClientCapacity
  ClientLimitReached
}
```

#### Constructors

##### `StoreFull`

The store holds `max_entries` live sessions and no expired ones could
be reclaimed. New flows are refused until sessions are consumed or
expire.

##### `InvalidCapacity`

`create_with_capacity` was given a `max_entries` of zero or less.

##### `InvalidClientCapacity`

`create_with_limits` was given a per-client limit of zero or less.

##### `ClientLimitReached`

This client already has the maximum number of live sessions.

## Constants

### `default_max_entries`

Default upper bound on live sessions per store. Each entry is a few
hundred bytes, so this keeps the default store within a few megabytes.

```gleam
pub const default_max_entries: Int
```

### `default_max_entries_per_client`

Default upper bound on live sessions attributed to one client.

```gleam
pub const default_max_entries_per_client: Int
```

## Functions

### `consume`

Consume a CSRF state, code verifier, and optional nonce by session ID.

Returns `Error(Nil)` if not found, expired, already consumed, or stored
for a different `provider`. Provider matching, expiration checking, and
removal happen in one owner-process operation. A wrong-provider attempt
cannot read or consume another provider's session.

```gleam
pub fn consume(
  StateStore,
  String,
  provider: String
) -> Result(#(String, String, option.Option(String)), Nil)
```

### `create`

Create the state store. Call once per VM at application startup; the
returned table handle is needed by `store` and `consume`.

```gleam
pub fn create() -> Result(StateStore, StateStoreError)
```

### `create_named`

Create a named state store with the default capacity. Returns
`Error(TableAlreadyExists)` if the table already exists, or another
`StateStoreError` if the owner process or ETS operation fails.

```gleam
pub fn create_named(String) -> Result(StateStore, StateStoreError)
```

### `create_with_capacity`

Create a named state store that holds at most `max_entries` live
sessions. Once full, `store` fails with `StoreFull` until
sessions are consumed or expire. Returns `Error(InvalidCapacity)` when
`max_entries` is not positive.

```gleam
pub fn create_with_capacity(
  name: String,
  max_entries: Int
) -> Result(StateStore, StateStoreError)
```

### `create_with_limits`

Create a named store with explicit global and per-client live-session
limits. Transport adapters apply both limits before state is inserted.

```gleam
pub fn create_with_limits(
  name: String,
  max_entries: Int,
  max_entries_per_client: Int
) -> Result(StateStore, StateStoreError)
```

### `peek`

Look up a CSRF state, code verifier, and optional nonce by session ID
without consuming it.

Expired sessions are treated as missing and removed from the store. A
session stored for a different `provider` is treated as missing but left
in place, so a wrong-provider probe cannot burn a legitimate in-flight
login.

```gleam
pub fn peek(
  StateStore,
  String,
  provider: String
) -> Result(#(String, String, option.Option(String)), Nil)
```

### `peek_with_error`

Look up a session without consuming it and preserve provider-mismatch
information. Transport adapters use this to avoid clearing a valid
in-flight cookie when it is presented to another provider's callback.

```gleam
pub fn peek_with_error(
  StateStore,
  String,
  provider: String
) -> Result(#(String, String, option.Option(String)), SessionLookupError)
```

### `store`

Store a CSRF state value, PKCE code verifier, and optional OIDC nonce for
a flow started with `provider`, returning a session ID.

`provider` is the strategy's provider name; `consume` and `peek` must be
called with the same value. This low-level function applies only the global
hard bound. HTTP entry points should use `store_for_client`.

```gleam
pub fn store(
  StateStore,
  provider: String,
  state: String,
  code_verifier: String,
  nonce: option.Option(String)
) -> Result(String, StateStoreError)
```

### `store_for_client`

Store a flow after atomically applying the store's admission limits for
`client_key`.

```gleam
pub fn store_for_client(
  StateStore,
  client_key: String,
  provider: String,
  state: String,
  code_verifier: String,
  nonce: option.Option(String)
) -> Result(String, StateStoreError)
```

### `store_for_client_with_ttl`

Store a flow after atomically applying the store's per-client and global
admission limits. `client_key` must identify the direct peer, not an
untrusted forwarded header. An empty key is treated as an unclassified
shared client and is still limited.

```gleam
pub fn store_for_client_with_ttl(
  StateStore,
  client_key: String,
  provider: String,
  state: String,
  code_verifier: String,
  nonce: option.Option(String),
  ttl_seconds: Int
) -> Result(String, StateStoreError)
```

### `store_with_ttl`

Store a CSRF state value, PKCE verifier, and optional OIDC nonce for a
flow started with `provider`, with a TTL, returning a session ID. This
low-level function applies only the global hard bound.

```gleam
pub fn store_with_ttl(
  StateStore,
  provider: String,
  state: String,
  code_verifier: String,
  nonce: option.Option(String),
  ttl_seconds: Int
) -> Result(String, StateStoreError)
```

### `sweep_expired`

Remove every expired session from the store now, returning how many were
removed. The owner process does this on a timer and on demand when the
store is at capacity, so calling it is optional.

```gleam
pub fn sweep_expired(StateStore) -> Result(Int, StateStoreError)
```
