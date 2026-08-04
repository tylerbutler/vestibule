---
title: "vestibule/state_store"
description: "Single-use storage for in-flight OAuth flow state (CSRF `state` and PKCE `code_verifier`). Entries are deleted on first read to prevent replay."
nav:
  group: Reference
  groupOrder: 20
  order: 20
  label: "vestibule/state_store"
toc:
  - href: "#types"
    label: "Types"
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

This is the shared store used by transport packages (`vestibule_wisp`,
`vestibule_mist`, etc.). Applications that load more than one
transport share a single ETS owner process and may share a store.

## Types

### `StateStore`

The state store table.

The concrete storage implementation is intentionally opaque so the public
API can evolve without exposing the underlying table representation.

```gleam
pub type StateStore
```

### `StateStoreError`

Errors returned by checked state store operations.

```gleam
pub type StateStoreError {
  OwnerUnavailable
  OperationTimedOut
  TableAlreadyExists
  TableCreateFailed
  TableNotFound
  InsertFailed
  CleanupFailed
}
```

## Functions

### `consume`

Consume a CSRF state, code verifier, and optional nonce by session ID.

Returns `Error(Nil)` if not found, expired, or already consumed.

```gleam
pub fn consume(
  StateStore,
  String
) -> Result(#(String, String, option.Option(String)), Nil)
```

### `peek`

Look up a CSRF state, code verifier, and optional nonce by session ID
without consuming it.

Expired sessions are treated as missing and removed from the store.

```gleam
pub fn peek(
  StateStore,
  String
) -> Result(#(String, String, option.Option(String)), Nil)
```

### `try_init`

Try to initialize the state store. Call once per VM at application
startup; the returned table handle is needed by `try_store`/`consume`.

```gleam
pub fn try_init() -> Result(StateStore, StateStoreError)
```

### `try_init_named`

Try to initialize a named state store. Returns `Error(TableAlreadyExists)`
if the table already exists, or another `StateStoreError` if the owner
process or ETS operation fails.

```gleam
pub fn try_init_named(String) -> Result(StateStore, StateStoreError)
```

### `try_store`

Try to store a CSRF state value, PKCE code verifier, and optional OIDC
nonce, returning a session ID.

```gleam
pub fn try_store(
  StateStore,
  state: String,
  code_verifier: String,
  nonce: option.Option(String)
) -> Result(String, StateStoreError)
```

### `try_store_with_ttl`

Try to store a CSRF state value, PKCE verifier, and optional OIDC nonce
with a TTL, returning a session ID.

```gleam
pub fn try_store_with_ttl(
  StateStore,
  state: String,
  code_verifier: String,
  nonce: option.Option(String),
  ttl_seconds: Int
) -> Result(String, StateStoreError)
```
