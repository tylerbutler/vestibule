---
title: "vestibule/transport_flow"
description: "Transport-independent OAuth request and callback flow helpers."
nav:
  group: Reference
  groupOrder: 20
  order: 22
  label: "vestibule/transport_flow"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/transport_flow
---

# `vestibule/transport_flow`

Transport-independent OAuth request and callback flow helpers.

## Types

### `CallbackFlowError`

Errors that can occur while finishing a callback flow.

```gleam
pub type CallbackFlowError(a) {
  CallbackUnknownProvider(provider: String)
  CallbackSessionUnavailable
  CallbackAuthFailed(error.AuthError(a))
}
```

### `RequestFlowError`

Errors that can occur while starting an authorization flow.

```gleam
pub type RequestFlowError(a) {
  UnknownProvider(provider: String)
  AuthFailed(error.AuthError(a))
  StoreFailed(state_store.StateStoreError)
}
```

## Functions

### `ensure_callback_provider`

Look up the provider's strategy and config without touching cookies,
request bodies, or the state store.

Transports call this first so that an unknown provider returns
`CallbackUnknownProvider` before any cookie or request-body parsing
happens. The returned strategy/config pair is threaded into
`finish_callback` to avoid a second registry lookup.

```gleam
pub fn ensure_callback_provider(
  registry.Registry(a),
  String
) -> Result(#(strategy.Strategy(a), config.ClientConfig), CallbackFlowError(a))
```

### `finish_callback`

Validate callback state, consume the stored verifier, and fetch auth data.

Pass the strategy/config pair returned by `ensure_callback_provider` to
reuse the provider lookup instead of querying the registry again.

```gleam
pub fn finish_callback(
  #(strategy.Strategy(a), config.ClientConfig),
  store: state_store.StateStore,
  params: dict.Dict(String, String),
  session_id: String
) -> Result(auth.Auth, CallbackFlowError(a))
```

### `start_authorization`

Generate an authorization URL and store the expected state/verifier.

```gleam
pub fn start_authorization(
  registry.Registry(a),
  provider: String,
  store: state_store.StateStore,
  ttl_seconds: Int,
  options: config.AuthorizeOptions
) -> Result(#(String, String), RequestFlowError(a))
```
