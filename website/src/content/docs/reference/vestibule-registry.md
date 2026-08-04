---
title: "vestibule/registry"
description: "In-memory registry that maps provider names (\"google\", \"apple\", ...) to `Strategy` values. Used by the middleware to dispatch incoming authorize/callback requests to the right provider."
nav:
  group: Reference
  groupOrder: 20
  order: 19
  label: "vestibule/registry"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/registry
---

# `vestibule/registry`

In-memory registry that maps provider names ("google", "apple", ...)
to `Strategy` values. Used by the middleware to dispatch incoming
authorize/callback requests to the right provider.

## Types

### `Registry`

A registry mapping provider names to Strategy + ClientConfig pairs.

The type parameter `e` must match across all registered strategies.

```gleam
pub type Registry(a)
```

### `RegistryError`

Errors returned when registering a strategy.

```gleam
pub type RegistryError {
  DuplicateProvider(name: String)
}
```

#### Constructors

##### `DuplicateProvider(name: String)`

A strategy with this provider name is already registered. Use
`register_or_replace` if you intend to overwrite the existing entry.

## Functions

### `get`

Look up a provider by name.

```gleam
pub fn get(
  Registry(a),
  provider: String
) -> Result(#(strategy.Strategy(a), config.ClientConfig), Nil)
```

### `new`

Create an empty registry.

```gleam
pub fn new() -> Registry(a)
```

### `providers`

List all registered provider names.

```gleam
pub fn providers(Registry(a)) -> List(String)
```

### `register`

Register a strategy with its config. Provider name is taken from the
strategy.

Registration is rejected with `Error(DuplicateProvider(name))` if a
strategy is already registered under the same provider name. This prevents
a later (possibly untrusted) registration from silently replacing a trusted
provider — which would otherwise enable provider impersonation when account
identity is keyed by `provider + uid`.

When accepting provider names from dynamic or partly untrusted
configuration, namespace custom names (for example `"custom:acme"`) so they
cannot collide with built-in trusted providers. Trusted callers that
genuinely need to overwrite an entry should use `register_or_replace`.

```gleam
pub fn register(
  Registry(a),
  strategy: strategy.Strategy(a),
  config: config.ClientConfig
) -> Result(Registry(a), RegistryError)
```

### `register_or_replace`

Register a strategy with its config, replacing any existing strategy
registered under the same provider name.

This is the explicit, trusted-caller counterpart to `register`. Only use it
when the provider name and strategy are fully trusted, since it silently
overwrites a previously registered provider.

```gleam
pub fn register_or_replace(
  Registry(a),
  strategy: strategy.Strategy(a),
  config: config.ClientConfig
) -> Registry(a)
```
