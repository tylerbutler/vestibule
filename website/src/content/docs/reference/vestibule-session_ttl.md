---
title: "vestibule/session_ttl"
description: "A validated lifetime for short-lived OAuth flow sessions."
nav:
  group: Reference
  groupOrder: 20
  order: 20
  label: "vestibule/session_ttl"
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
  - vestibule/session_ttl
---

# `vestibule/session_ttl`

A validated lifetime for short-lived OAuth flow sessions.

Session TTLs must be whole seconds between 1 and 3,600 inclusive. The
maximum limits the replay window for state stored during an OAuth flow.

## Types

### `SessionTtl`

A validated session lifetime.

```gleam
pub type SessionTtl
```

### `SessionTtlError`

Errors returned when constructing a session TTL.

```gleam
pub type SessionTtlError {
  NotPositive
  ExceedsMaximum
  FractionalSeconds
}
```

#### Constructors

##### `NotPositive`

The TTL was zero or negative.

##### `ExceedsMaximum`

The TTL exceeded `maximum_seconds`.

##### `FractionalSeconds`

The duration included a fraction of a second.

## Constants

### `maximum_seconds`

The longest permitted session TTL, in seconds.

```gleam
pub const maximum_seconds: Int
```

## Functions

### `from_duration`

Construct a session TTL from a duration.

Durations with fractional seconds are rejected because storage and cookie
adapters use whole-second TTLs.

```gleam
pub fn from_duration(duration.Duration) -> Result(SessionTtl, SessionTtlError)
```

### `from_seconds`

Construct a session TTL from whole seconds.

```gleam
pub fn from_seconds(Int) -> Result(SessionTtl, SessionTtlError)
```

### `to_duration`

Return the validated TTL as a duration.

```gleam
pub fn to_duration(SessionTtl) -> duration.Duration
```

### `to_seconds`

Return the validated TTL in whole seconds.

```gleam
pub fn to_seconds(SessionTtl) -> Int
```
