---
title: "vestibule/logger"
description: "Reference for vestibule/logger."
nav:
  group: Reference
  groupOrder: 20
  order: 16
  label: "vestibule/logger"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/logger
---

# `vestibule/logger`

Reference for vestibule/logger.

## Types

### `Event`

```gleam
pub type Event
```

### `Level`

```gleam
pub type Level {
  Debug
  Info
  Warning
  Error
}
```

## Functions

### `auth_error_category`

```gleam
pub fn auth_error_category(error.AuthError(a)) -> String
```

### `bool_field`

```gleam
pub fn bool_field(
  String,
  Bool
) -> #(String, String)
```

### `emit`

```gleam
pub fn emit(Event) -> Nil
```

### `field`

```gleam
pub fn field(
  String,
  String
) -> #(String, String)
```

### `fields`

```gleam
pub fn fields(Event) -> List(#(String, String))
```

### `int_field`

```gleam
pub fn int_field(
  String,
  Int
) -> #(String, String)
```

### `level`

```gleam
pub fn level(Event) -> Level
```

### `new`

```gleam
pub fn new(
  level: Level,
  event: String,
  phase: String,
  outcome: String,
  provider: option.Option(String),
  fields: List(#(String, String))
) -> Event
```

### `safe_fields`

```gleam
pub fn safe_fields(List(#(String, String))) -> List(#(String, String))
```
