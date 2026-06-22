---
title: "vestibule/user_info"
description: "Normalized user profile returned by a provider's userinfo endpoint or extracted from an ID token. Provider-specific fields land in `extra`."
nav:
  group: Reference
  groupOrder: 20
  order: 22
  label: "vestibule/user_info"
toc:
  - href: "#types"
    label: "Types"
searchTerms:
  - api
  - reference
  - module
  - vestibule/user_info
---

# `vestibule/user_info`

Normalized user profile returned by a provider's userinfo endpoint or
extracted from an ID token. Provider-specific fields land in `extra`.

## Types

### `UserInfo`

Normalized user information across all providers.

```gleam
pub type UserInfo {
  UserInfo(
    name: option.Option(String),
    email: option.Option(String),
    nickname: option.Option(String),
    image: option.Option(String),
    description: option.Option(String),
    urls: dict.Dict(String, String)
  )
}
```
