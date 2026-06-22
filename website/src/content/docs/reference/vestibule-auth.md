---
title: "vestibule/auth"
description: "Authentication result types returned to the calling application after a successful OAuth/OIDC flow."
nav:
  group: Reference
  groupOrder: 20
  order: 11
  label: "vestibule/auth"
toc:
  - href: "#types"
    label: "Types"
searchTerms:
  - api
  - reference
  - module
  - vestibule/auth
---

# `vestibule/auth`

Authentication result types returned to the calling application after a
successful OAuth/OIDC flow.

## Types

### `Auth`

The normalized result of a successful authentication.

```gleam
pub type Auth {
  Auth(
    uid: String,
    provider: String,
    info: user_info.UserInfo,
    credentials: credentials.Credentials,
    extra: dict.Dict(String, dynamic.Dynamic)
  )
}
```
