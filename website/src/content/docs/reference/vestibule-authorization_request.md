---
title: "vestibule/authorization_request"
description: "An opaque value carrying everything the middleware needs to start an authorization flow: the URL to redirect the browser to, the CSRF `state`, and the PKCE `code_verifier` that must be stored for the callback."
nav:
  group: Reference
  groupOrder: 20
  order: 12
  label: "vestibule/authorization_request"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/authorization_request
---

# `vestibule/authorization_request`

An opaque value carrying everything the middleware needs to start an
authorization flow: the URL to redirect the browser to, the CSRF
`state`, and the PKCE `code_verifier` that must be stored for the
callback.

## Types

### `AuthorizationRequest`

Represents the result of generating an authorization URL.

Contains all values needed for the OAuth2 authorization phase,
including PKCE parameters that must be stored for the callback phase.

Opaque so that new artifacts (e.g., an OIDC `nonce`) can be added
without breaking consumers. Construct with `new` and read fields via
the `url`, `state`, and `code_verifier` accessors.

```gleam
pub type AuthorizationRequest
```

## Functions

### `code_verifier`

The PKCE code verifier (must be stored for token exchange).

```gleam
pub fn code_verifier(AuthorizationRequest) -> String
```

### `new`

Build an `AuthorizationRequest`.

```gleam
pub fn new(
  url: String,
  state: String,
  code_verifier: String
) -> AuthorizationRequest
```

### `state`

The CSRF state parameter (must be stored for validation).

Store a timestamp alongside it if you need time-based expiration.

```gleam
pub fn state(AuthorizationRequest) -> String
```

### `url`

The authorization URL to redirect the user to.

```gleam
pub fn url(AuthorizationRequest) -> String
```
