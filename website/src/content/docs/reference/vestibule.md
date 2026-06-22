---
title: "vestibule"
description: "Vestibule — a strategy-based authentication library for Gleam."
nav:
  group: Reference
  groupOrder: 20
  order: 10
  label: "vestibule"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule
---

# `vestibule`

Vestibule — a strategy-based authentication library for Gleam.

Provides a consistent interface across OAuth2 identity providers
using a two-phase flow: redirect to provider, then handle callback.
All flows use PKCE (Proof Key for Code Exchange) for enhanced security.

## Functions

### `create_authorization_request`

Phase 1: Generate the authorization URL to redirect the user to.

Returns an `AuthorizationRequest` containing the URL, CSRF state,
and PKCE code verifier. The caller must store both the state and
code_verifier in their session for use during the callback phase.

PKCE parameters (`code_challenge` and `code_challenge_method=S256`)
are automatically appended to the authorization URL.

**State expiration:** This library generates the state token but does
not enforce expiration. If you need time-based expiration, store a
timestamp alongside the state when saving it to your session and
check it before calling `handle_callback`.

```gleam
pub fn create_authorization_request(
  strategy.Strategy(a),
  cfg: config.Config
) -> Result(authorization_request.AuthorizationRequest, error.AuthError(a))
```

### `handle_callback`

Phase 2: Handle the OAuth callback from the provider.

Validates the state parameter, exchanges the authorization code
for credentials (including the PKCE code verifier), and fetches
normalized user information.

**Caller responsibilities:** This function checks that the callback
state matches `expected_state`, but does not enforce single-use or
expiration. Callers should delete the stored state after a successful
call to prevent replay attacks. The wisp middleware's `uset.take`
provides one-time-use semantics automatically. For time-based
expiration, check the timestamp you stored alongside the state
before calling this function.

```gleam
pub fn handle_callback(
  strategy.Strategy(a),
  cfg: config.Config,
  callback_params: dict.Dict(String, String),
  expected_state: String,
  code_verifier: String
) -> Result(auth.Auth, error.AuthError(a))
```

### `refresh_token`

Refresh an access token using a refresh token.

Delegates to the provider strategy so refresh semantics remain provider-owned.

```gleam
pub fn refresh_token(
  strategy.Strategy(a),
  cfg: config.Config,
  refresh_tok: String
) -> Result(credentials.Credentials, error.AuthError(a))
```
