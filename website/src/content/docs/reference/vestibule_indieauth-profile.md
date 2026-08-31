---
title: "vestibule_indieauth/profile"
description: "Profile URL confirmation for the IndieAuth callback phase."
nav:
  group: Reference
  groupOrder: 20
  order: 30
  label: "vestibule_indieauth/profile"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_indieauth/profile
---

# `vestibule_indieauth/profile`

Profile URL confirmation for the IndieAuth callback phase.

The `me` a user types into the login form is only a *claim*. The identity
that must be trusted is the profile URL the authorization server returns
in the token response — and only after confirming that URL is really
served by the same authorization server the flow ran against (IndieAuth
§5.3.4, "Authorization Server Confirmation"). Without this check, any
token or userinfo endpoint could assert an arbitrary `me` and log the
caller in as somebody else.

## Functions

### `confirm_profile_url`

Confirm the profile URL returned by the authorization server.

- If `returned_me` canonicalizes to `expected_me`, it is accepted as-is.
- Otherwise the returned URL is re-discovered with `rediscover` and is
  accepted only when it advertises exactly the same endpoint set that
  this flow used. Comparing the full set (not just the authorization
  endpoint) matters: an attacker whose metadata borrows a shared
  authorization endpoint but supplies their own token endpoint must not be
  able to assert a `me` that the shared server never authenticated.

Returns the canonical, confirmed profile URL to use as the user's identity.

```gleam
pub fn confirm_profile_url(
  expected_me: String,
  returned_me: String,
  endpoints: discovery.DiscoveredEndpoints,
  rediscover: fn(String) -> Result(discovery.DiscoveredEndpoints, error.AuthError(a))
) -> Result(String, error.AuthError(a))
```

### `require_same_profile_url`

Require `actual_me` to canonicalize to the already-confirmed
`expected_me`. Used for the userinfo endpoint, which is not permitted to
change the identity established during the token exchange.

```gleam
pub fn require_same_profile_url(
  expected_me: String,
  actual_me: String
) -> Result(String, error.AuthError(a))
```
