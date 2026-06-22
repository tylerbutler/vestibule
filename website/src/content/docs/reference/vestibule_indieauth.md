---
title: "vestibule_indieauth"
description: "Reference for vestibule_indieauth."
nav:
  group: Reference
  groupOrder: 20
  order: 28
  label: "vestibule_indieauth"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_indieauth
---

# `vestibule_indieauth`

Reference for vestibule_indieauth.

## Functions

### `discover`

Discover IndieAuth endpoints from a user's profile URL and return
a configured Strategy.

This performs the full discovery flow:
1. Validates and canonicalizes the user URL
2. Fetches the URL and follows redirects
3. Discovers authorization and token endpoints
4. Returns a `Strategy(e)` ready for use with `vestibule.authorize_url`

## Example

```gleam
let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")
let cfg = config.new("https://myapp.com/", "", "https://myapp.com/callback")
let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
```

```gleam
pub fn discover(String) -> Result(strategy.Strategy(a), error.AuthError(a))
```

### `discover_endpoints`

Discover IndieAuth endpoints without creating a strategy.

Useful when you want to inspect the discovered endpoints before
creating a strategy, or need to store them for later use.

```gleam
pub fn discover_endpoints(String) -> Result(discovery.DiscoveredEndpoints, error.AuthError(a))
```

### `strategy`

Create a strategy from previously discovered endpoints.

Use this with `discover_endpoints` when you want to separate
discovery from strategy creation.

```gleam
pub fn strategy(
  discovery.DiscoveredEndpoints,
  String
) -> strategy.Strategy(a)
```
