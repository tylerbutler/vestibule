---
title: "vestibule_indieauth"
description: "IndieAuth strategy for vestibule — decentralized identity via OAuth 2.0."
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

IndieAuth strategy for vestibule — decentralized identity via OAuth 2.0.

IndieAuth is an identity layer on top of OAuth 2.0 where users are identified
by a URL they control. Endpoints are discovered dynamically from the user's
homepage rather than being statically configured.

## Usage

```gleam
// Discover the user's IndieAuth endpoints
let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")

// Use with vestibule's standard two-phase flow
let options = config.authorize_options()
let assert Ok(auth_request) =
  vestibule.create_authorization_request(strategy, config: client_config, options: options)
```

## Discovery

The `discover` function fetches the user's homepage and finds their
authorization and token endpoints using a three-tier fallback:

1. IndieAuth server metadata (`rel="indieauth-metadata"` → JSON document)
2. Direct link relations (`rel="authorization_endpoint"`, `rel="token_endpoint"`)
3. Falls back from HTTP `Link` headers to HTML `<link>` tags at each tier

## Functions

### `discover`

Discover IndieAuth endpoints from a user's profile URL and return
a configured Strategy.

This performs the full discovery flow:
1. Validates and canonicalizes the user URL
2. Fetches the URL and follows redirects
3. Discovers authorization and token endpoints
4. Returns a `Strategy(e)` ready for use with `vestibule.create_authorization_request`

## Example

```gleam
let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")
let client_config =
  config.new(
    client_id: "https://myapp.com/",
    redirect_uri: "https://myapp.com/callback",
    auth: config.PublicClient,
  )
let options = config.authorize_options()
let assert Ok(auth_request) =
  vestibule.create_authorization_request(strategy, config: client_config, options: options)
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

### `discover_endpoints_with_me`

Discover IndieAuth endpoints and return them together with the canonical
`me` URL.

IndieAuth's two-phase flow needs both the discovered endpoints and the
canonical profile URL again at callback time, but `discover` returns only a
`Strategy` and `discover_endpoints` returns only the endpoints. This helper
performs validation + discovery once and hands back both, so callers don't
have to reach into the `url` and `discovery` submodules themselves.

Pair it with `serialize_endpoints` / `parse_endpoints` to carry the result
across the request→callback boundary (e.g. in a signed cookie), then rebuild
the strategy with `strategy(endpoints, me)`.

## Example

```gleam
let assert Ok(#(endpoints, me)) =
  vestibule_indieauth.discover_endpoints_with_me("https://user.example.com")
let strategy = vestibule_indieauth.strategy(endpoints, me)
```

```gleam
pub fn discover_endpoints_with_me(String) -> Result(#(discovery.DiscoveredEndpoints, String), error.AuthError(a))
```

### `parse_endpoints`

Parse a string produced by `serialize_endpoints` back into the discovered
endpoints and the canonical `me` URL.

Returns `Error(error.config(..))` if the value is missing fields or is
not the JSON produced by `serialize_endpoints`.

```gleam
pub fn parse_endpoints(String) -> Result(#(discovery.DiscoveredEndpoints, String), error.AuthError(a))
```

### `serialize_endpoints`

Serialize discovered endpoints + the canonical `me` URL to a compact JSON
string.

IndieAuth strategies are discovered per-user at request time, but the
transport-independent flow needs the same endpoints again in the callback
phase. Persist this string (for example in a signed cookie or server-side
session) during the request phase and restore it with `parse_endpoints` in
the callback phase to rebuild the strategy via `strategy(endpoints, me)` —
no second discovery round-trip required.

```gleam
pub fn serialize_endpoints(
  discovery.DiscoveredEndpoints,
  String
) -> String
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
