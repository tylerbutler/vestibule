---
title: "vestibule_indieauth/discovery"
description: "Reference for vestibule_indieauth/discovery."
nav:
  group: Reference
  groupOrder: 20
  order: 29
  label: "vestibule_indieauth/discovery"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_indieauth/discovery
---

# `vestibule_indieauth/discovery`

Reference for vestibule_indieauth/discovery.

## Types

### `DiscoveredEndpoints`

Endpoints discovered from a user's IndieAuth server.

```gleam
pub type DiscoveredEndpoints {
  DiscoveredEndpoints(
    authorization_endpoint: String,
    token_endpoint: String,
    issuer: option.Option(String),
    userinfo_endpoint: option.Option(String)
  )
}
```

## Functions

### `discover_endpoints`

Discover IndieAuth endpoints from a user's profile URL.

Fetches the URL and discovers endpoints using the three-tier fallback:
1. IndieAuth server metadata (`rel="indieauth-metadata"`)
2. Direct link relations (`rel="authorization_endpoint"`, `rel="token_endpoint"`)
3. HTTP `Link` headers take precedence over HTML `<link>` tags

```gleam
pub fn discover_endpoints(String) -> Result(DiscoveredEndpoints, error.AuthError(a))
```

### `find_html_link_rel`

Find an HTML `<link>` element with the given rel attribute.

Uses presentable_soup for robust HTML parsing.
Exported for testing.

```gleam
pub fn find_html_link_rel(
  String,
  String
) -> option.Option(String)
```

### `find_link_header_rel`

Parse HTTP Link headers to find a URL with the given rel value.

Handles the format: `<URL>; rel="value"` or `<URL>; rel=value`
Exported for testing.

```gleam
pub fn find_link_header_rel(
  List(#(String, String)),
  String
) -> option.Option(String)
```

### `parse_metadata`

Parse IndieAuth server metadata JSON.
Exported for testing.

```gleam
pub fn parse_metadata(String) -> Result(DiscoveredEndpoints, error.AuthError(a))
```
