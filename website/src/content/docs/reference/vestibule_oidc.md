---
title: "vestibule_oidc"
description: "OpenID Connect Discovery support for auto-configuring strategies."
nav:
  group: Reference
  groupOrder: 20
  order: 36
  label: "vestibule_oidc"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_oidc
---

# `vestibule_oidc`

OpenID Connect Discovery support for auto-configuring strategies.

This module implements [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
to automatically fetch provider configuration from a well-known endpoint
and build a `Strategy` from the discovered endpoints.

## Usage

```gleam
// Auto-discover and create a strategy in one step:
import vestibule_oidc
let assert Ok(strategy) = vestibule_oidc.discover("https://accounts.google.com")

// Or fetch configuration separately for inspection:
let assert Ok(config) = vestibule_oidc.fetch_configuration("https://accounts.google.com")
let strategy = vestibule_oidc.strategy_from_config(config, "my-provider")
```

## Types

### `OidcConfig`

Configuration discovered from an OpenID Connect provider's
`/.well-known/openid-configuration` endpoint.

```gleam
pub type OidcConfig
```

## Functions

### `authorization_endpoint`

Get the authorization endpoint URL for an OIDC configuration.

```gleam
pub fn authorization_endpoint(OidcConfig) -> String
```

### `discover`

Discover an OIDC provider and build a strategy in one step.

Fetches the discovery document from the issuer's well-known endpoint,
then constructs a strategy using the discovered configuration.
The issuer's hostname is used as the provider name.

```gleam
pub fn discover(String) -> Result(strategy.Strategy(a), error.AuthError(a))
```

### `discovery_url`

Build the OpenID Connect discovery URL for an issuer URL.

Per OIDC Discovery, path-based issuers insert
`/.well-known/openid-configuration` between the host and issuer path.

```gleam
pub fn discovery_url(String) -> Result(String, error.AuthError(a))
```

### `fetch_configuration`

Fetch the OpenID Connect configuration from a provider's discovery endpoint.

Constructs the well-known URL from the issuer, makes a GET request, parses
the JSON response, and validates that the `issuer` field in the response
matches the provided `issuer_url` (a security requirement per the OIDC spec).

**Security warning:** If `issuer_url` is provided dynamically by end-users
(e.g., for custom SSO in a multi-tenant application), you must sanitize
the URL before passing it here to prevent Server-Side Request Forgery (SSRF).

```gleam
pub fn fetch_configuration(String) -> Result(OidcConfig, error.AuthError(a))
```

### `filter_default_scopes`

Filter scopes to only include the standard OIDC scopes that the provider supports.

Supported helper for custom OIDC strategy authors.

```gleam
pub fn filter_default_scopes(List(String)) -> List(String)
```

### `issuer`

Get the issuer identifier for an OIDC configuration.

```gleam
pub fn issuer(OidcConfig) -> String
```

### `new_config`

Construct a validated OIDC configuration.

The issuer and endpoint URLs must use HTTPS and target a publicly-routable
host. Loopback (`localhost`, `127.0.0.1`, `[::1]`), private, and link-local
addresses are rejected: these endpoints come from a provider-controlled
discovery document and are called server-side with an `Authorization`
header, so permitting internal hosts would enable SSRF.

```gleam
pub fn new_config(
  issuer: String,
  authorization_endpoint: String,
  token_endpoint: String,
  userinfo_endpoint: String,
  scopes_supported: List(String)
) -> Result(OidcConfig, error.AuthError(a))
```

### `parse_discovery_document`

Parse an OIDC discovery JSON document into an `OidcConfig`.

Supported parsing helper for custom OIDC strategy authors. Extracts the
required fields from the standard OpenID Connect discovery response.

```gleam
pub fn parse_discovery_document(String) -> Result(OidcConfig, error.AuthError(a))
```

### `parse_token_response`

Parse a standard OAuth2/OIDC token response.

Supported parsing helper for custom OIDC strategy authors. Handles both
success and error responses.

```gleam
pub fn parse_token_response(String) -> Result(credentials.Credentials, error.AuthError(a))
```

### `parse_userinfo_response`

Parse a standard OIDC userinfo response into a uid and UserInfo.

Supported parsing helper for custom OIDC strategy authors. Maps standard
OIDC claims to UserInfo fields:
- `sub` -> uid
- `name` -> name
- `email` -> email
- `preferred_username` -> nickname
- `picture` -> image

```gleam
pub fn parse_userinfo_response(String) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `scopes_supported`

Get the scopes supported by an OIDC configuration.

```gleam
pub fn scopes_supported(OidcConfig) -> List(String)
```

### `strategy_from_config`

Build a `Strategy` from a discovered `OidcConfig`.

The resulting strategy uses standard OIDC/OAuth2 flows:
- Authorization code flow for authentication
- Standard token exchange
- Userinfo endpoint for user claims

The `provider_name` is used as the strategy's provider identifier.

```gleam
pub fn strategy_from_config(
  OidcConfig,
  String
) -> strategy.Strategy(a)
```

### `token_endpoint`

Get the token endpoint URL for an OIDC configuration.

```gleam
pub fn token_endpoint(OidcConfig) -> String
```

### `userinfo_endpoint`

Get the userinfo endpoint URL for an OIDC configuration.

```gleam
pub fn userinfo_endpoint(OidcConfig) -> String
```
