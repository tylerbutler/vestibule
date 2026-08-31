---
title: "Reference"
description: "Generated API reference from Gleam docs metadata for every Vestibule package."
nav:
  group: Reference
  groupOrder: 20
  order: 0
  label: API overview
toc:
  - href: "#packages"
    label: Packages
  - href: "#modules"
    label: Modules
searchTerms:
  - api
  - reference
  - vestibule
---

# Reference

This reference is generated from Gleam's docs metadata for the Vestibule packages: `vestibule`, `vestibule_apple`, `vestibule_github`, `vestibule_google`, `vestibule_indieauth`, `vestibule_microsoft`, `vestibule_mist`, `vestibule_oidc`, `vestibule_wisp`.

> **Generated content:** Pages under `/docs/reference` are generated from Gleam's docs metadata and reflect every public type, function, and constant.

Vestibule packages are not published on Hex. Follow the [installation guide](/docs/installation) to add them as Git dependencies with Gleam 1.18 or later.

## Packages

| Package | Version | Modules | Description |
|---|---:|---:|---|
| `vestibule` | `0.0.0` | 13 | Demo-ready OAuth sign-in for Gleam. Real auth flows for demos and prototypes — not audited, not for production. |
| `vestibule_apple` | `0.0.0` | 3 | Apple Sign In strategy for vestibule (demo-ready — not audited, not for production) |
| `vestibule_github` | `0.0.0` | 1 | GitHub OAuth strategy for vestibule (demo-ready — not audited, not for production) |
| `vestibule_google` | `0.0.0` | 1 | Google OAuth strategy for vestibule (demo-ready — not audited, not for production) |
| `vestibule_indieauth` | `0.0.0` | 5 | IndieAuth strategy for vestibule — decentralized identity via OAuth 2.0 (demo-ready — not audited, not for production) |
| `vestibule_microsoft` | `0.0.0` | 1 | Microsoft OAuth strategy for vestibule (demo-ready — not audited, not for production) |
| `vestibule_mist` | `0.0.0` | 2 | Mist middleware for vestibule OAuth authentication (demo-ready — not audited, not for production) |
| `vestibule_oidc` | `0.0.0` | 1 | OpenID Connect discovery for vestibule — auto-configure strategies from an issuer URL (demo-ready — not audited, not for production) |
| `vestibule_wisp` | `0.0.0` | 1 | Wisp middleware for vestibule OAuth authentication (demo-ready — not audited, not for production) |

## Modules

| Package | Module | Description |
|---|---|---|
| `vestibule` | [`vestibule`](/docs/reference/vestibule) | Vestibule — demo-ready OAuth sign-in for Gleam. |
| `vestibule` | [`vestibule/auth`](/docs/reference/vestibule-auth) | Authentication result types returned to the calling application after a successful OAuth/OIDC flow. |
| `vestibule` | [`vestibule/authorization_request`](/docs/reference/vestibule-authorization_request) | An opaque value carrying everything the middleware needs to start an authorization flow: the URL to redirect the browser to, the CSRF `state`, the PKCE `code_verifier`, and an optional OIDC `nonce`, all of which must be stored for the callback. |
| `vestibule` | [`vestibule/config`](/docs/reference/vestibule-config) | OAuth client configuration and per-authorization request options. |
| `vestibule` | [`vestibule/credentials`](/docs/reference/vestibule-credentials) | Bearer credentials returned by a provider after a successful token exchange or refresh. |
| `vestibule` | [`vestibule/error`](/docs/reference/vestibule-error) | Authentication error types. |
| `vestibule` | [`vestibule/logger`](/docs/reference/vestibule-logger) | Reference for vestibule/logger. |
| `vestibule` | [`vestibule/nonce`](/docs/reference/vestibule-nonce) | OIDC `nonce` generation and constant-time validation. A fresh 256-bit base64url nonce is minted for every OIDC authorization request, sent as the `nonce` authorize-request parameter, and echoed back by the provider in the signed `id_token`. On callback the value read from the id_token is compared against the stored value to bind the token to this browser session, preventing id_token replay/injection. |
| `vestibule` | [`vestibule/provider_support`](/docs/reference/vestibule-provider_support) | Stable helpers for OAuth provider implementations. |
| `vestibule` | [`vestibule/registry`](/docs/reference/vestibule-registry) | In-memory registry that maps provider names ("google", "apple", ...) to `Strategy` values. Used by the middleware to dispatch incoming authorize/callback requests to the right provider. |
| `vestibule` | [`vestibule/state_store`](/docs/reference/vestibule-state_store) | Single-use storage for in-flight OAuth flow state (CSRF `state` and PKCE `code_verifier`). Entries are deleted on first read to prevent replay. |
| `vestibule` | [`vestibule/strategy`](/docs/reference/vestibule-strategy) | Provider-strategy interface. A `Strategy(e)` is an opaque record bundling the provider-specific functions an OAuth/OIDC provider implements: build authorize URL, exchange code, fetch user, and an optional refresh token. |
| `vestibule` | [`vestibule/user_info`](/docs/reference/vestibule-user_info) | Normalized user profile returned by a provider's userinfo endpoint or extracted from an ID token. Provider-specific fields land in `extra`. |
| `vestibule_apple` | [`vestibule_apple`](/docs/reference/vestibule_apple) | Apple Sign In strategy for vestibule. |
| `vestibule_apple` | [`vestibule_apple/jwks`](/docs/reference/vestibule_apple-jwks) | Apple JWKS (JSON Web Key Set) fetching and caching. |
| `vestibule_apple` | [`vestibule_apple/jwt`](/docs/reference/vestibule_apple-jwt) | JWT verification using ywt_core with a custom Erlang FFI backend. |
| `vestibule_github` | [`vestibule_github`](/docs/reference/vestibule_github) | Reference for vestibule_github. |
| `vestibule_google` | [`vestibule_google`](/docs/reference/vestibule_google) | Google OAuth 2.0 / OIDC strategy. |
| `vestibule_indieauth` | [`vestibule_indieauth`](/docs/reference/vestibule_indieauth) | IndieAuth strategy for vestibule — decentralized identity via OAuth 2.0. |
| `vestibule_indieauth` | [`vestibule_indieauth/discovery`](/docs/reference/vestibule_indieauth-discovery) | IndieAuth endpoint discovery. |
| `vestibule_indieauth` | [`vestibule_indieauth/profile`](/docs/reference/vestibule_indieauth-profile) | Profile URL confirmation for the IndieAuth callback phase. |
| `vestibule_indieauth` | [`vestibule_indieauth/token`](/docs/reference/vestibule_indieauth-token) | IndieAuth token exchange and response parsing. |
| `vestibule_indieauth` | [`vestibule_indieauth/url`](/docs/reference/vestibule_indieauth-url) | URL validation and canonicalization for IndieAuth. |
| `vestibule_microsoft` | [`vestibule_microsoft`](/docs/reference/vestibule_microsoft) | Microsoft Identity Platform (v2.0) strategy. |
| `vestibule_mist` | [`vestibule_mist`](/docs/reference/vestibule_mist) | Mist middleware that wires a `Registry` of `Strategy` values into HTTP endpoints. |
| `vestibule_mist` | [`vestibule_mist/signed_cookie`](/docs/reference/vestibule_mist-signed_cookie) | HMAC-SHA256 signed cookie payload helpers. |
| `vestibule_oidc` | [`vestibule_oidc`](/docs/reference/vestibule_oidc) | OpenID Connect Discovery support for auto-configuring strategies. |
| `vestibule_wisp` | [`vestibule_wisp`](/docs/reference/vestibule_wisp) | Wisp middleware that wires a `Registry` of `Strategy` values into HTTP endpoints. |
