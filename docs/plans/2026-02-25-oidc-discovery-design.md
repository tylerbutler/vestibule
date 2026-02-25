# OIDC Discovery Support Design

## Goal

Add OpenID Connect Discovery support so users can create a Strategy from any OIDC-compliant provider by passing just the issuer URL. The library fetches the provider's `.well-known/openid-configuration` document and builds a fully configured Strategy.

## Approach

Create a new `vestibule/oidc.gleam` module in the core package. It provides a `discover` function that fetches the OIDC configuration document, parses it, and returns a ready-to-use Strategy. The returned strategy uses standard OIDC userinfo parsing (sub, name, email, etc.).

## API

### Primary function: `discover/1`

```gleam
/// Discover an OIDC provider and build a Strategy from its configuration.
///
/// Example:
///   let assert Ok(strategy) = oidc.discover("https://accounts.google.com")
///   // strategy is now a fully configured Strategy for Google
///
pub fn discover(issuer_url: String) -> Result(Strategy(e), AuthError(e))
```

### Configuration document type

```gleam
/// Parsed OIDC discovery document (.well-known/openid-configuration).
pub type OidcConfig {
  OidcConfig(
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    scopes_supported: List(String),
  )
}
```

### Lower-level function: `fetch_configuration/1`

For users who want the raw discovery data without auto-building a strategy:

```gleam
/// Fetch and parse an OIDC discovery document.
pub fn fetch_configuration(issuer_url: String) -> Result(OidcConfig, AuthError(e))
```

### Strategy builder: `strategy_from_config/2`

```gleam
/// Build a Strategy from an already-fetched OIDC configuration.
pub fn strategy_from_config(
  oidc_config: OidcConfig,
  provider_name: String,
) -> Strategy(e)
```

## Implementation

### Discovery document fetch

1. Construct URL: `{issuer_url}/.well-known/openid-configuration`
2. GET request with Accept: application/json
3. Parse JSON response for required fields
4. Validate `issuer` field matches the input URL (security check per spec)

### Built strategy behavior

The strategy returned by `discover` uses standard OIDC behavior:

**authorize_url:** Builds URL from `authorization_endpoint` with standard params (response_type=code, client_id, redirect_uri, scope, state, code_challenge).

**exchange_code:** POSTs to `token_endpoint` with standard params (grant_type=authorization_code, code, redirect_uri, client_id, client_secret, code_verifier).

**fetch_user:** GETs `userinfo_endpoint` with Bearer token. Parses standard OIDC claims:
- `sub` → uid
- `name` → UserInfo.name
- `email` → UserInfo.email
- `preferred_username` → UserInfo.nickname
- `picture` → UserInfo.image

**token_url:** Set from `token_endpoint` for refresh support.

**default_scopes:** Uses `scopes_supported` from discovery, filtered to `["openid", "profile", "email"]` if those are available.

**provider:** The `provider_name` parameter, or derived from the issuer hostname.

## Files to create/modify

- **Create** `src/vestibule/oidc.gleam` — discovery, parsing, strategy builder
- **Create** `test/vestibule/oidc_test.gleam` — tests with mocked HTTP responses
- **Modify** `gleam.toml` — no new dependencies needed (already has gleam_httpc, gleam_json)

## Notes

- The OIDC spec requires issuer validation — the `issuer` field in the response MUST exactly match the URL used to fetch the document.
- Not all OIDC providers include a `userinfo_endpoint` — some only provide ID tokens. This initial implementation requires userinfo_endpoint; ID token decoding (JWT) is a future enhancement.
- Google (`https://accounts.google.com`) and Microsoft (`https://login.microsoftonline.com/common/v2.0`) both support OIDC discovery.
