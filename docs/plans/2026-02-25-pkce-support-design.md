# PKCE Support Design

## Goal

Add always-on PKCE (Proof Key for Code Exchange) support to vestibule. Every OAuth2 authorization flow generates a code verifier/challenge pair, adding defense-in-depth against authorization code interception attacks.

## Approach

PKCE is handled transparently by the core library — individual strategies don't generate PKCE values. The core `authorize_url` generates a code_verifier and code_challenge, appends challenge params to the authorization URL, and returns the verifier for the caller to store. During callback, the verifier is passed through to the token exchange.

## API Changes

### New type: `AuthorizationRequest`

Replace the `#(String, String)` tuple return from `authorize_url` with a named record:

```gleam
pub type AuthorizationRequest {
  AuthorizationRequest(
    url: String,
    state: String,
    code_verifier: String,
  )
}
```

### Updated `authorize_url/2`

```gleam
pub fn authorize_url(
  strategy: Strategy(e),
  config: Config,
) -> Result(AuthorizationRequest, AuthError(e))
```

The function now:
1. Generates CSRF state (existing)
2. Generates PKCE code_verifier (new)
3. Computes code_challenge = base64url(sha256(code_verifier)) (new)
4. Calls strategy's authorize_url with code_challenge + code_challenge_method=S256 added as extra params
5. Returns AuthorizationRequest with url, state, and code_verifier

### Updated `handle_callback`

```gleam
pub fn handle_callback(
  strategy: Strategy(e),
  config: Config,
  callback_params: Dict(String, String),
  expected_state: String,
  code_verifier: String,
) -> Result(Auth, AuthError(e))
```

Adds `code_verifier` parameter, passed through to the strategy's `exchange_code`.

### Updated Strategy type

```gleam
pub type Strategy(e) {
  Strategy(
    provider: String,
    default_scopes: List(String),
    authorize_url: fn(Config, List(String), String) -> Result(String, AuthError(e)),
    exchange_code: fn(Config, String, Option(String)) -> Result(Credentials, AuthError(e)),
    fetch_user: fn(Credentials) -> Result(#(String, UserInfo), AuthError(e)),
  )
}
```

The `exchange_code` function gains an `Option(String)` third parameter for the code_verifier. Strategies include it in the token POST body when present.

### New module: `vestibule/pkce.gleam`

```gleam
/// Generate a cryptographically random code verifier (43-128 chars).
pub fn generate_verifier() -> String

/// Compute the S256 code challenge from a verifier.
pub fn compute_challenge(verifier: String) -> String
```

Implementation:
- Verifier: 32 bytes of crypto random, base64url-encoded (43 chars)
- Challenge: SHA-256 hash of verifier, base64url-encoded (no padding)

### Wisp middleware update

`vestibule_wisp` state store stores `#(state, code_verifier)` instead of just `state`. The middleware passes code_verifier through transparently during callback.

## Files to create/modify

- **Create** `src/vestibule/pkce.gleam` — verifier generation + challenge computation
- **Create** `src/vestibule/authorization_request.gleam` — AuthorizationRequest type
- **Modify** `src/vestibule.gleam` — update authorize_url return type, update handle_callback signature
- **Modify** `src/vestibule/strategy.gleam` — update exchange_code signature
- **Modify** `src/vestibule/strategy/github.gleam` — accept Option(String) code_verifier in exchange_code
- **Modify** `packages/vestibule_google/src/vestibule_google.gleam` — same
- **Modify** `packages/vestibule_microsoft/src/vestibule_microsoft.gleam` — same
- **Modify** `packages/vestibule_wisp/src/vestibule_wisp.gleam` — pass code_verifier through
- **Modify** `packages/vestibule_wisp/src/vestibule_wisp/state_store.gleam` — store/retrieve code_verifier
- **Modify** `packages/vestibule_wisp/src/vestibule_wisp_state_store_ffi.erl` — if needed for tuple storage
- **Modify** `example/src/vestibule_example.gleam` and `example/src/router.gleam` — update to new API
- **Update** all tests

## Security requirements (from PRD)

- Code verifier MUST be at least 43 characters (SR-4)
- Code verifier MUST use cryptographically random bytes
- Code challenge method MUST be S256 (not plain)
- Code challenge = base64url(sha256(ascii(code_verifier))) per RFC 7636
