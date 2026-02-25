# Token Refresh Utilities Design

## Goal

Add token refresh support to the core vestibule package. Applications with long-lived sessions need to refresh expired access tokens without re-authenticating the user.

## Approach

Add a `refresh_token` function to the main `vestibule` module alongside `authorize_url` and `handle_callback`. Token refresh is standardized in RFC 6749 Section 6 — all OAuth2 providers use the same token endpoint with `grant_type=refresh_token`.

## API

### New function: `vestibule.refresh_token/3`

```gleam
/// Refresh an access token using a refresh token.
/// Returns new credentials (which may include a new refresh token).
pub fn refresh_token(
  strategy: Strategy(e),
  config: Config,
  refresh_token: String,
) -> Result(Credentials, AuthError(e))
```

### Strategy type change

Add a `token_url` field to the Strategy record:

```gleam
pub type Strategy(e) {
  Strategy(
    provider: String,
    default_scopes: List(String),
    token_url: String,
    authorize_url: fn(Config, List(String), String) -> Result(String, AuthError(e)),
    exchange_code: fn(Config, String, Option(String)) -> Result(Credentials, AuthError(e)),
    fetch_user: fn(Credentials) -> Result(#(String, UserInfo), AuthError(e)),
  )
}
```

The `token_url` is the OAuth2 token endpoint (e.g., `https://github.com/login/oauth/access_token`). This is already known by each strategy for code exchange — making it a field on the record allows the core library to reuse it for refresh.

### Implementation

The `refresh_token` function performs:

```
POST {strategy.token_url}
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token={refresh_token}
&client_id={config.client_id}
&client_secret={config.client_secret}
```

Response parsing reuses the same token response format as code exchange — the response contains `access_token`, `token_type`, optionally `refresh_token`, `expires_in`, and `scope`.

### Shared token response parsing

Since code exchange and token refresh return the same response shape, extract a shared token response parser that both paths can use. This avoids duplicating JSON parsing logic.

## Files to create/modify

- **Modify** `src/vestibule.gleam` — add `refresh_token/3` function
- **Modify** `src/vestibule/strategy.gleam` — add `token_url` field to Strategy
- **Modify** `src/vestibule/strategy/github.gleam` — add token_url value, refactor token parsing
- **Modify** `packages/vestibule_google/src/vestibule_google.gleam` — same
- **Modify** `packages/vestibule_microsoft/src/vestibule_microsoft.gleam` — same
- **Create** tests for refresh_token in `test/vestibule_test.gleam`

## Notes

- GitHub does not support refresh tokens in standard OAuth apps (only GitHub Apps). The function will work but GitHub strategies typically won't have refresh tokens to use.
- Google and Microsoft both return refresh tokens and support refresh flows.
- If the provider returns a new refresh_token in the refresh response, it should be included in the returned Credentials.
