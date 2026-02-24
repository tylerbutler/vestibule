# Phase 1 Design: Core Types + GitHub Strategy

**Date:** 2026-02-24
**Status:** Approved
**Scope:** Phase 1 MVP — core library types, state management, strategy interface, GitHub provider

---

## Decisions

- **Approach:** Types-first, bottom-up build order
- **Strategy pattern:** Record of functions (as PRD specifies)
- **HTTP:** Strategies make HTTP calls internally using `gleam_httpc`
- **Wisp:** Deferred to Phase 2 — core library only
- **JWT:** Not needed for Phase 1 (GitHub uses opaque tokens); add `gwt` when Google lands
- **Provider change:** Microsoft replaces Discord in the PRD's three launch providers

---

## Module Structure

```
src/
├── vestibule.gleam                    # Public API: authorize_url, handle_callback
└── vestibule/
    ├── auth.gleam                     # Auth result type
    ├── config.gleam                   # Config type and builders
    ├── credentials.gleam              # Credentials type
    ├── user_info.gleam                # UserInfo type
    ├── strategy.gleam                 # Strategy record type
    ├── state.gleam                    # CSRF state generation/validation
    ├── error.gleam                    # AuthError type
    └── strategy/
        └── github.gleam              # GitHub strategy
```

Deferred: `registry.gleam`, `wisp.gleam`, `strategy/google.gleam`, `strategy/microsoft.gleam`

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `gleam_stdlib` | Core types (already present) |
| `glow_auth` | OAuth2 protocol helpers (auth URLs, token exchange, token decoding) |
| `gleam_http` | Request/Response types |
| `gleam_httpc` | HTTP client for provider API calls |
| `gleam_json` | Parsing provider JSON responses |
| `gleam_crypto` | Random bytes for state, constant-time comparison |

---

## Core Types

### `vestibule/error.gleam`

```gleam
pub type AuthError {
  StateMismatch
  CodeExchangeFailed(reason: String)
  UserInfoFailed(reason: String)
  ProviderError(code: String, description: String)
  NetworkError(reason: String)
  ConfigError(reason: String)
}
```

### `vestibule/user_info.gleam`

```gleam
pub type UserInfo {
  UserInfo(
    name: Option(String),
    email: Option(String),
    nickname: Option(String),
    image: Option(String),
    description: Option(String),
    urls: Dict(String, String),
  )
}
```

### `vestibule/credentials.gleam`

```gleam
pub type Credentials {
  Credentials(
    token: String,
    refresh_token: Option(String),
    token_type: String,
    expires_at: Option(Int),
    scopes: List(String),
  )
}
```

### `vestibule/config.gleam`

```gleam
pub type Config {
  Config(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: List(String),
    extra_params: Dict(String, String),
  )
}

pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Config
pub fn with_scopes(config: Config, scopes: List(String)) -> Config
pub fn with_extra_params(config: Config, params: List(#(String, String))) -> Config
```

### `vestibule/auth.gleam`

```gleam
pub type Auth {
  Auth(
    uid: String,
    provider: String,
    info: UserInfo,
    credentials: Credentials,
    extra: Dict(String, Dynamic),
  )
}
```

### `vestibule/strategy.gleam`

```gleam
pub type Strategy {
  Strategy(
    provider: String,
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError),
    exchange_code: fn(Config, String) ->
      Result(Credentials, AuthError),
    fetch_user: fn(Credentials) ->
      Result(UserInfo, AuthError),
  )
}
```

---

## State Management (`vestibule/state.gleam`)

- `generate()` → 32 bytes random, base64url-encoded (~43 chars)
- `validate(received, expected)` → constant-time comparison, returns `Result(Nil, AuthError)`
- Uses `gleam/crypto` for both operations

---

## Public API (`vestibule.gleam`)

### `authorize_url(strategy, config) -> Result(#(String, String), AuthError)`

1. Generate state via `state.generate()`
2. Merge scopes (config scopes if non-empty, otherwise strategy defaults)
3. Call `strategy.authorize_url(config, scopes, state)`
4. Return `#(url, state)` — caller stores state in session

### `handle_callback(strategy, config, callback_params, expected_state) -> Result(Auth, AuthError)`

1. Extract `code` and `state` from `callback_params`
2. Validate state via `state.validate(received, expected)`
3. Call `strategy.exchange_code(config, code)` → `Credentials`
4. Call `strategy.fetch_user(credentials)` → `UserInfo`
5. Assemble `Auth` with uid from user info, provider from strategy

---

## GitHub Strategy (`vestibule/strategy/github.gleam`)

- **Provider:** `"github"`
- **Default scopes:** `["user:email"]`

### authorize_url

Builds `https://github.com/login/oauth/authorize` using `glow_auth/authorize_uri` with client_id, redirect_uri, scope (space-joined), state.

### exchange_code

POSTs to `https://github.com/login/oauth/access_token` via `glow_auth/token_request.authorization_code`. Parses response with `glow_auth/access_token.decoder`. Converts `AccessToken` → `Credentials`.

### fetch_user

1. GET `https://api.github.com/user` with Bearer token → parse name, nickname (login), image (avatar_url), bio
2. GET `https://api.github.com/user/emails` → find primary verified email
3. Assemble `UserInfo`, use GitHub user ID as uid

---

## Testing Strategy

### Unit tests (pure, no HTTP)

| Module | Tests |
|--------|-------|
| `state.gleam` | generate() length, validate() match/mismatch, uniqueness |
| `config.gleam` | new() defaults, with_scopes(), with_extra_params() |
| Core types | Constructor roundtrips |

### Integration tests (JSON parsing)

Extract internal parsing functions from the GitHub strategy and test with sample JSON:

- `parse_token_response(json)` → `Credentials`
- `parse_user_response(json)` → partial `UserInfo`
- `parse_emails_response(json)` → primary verified email
- Error responses → `AuthError`

### Test file structure

```
test/
├── vestibule_test.gleam
├── vestibule/
│   ├── state_test.gleam
│   ├── config_test.gleam
│   └── strategy/
│       └── github_test.gleam
```

---

## Build Order

1. Add dependencies to `gleam.toml`
2. `error.gleam` — standalone, no deps
3. `user_info.gleam` — standalone
4. `credentials.gleam` — standalone
5. `config.gleam` + tests — standalone
6. `auth.gleam` — depends on user_info, credentials
7. `strategy.gleam` — depends on config, credentials, user_info, error
8. `state.gleam` + tests — depends on error, gleam_crypto
9. `strategy/github.gleam` + tests — depends on all above + glow_auth + httpc + json
10. `vestibule.gleam` + tests — orchestrator, depends on all above
