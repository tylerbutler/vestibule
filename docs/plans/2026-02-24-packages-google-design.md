# Provider Packages Layout & Google Strategy — Design

## Context

Provider strategies should be independently publishable packages so third parties can contribute providers without modifying the core library. This restructures the repo to use a `packages/` directory with per-provider Gleam packages, moves Microsoft out of core, and adds a full Google OAuth implementation.

## Package Layout

```
vestibule/                          # core (Hex: vestibule)
├── src/vestibule/
│   ├── strategy.gleam              # Strategy(e) type
│   ├── error.gleam                 # AuthError(e) + Custom(e)
│   ├── registry.gleam              # Registry(e)
│   └── strategy/
│       └── github.gleam            # bundled GitHub provider
├── packages/
│   ├── vestibule_microsoft/        # Hex: vestibule_microsoft
│   │   ├── gleam.toml
│   │   ├── src/vestibule_microsoft.gleam
│   │   └── test/vestibule_microsoft_test.gleam
│   └── vestibule_google/           # Hex: vestibule_google
│       ├── gleam.toml
│       ├── src/vestibule_google.gleam
│       └── test/vestibule_google_test.gleam
└── example/                        # demo app (not published)
    └── gleam.toml                  # depends on all three
```

## Key Decisions

- **GitHub stays in core** — it's the canonical example and most common provider.
- **Microsoft moves** from `src/vestibule/strategy/microsoft.gleam` to `packages/vestibule_microsoft/`.
- **Naming**: `vestibule_<provider>` (matches Gleam convention: `gleam_json`, `gleam_http`).
- **Module names**: Each package exports a flat module matching the package name — `vestibule_google.strategy()`, not `vestibule/strategy/google`.
- **Path dependencies for dev**: `vestibule = { path = "../.." }` in each provider's `gleam.toml`. Swapped to Hex version constraint for publishing.

## Google Strategy

### OAuth Endpoints
- **Authorize**: `https://accounts.google.com/o/oauth2/v2/auth`
- **Token exchange**: `https://oauth2.googleapis.com/token`
- **User info**: `https://www.googleapis.com/oauth2/v3/userinfo`

### Default Scopes
`["openid", "profile", "email"]`

### Token Response
Google returns standard OAuth2 JSON: `access_token`, `token_type`, `expires_in`, `scope`, and optionally `refresh_token` (only on first consent with `access_type=offline`). Scopes are space-delimited.

### User Info Response (`/oauth2/v3/userinfo`)
```json
{
  "sub": "1234567890",
  "name": "Jane Doe",
  "given_name": "Jane",
  "family_name": "Doe",
  "picture": "https://lh3.googleusercontent.com/...",
  "email": "jane@example.com",
  "email_verified": true
}
```

Mapping to `UserInfo`:
- `sub` → uid
- `name` → name
- `email` → email (only if `email_verified` is true)
- `email` → nickname (always, as Google has no username concept)
- `picture` → image
- `description` → None (Google doesn't have a bio field)

### Exported API
```gleam
pub fn strategy() -> Strategy(e)
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e))
pub fn parse_user_response(body: String) -> Result(#(String, UserInfo), AuthError(e))
```

## Example App Updates

- Add `vestibule_google` and `vestibule_microsoft` as path dependencies
- Update imports from `vestibule/strategy/microsoft` to `vestibule_microsoft`
- Add Google credential loading alongside GitHub and Microsoft
- Update `.env.example` with `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`

## Verification

Each provider package runs independently:
```bash
cd packages/vestibule_google && gleam test
cd packages/vestibule_microsoft && gleam test
```

Core library unaffected:
```bash
gleam test   # from repo root
```

Example app compiles with all three:
```bash
cd example && gleam build && gleam test
```
