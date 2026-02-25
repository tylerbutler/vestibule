# Microsoft Strategy, Provider Registry & Example App Updates — Design

## Goal

Add a Microsoft OAuth strategy, a provider registry for managing multiple strategies, and update the example app to support multiple providers with dynamic UI.

## Scope

1. **Microsoft strategy** (`vestibule/strategy/microsoft.gleam`)
2. **Provider registry** (`vestibule/registry.gleam`)
3. **Example app updates** — multi-provider support with graceful credential loading

---

## 1. Microsoft Strategy

### Overview

Follows the same pattern as the GitHub strategy — a `strategy()` function returning a `Strategy` record with three callbacks: `authorize_url`, `exchange_code`, `fetch_user`.

### Endpoints

| Endpoint | URL |
|----------|-----|
| Authorize | `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` |
| Token | `https://login.microsoftonline.com/common/oauth2/v2.0/token` |
| User info | `https://graph.microsoft.com/v1.0/me` |

Uses `/common` tenant — works with any Microsoft account (personal + work/school).

### Default Scopes

`["User.Read"]`

### Token Handling

Microsoft token responses include `refresh_token` and `expires_in`, unlike GitHub. Both are stored in `Credentials`:
- `refresh_token` → `option.Some(refresh_token)`
- `expires_in` → stored as raw seconds in `expires_at` (no clock dependency, consumer calculates absolute time if needed)

### User Info Mapping

Single Microsoft Graph `/me` call (no separate email endpoint).

| Microsoft Graph field | UserInfo field |
|---|---|
| `displayName` | `name` |
| `mail` (fallback: `userPrincipalName`) | `email` |
| `userPrincipalName` | `nickname` |
| Gravatar URL from SHA-256 email hash | `image` (fallback, no API call) |
| `jobTitle` | `description` |

**Profile photo**: Microsoft Graph returns binary image data at `/me/photo/$value`, which requires auth headers — not usable as a plain URL. Instead, we construct a Gravatar URL from the email's SHA-256 hash (`https://www.gravatar.com/avatar/{sha256}?d=identicon`). If no email, `image` is `None`.

### Differences from GitHub

- Token response includes `refresh_token` and `expires_in`
- User info from single `/me` call (no separate email endpoint)
- UID is Microsoft `id` (already a string)
- No `User-Agent` header required
- Gravatar fallback for profile image

### Exported Test Helpers

Following GitHub's pattern: `parse_token_response`, `parse_user_response`

### File

`src/vestibule/strategy/microsoft.gleam`

---

## 2. Provider Registry

### Overview

A convenience type that maps provider names to `Strategy + Config` pairs. Defined in the PRD as FR-7.

### API

```gleam
pub opaque type Registry {
  Registry(providers: Dict(String, #(Strategy, Config)))
}

pub fn new() -> Registry
pub fn register(registry: Registry, strategy: Strategy, config: Config) -> Registry
pub fn get(registry: Registry, provider: String) -> Result(#(Strategy, Config), Nil)
pub fn providers(registry: Registry) -> List(String)
```

### Design Decisions

- **Opaque type** wrapping `Dict(String, #(Strategy, Config))` — encapsulation with O(log n) lookup
- **`providers()` function** returns list of registered provider names — needed for dynamic UI rendering
- **Provider name** keyed from `strategy.provider` field (e.g., "github", "microsoft")
- **No changes to core API** — `vestibule.authorize_url` and `vestibule.handle_callback` still take `Strategy + Config` directly. Registry is a convenience layer.

### File

`src/vestibule/registry.gleam`

---

## 3. Example App Updates

### Router Context

Changes from single strategy to registry:

```gleam
pub type Context {
  Context(registry: Registry)
}
```

### Routes

| Route | Method | Behavior |
|-------|--------|----------|
| `GET /` | Landing page — queries registry, renders button per provider |
| `GET /auth/:provider` | Look up provider in registry, generate auth URL, redirect |
| `GET /auth/:provider/callback` | Look up provider in registry, complete OAuth flow |
| `*` | 404 |

### Graceful Credential Loading

In `vestibule_example.gleam`:
- Check `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` → register GitHub if both set
- Check `MICROSOFT_CLIENT_ID` + `MICROSOFT_CLIENT_SECRET` → register Microsoft if both set
- If neither set, crash with helpful message
- If only one set, start with just that provider

### Pages Changes

- `landing(providers: List(String))` — takes provider names, renders a button per provider dynamically
- `success(auth)` — unchanged
- `error(err)` — unchanged

### Session/Cookie

Session cookie (`vestibule_session`) stays the same — CSRF state is per-auth-attempt, not per-provider. Both providers share the same ETS session store.

### .env.example

```
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
MICROSOFT_CLIENT_ID=...
MICROSOFT_CLIENT_SECRET=...
```
