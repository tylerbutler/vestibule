# Gleam Authentication Strategies Library - Product Requirements Document

**Version:** 1.0  
**Date:** February 2026  
**Status:** Draft  

---

## 1. Overview

### 1.1 Problem Statement

The Gleam ecosystem lacks a unified authentication strategy framework. Developers wanting to add social login (Google, GitHub, Microsoft, etc.) must hand-roll OAuth flows on top of low-level primitives like `glow_auth`. Each implementation requires understanding provider-specific quirks (authorization URLs, token exchange, user info endpoints, scope formats, response shapes) and building the same request/callback plumbing from scratch.

The Elixir ecosystem solved this with Ueberauth — a two-phase strategy pattern that normalizes provider-specific authentication into a consistent result type. No equivalent exists for Gleam.

### 1.2 Existing Landscape

| Package | What It Does | What's Missing |
|---------|-------------|----------------|
| **glow_auth** | Low-level OAuth 2.0 RFC 6749 helpers (auth URLs, token requests, token decoding) | No provider-specific logic, no user info fetching, no strategy pattern |
| **glebs** | OAuth PKCE for browser/Lustre apps | Client-side only, no server callback handling |
| **Pevensie Auth** | Email/password auth with sessions, driver-based storage | OAuth2 listed as "planned" — focused on full-stack auth, not strategy abstraction |
| **wisp_kv_sessions** | Session management for Wisp | Sessions only, no authentication |
| **wisp_basic_auth** | HTTP Basic Auth for Wisp | Single mechanism, no social providers |

**The gap:** A middleware-level library that handles "redirect to provider → handle callback → normalized user info" across providers with a pluggable strategy interface.

### 1.3 Vision

Build a strategy-based authentication library for Gleam that provides a consistent interface across identity providers. The library should make adding social login to a Wisp application take minutes, not hours, while remaining framework-agnostic at its core.

### 1.4 Success Criteria

- Add GitHub login to a Wisp app in under 20 lines of configuration + handler code
- Consistent `Auth` result type regardless of provider
- At least 3 provider strategies at launch (GitHub, Google, Microsoft)
- Builds on `glow_auth` for OAuth2 plumbing rather than reimplementing
- Works on Erlang target (primary); JS target for core types only

---

## 2. Target Users

### 2.1 Primary Users

| User Type | Needs | Example Use Case |
|-----------|-------|------------------|
| **Web App Developer** | Quick social login integration with Wisp | Adding "Sign in with GitHub" to a side project |
| **SaaS Builder** | Multiple providers with consistent handling | Supporting Google, GitHub, and email/password login |
| **Strategy Author** | Clean interface for adding new providers | Publishing a strategy for a niche provider (Twitch, Spotify, etc.) |

### 2.2 User Stories

1. **As a web app developer**, I want to add GitHub login by configuring a strategy and handling one callback, so that I don't need to understand OAuth2 internals.

2. **As a SaaS builder**, I want a consistent `Auth` result type from any provider so that my user creation logic works identically regardless of how someone signs in.

3. **As a strategy author**, I want a clear interface to implement so that I can publish a strategy package for my provider without coordinating with the core library.

4. **As an application developer**, I want the library to handle CSRF state parameter generation and validation so that I don't accidentally ship a security vulnerability.

---

## 3. Goals and Non-Goals

### 3.1 Goals

| Priority | Goal |
|----------|------|
| **P0** | Strategy interface (record of functions) for OAuth2 providers |
| **P0** | Normalized `Auth` result type (uid, provider, user info, credentials) |
| **P0** | CSRF state parameter generation and validation |
| **P0** | Built-in strategies: GitHub, Google, Microsoft |
| **P1** | Wisp middleware for request/callback routing |
| **P1** | Configurable scopes per provider |
| **P1** | PKCE support for providers that require/recommend it |
| **P2** | Non-OAuth strategies (email/password, magic link) |
| **P2** | Token refresh utilities |
| **P2** | OpenID Connect (OIDC) discovery support |

### 3.2 Non-Goals

- **Session management** — Use Pevensie, wisp_kv_sessions, or roll your own
- **User storage/database** — The library produces an `Auth` result; persistence is your concern
- **Account linking** — Multi-provider account merging is application-level logic
- **Authorization/permissions** — Out of scope; this is authentication only
- **JavaScript target runtime** — OAuth callbacks require a server; core types can be cross-target but runtime is Erlang-focused
- **Built-in UI** — No login pages or buttons; this is backend plumbing

---

## 4. Architecture

### 4.1 Two-Phase Flow

Following Ueberauth's proven model, authentication proceeds in two phases:

```
Phase 1: REQUEST                    Phase 2: CALLBACK
─────────────────                   ──────────────────
User clicks "Sign in with GitHub"   Provider redirects back with ?code=...
  → Library generates state param     → Library validates state param
  → Library builds authorize URL      → Library exchanges code for token
  → Redirect user to provider         → Library fetches user info from provider
                                      → Library returns normalized Auth result
```

### 4.2 Core Design: Strategy as Data

Unlike Ueberauth's behaviour/macro approach, strategies are **records of functions** — idiomatic Gleam, no magic:

```gleam
/// A strategy is a record containing the functions needed
/// to authenticate with a specific provider.
pub type Strategy {
  Strategy(
    /// Human-readable provider name (e.g., "github", "google")
    provider: String,
    /// Build the authorization URL to redirect the user to
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError),
    /// Exchange an authorization code for credentials
    exchange_code: fn(Config, String) ->
      Result(Credentials, AuthError),
    /// Fetch user info using the obtained credentials
    fetch_user: fn(Credentials) ->
      Result(UserInfo, AuthError),
  )
}
```

### 4.3 Core Types

```gleam
/// The normalized result of a successful authentication.
pub type Auth {
  Auth(
    /// Unique identifier from the provider (e.g., GitHub user ID)
    uid: String,
    /// Provider name matching the strategy
    provider: String,
    /// Normalized user information
    info: UserInfo,
    /// OAuth credentials (tokens, expiry)
    credentials: Credentials,
    /// Provider-specific extra data
    extra: Dict(String, Dynamic),
  )
}

/// Normalized user information across all providers.
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

/// OAuth credentials from the provider.
pub type Credentials {
  Credentials(
    token: String,
    refresh_token: Option(String),
    token_type: String,
    expires_at: Option(Int),
    scopes: List(String),
  )
}

/// Authentication failure.
pub type AuthError {
  StateMismatch
  CodeExchangeFailed(reason: String)
  UserInfoFailed(reason: String)
  ProviderError(code: String, description: String)
  NetworkError(reason: String)
  ConfigError(reason: String)
}

/// Provider configuration.
pub type Config {
  Config(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: List(String),
    extra_params: Dict(String, String),
  )
}
```

### 4.4 Result Type

The callback phase produces:

```gleam
pub type AuthResult {
  Success(auth: Auth)
  Failure(errors: List(AuthError))
}
```

---

## 5. Functional Requirements

### 5.1 Request Phase

#### FR-1: Authorization URL Generation

```gleam
/// Generate the authorization URL for a given strategy.
/// State parameter is generated internally for CSRF protection.
pub fn authorize_url(
  strategy: Strategy,
  config: Config,
) -> Result(#(String, String), AuthError)
// Returns #(url, state) — caller stores state in session
```

#### FR-2: State Parameter

- MUST generate a cryptographically random state parameter
- MUST return the state so the caller can store it in their session
- MUST validate state on callback to prevent CSRF attacks

#### FR-3: Scope Handling

- Default scopes SHOULD be defined per strategy
- Config scopes MUST override defaults when provided
- Scope format MUST match provider expectations (space-separated vs comma-separated)

### 5.2 Callback Phase

#### FR-4: Code Exchange

```gleam
/// Handle the callback from the provider.
/// Validates state, exchanges code for tokens, fetches user info.
pub fn handle_callback(
  strategy: Strategy,
  config: Config,
  callback_params: Dict(String, String),
  expected_state: String,
) -> Result(Auth, AuthError)
```

#### FR-5: Error Handling

- Provider errors (user denied, invalid scope) MUST be captured as `AuthError`
- Network failures during token exchange MUST NOT crash the application
- Missing or unexpected callback parameters MUST produce clear errors

### 5.3 Wisp Integration

#### FR-6: Middleware

```gleam
/// Wisp middleware that handles the two-phase auth flow.
///
/// Usage:
/// ```gleam
/// fn handle_request(req: Request, ctx: Context) -> Response {
///   case wisp.path_segments(req) {
///     ["auth", provider] -> auth.request_phase(req, ctx, provider)
///     ["auth", provider, "callback"] -> auth.callback_phase(req, ctx, provider)
///     _ -> // ... your routes
///   }
/// }
/// ```
```

#### FR-7: Provider Registry

```gleam
/// Register strategies with their configs.
pub type Registry

pub fn new() -> Registry

pub fn register(
  registry: Registry,
  strategy: Strategy,
  config: Config,
) -> Registry

pub fn get(
  registry: Registry,
  provider: String,
) -> Result(#(Strategy, Config), Nil)
```

### 5.4 Built-in Strategies

#### FR-8: GitHub Strategy

| Field | Details |
|-------|---------|
| Authorize URL | `https://github.com/login/oauth/authorize` |
| Token URL | `https://github.com/login/oauth/access_token` |
| User Info URL | `https://api.github.com/user` |
| Email URL | `https://api.github.com/user/emails` (for primary verified email) |
| Default Scopes | `["user:email"]` |
| UID | GitHub user ID (integer as string) |

#### FR-9: Google Strategy

| Field | Details |
|-------|---------|
| Authorize URL | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token URL | `https://oauth2.googleapis.com/token` |
| User Info URL | `https://www.googleapis.com/oauth2/v3/userinfo` |
| Default Scopes | `["openid", "email", "profile"]` |
| UID | Google `sub` claim |
| Notes | PKCE recommended |

#### FR-10: Microsoft Strategy

| Field | Details |
|-------|---------|
| Authorize URL | `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` |
| Token URL | `https://login.microsoftonline.com/common/oauth2/v2.0/token` |
| User Info URL | `https://graph.microsoft.com/v1.0/me` |
| Default Scopes | `["openid", "email", "profile", "User.Read"]` |
| UID | Microsoft `id` (object ID) |
| Notes | Uses `/common` tenant for multi-tenant; PKCE recommended |

---

## 6. Security Requirements

### SR-1: State Parameter Validation

- State MUST be at least 32 bytes of cryptographically random data
- State MUST be validated via constant-time comparison
- Missing state on callback MUST be rejected

### SR-2: Token Handling

- Access tokens MUST NOT be logged
- Client secrets MUST NOT appear in URLs or logs
- Token exchange MUST use POST, not GET

### SR-3: HTTPS

- Authorization URLs MUST use HTTPS
- Token exchange MUST use HTTPS
- User info requests MUST use HTTPS

### SR-4: PKCE

- PKCE SHOULD be supported for all providers
- PKCE MUST be used for providers that require it
- Code verifier MUST be at least 43 characters

---

## 7. API Design Principles

### 7.1 Progressive Disclosure

```gleam
// Level 1: Quick setup with defaults
let github = github.strategy()
let config = auth.config(
  client_id: "...",
  client_secret: "...",
  redirect_uri: "http://localhost:3000/auth/github/callback",
)

// Level 2: Custom scopes
let config = auth.config(
  client_id: "...",
  client_secret: "...",
  redirect_uri: "...",
)
|> auth.with_scopes(["user:email", "read:org"])

// Level 3: Full control
let config = auth.config(...)
|> auth.with_scopes([...])
|> auth.with_extra_params([#("allow_signup", "false")])
```

### 7.2 Build on glow_auth

The library SHOULD use `glow_auth` for:
- Authorization URI construction
- Token request execution
- Access token decoding

This avoids reimplementing OAuth2 fundamentals and benefits from glow_auth's maintenance.

### 7.3 Strategy as a Separate Package Pattern

Each provider strategy CAN be published as a separate hex package:

```
your_auth_lib           # Core types + middleware
your_auth_lib_github    # GitHub strategy
your_auth_lib_google    # Google strategy
your_auth_lib_microsoft # Microsoft strategy
```

However, for initial launch, bundling the top 3 providers in the core package reduces friction. Separate packages make sense once community strategies emerge.

**Recommended approach:** Ship core + GitHub/Google/Microsoft together initially. Extract to separate packages if/when the strategy count grows beyond ~5.

### 7.4 Type Safety

- Provider names are strings (not a closed union) to allow community strategies
- User info fields are `Option` types — providers vary in what they return
- Extra data is `Dict(String, Dynamic)` for provider-specific fields
- Errors are a well-defined custom type, not opaque strings

---

## 8. Module Structure

```
src/
├── {lib_name}.gleam                # Public API: authorize_url, handle_callback
├── {lib_name}/
│   ├── auth.gleam                  # Auth, AuthResult types
│   ├── config.gleam                # Config type and builders
│   ├── credentials.gleam           # Credentials type
│   ├── user_info.gleam             # UserInfo type
│   ├── strategy.gleam              # Strategy type definition
│   ├── state.gleam                 # CSRF state generation/validation
│   ├── registry.gleam              # Provider registry
│   ├── error.gleam                 # AuthError type
│   ├── wisp.gleam                  # Wisp middleware integration
│   └── strategy/
│       ├── github.gleam            # GitHub strategy
│       ├── google.gleam            # Google strategy
│       └── microsoft.gleam          # Microsoft strategy
```

---

## 9. Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| `gleam_stdlib` | Core types | Yes |
| `gleam_http` | Request/Response types | Yes |
| `gleam_json` | Parsing provider responses | Yes |
| `gleam_crypto` | State parameter generation, constant-time comparison | Yes |
| `glow_auth` | OAuth2 protocol helpers | Yes |
| `gleam_httpc` | Making HTTP requests to providers | Yes |
| `wisp` | Framework integration | Optional (dev dependency or soft dep) |

---

## 10. Relationship to Pevensie

Pevensie Auth is building toward a full-stack auth solution (users, sessions, permissions) with OAuth2 on their roadmap. This library is **complementary, not competing**:

| Concern | This Library | Pevensie Auth |
|---------|-------------|---------------|
| OAuth flow orchestration | ✅ | Planned |
| Normalized user info | ✅ | — |
| Provider strategies | ✅ | — |
| User storage | — | ✅ |
| Sessions | — | ✅ |
| Email/password auth | — | ✅ |
| Account management | — | ✅ |

**Ideal integration:** This library produces an `Auth` result → Pevensie (or your own code) creates/finds a user and establishes a session. The libraries compose rather than overlap.

---

## 11. Implementation Phases

### Phase 1: Core + GitHub (MVP)

- [ ] Core types: Auth, UserInfo, Credentials, AuthError, Config
- [ ] Strategy type definition
- [ ] State parameter generation and validation
- [ ] authorize_url and handle_callback functions
- [ ] GitHub strategy (with email fetching)
- [ ] Basic Wisp middleware helper
- [ ] Integration with glow_auth

**Deliverable:** Working GitHub login in a Wisp app

### Phase 2: More Providers + Polish

- [ ] Google strategy (with PKCE)
- [ ] Microsoft strategy
- [ ] Provider registry
- [ ] Configurable scopes and extra params
- [ ] Comprehensive error messages
- [ ] Example Wisp application

**Deliverable:** Production-usable with 3 providers

### Phase 3: Ecosystem Growth

- [ ] OIDC discovery support
- [ ] PKCE for all providers
- [ ] Token refresh utilities
- [ ] Strategy authoring guide (for community contributions)
- [ ] Separate strategy packages (if warranted)
- [ ] Apple Sign In strategy
- [ ] Microsoft/Azure AD strategy

**Deliverable:** Mature library with ecosystem for community strategies

---

## 12. Testing Strategy

### 12.1 Unit Tests

- State parameter generation (randomness, length)
- State validation (match, mismatch, constant-time)
- Config construction and scope merging
- User info normalization from provider-specific JSON
- Error type construction

### 12.2 Integration Tests

- Full OAuth flow with mocked HTTP responses per provider
- Wisp middleware routing
- Error handling for malformed callbacks
- Missing/extra callback parameters

### 12.3 Manual/Example Tests

- Example Wisp application with GitHub login
- Document manual testing flow for real OAuth (requires app credentials)

---

## 13. Documentation Plan

### 13.1 README

- 30-second quick start with GitHub login
- Minimal Wisp example
- Link to hexdocs

### 13.2 Hexdocs

- Complete API documentation
- Per-strategy setup guides (with screenshots of provider console setup)
- Security considerations

### 13.3 Guides

- "Adding GitHub login to your Wisp app"
- "Writing a custom strategy"
- "Using with Pevensie Auth"

---

## 14. Name Brainstorming

### Criteria

- Short and memorable
- Available on hex.pm
- Evocative of authentication/identity/entry without being generic
- Fits the Gleam ecosystem naming style (short, non-prefixed names like birch, wisp, lustre, mist)

### Candidates

| Name | Meaning/Vibe | Pros | Cons |
|------|-------------|------|------|
| **vestibule** | Entrance hall; transitional space before the interior | Perfect metaphor — the space between outside and inside, exactly what auth is. Architectural, distinctive. | Long (9 chars). Potentially hard to spell. |
| **postern** | A secondary gate in a castle wall | Evokes controlled entry. Historical charm. Short-ish. | Obscure word; most devs won't know it. |
| **wicket** | A small gate within a larger gate | Great metaphor — a controlled entry point. Short, punchy. | Cricket associations (especially for Commonwealth devs). |
| **usher** | One who guides people to their place | Strong verb form ("usher them in"). Clear metaphor. | The singer. Also taken on hex.pm (need to verify). |
| **turnstile** | Controlled entry mechanism | Very clear metaphor for auth. | Long. Cloudflare's CAPTCHA product uses this name. |
| **portico** | Covered entrance to a building | Elegant, architectural. Same vein as vestibule but shorter. | Might sound too generic. |
| **atrium** | Open entrance court | Short, elegant. | Taken (likely). More "space" than "gate." |
| **sally** | As in sally port — a secure gate for controlled exit/entry | Short, friendly, unexpected. | People will think it's a person's name. |
| **drawbridge** | Controlled access to a castle | Very clear metaphor. | Way too long. |
| **gatehouse** | Structure controlling entry to a fortified area | Perfect concept — the place where you prove who you are. | Long (9 chars). |
| **portcullis** | Heavy gate protecting a castle entrance | Strong metaphor for protection + entry. | Long (10 chars). Hard to type. |
| **alcove** | Recessed area; sheltered space | Short, pleasant. | Weak connection to auth concept. |
| **foyer** | Entry room | Short (5 chars), clear entry metaphor. French origin. | Might be taken. Sounds like a real estate term. |
| **threshold** | Point of entry | Conceptually perfect. | Very long (9 chars). |
| **latch** | Simple fastening/opening mechanism | Short (5 chars), clear verb ("latch the door"). | Might be taken. Sounds like a state management lib. |
| **wicketgate** | The small door within the large gate | More specific than wicket alone. Bunyan's Pilgrim's Progress reference. | Compound word, long. |
| **badge** | Proof of identity/access | Short, clear auth metaphor. Very verb-able. | Generic. Likely taken. |

### Top 3 Recommendations

1. **vestibule** — The strongest metaphor. A vestibule is literally the transitional space between outside (unauthenticated) and inside (authenticated). Architecturally elegant, memorable, and unlikely to conflict with existing packages. The length is a minor downside but the name is very typeable.

2. **wicket** — Short, punchy, and the metaphor works: a small controlled gate. The cricket association is actually fine — it makes the name memorable and searchable. At 6 characters, it's easy to type and import.

3. **portico** — A covered entrance space. Shorter than vestibule, same architectural vibe, and very pleasant to say. Good middle ground between metaphorical precision and brevity.

### Names to Avoid

- **herald** — Taken on hex.pm (Elixir message validation library)
- **envoy** — Taken on hex.pm (Gleam env var library by lpil)
- **sentry** — Conflicts with the error monitoring service
- **passport** — Conflicts with the popular Node.js auth library
- **guardian** — Conflicts with the Elixir auth library

---

## Appendix A: Example Usage

### Minimal Wisp Application

```gleam
import gleam/io
import gleam/result
import wisp.{type Request, type Response}
import vestibule as auth
import vestibule/strategy/github

pub type Context {
  Context(
    auth_registry: auth.Registry,
    // ... your other context
  )
}

pub fn setup() -> Context {
  let registry = auth.new_registry()
    |> auth.register(
      github.strategy(),
      auth.config(
        client_id: "your_client_id",
        client_secret: "your_client_secret",
        redirect_uri: "http://localhost:3000/auth/github/callback",
      ),
    )

  Context(auth_registry: registry)
}

pub fn handle_request(req: Request, ctx: Context) -> Response {
  case wisp.path_segments(req) {
    // Phase 1: Redirect to provider
    ["auth", provider] -> {
      case auth.begin(ctx.auth_registry, provider) {
        Ok(#(redirect_url, state)) -> {
          // Store state in session, redirect user
          wisp.redirect(redirect_url)
          |> wisp.set_cookie(req, "auth_state", state, wisp.Signed, 300)
        }
        Error(e) -> wisp.bad_request()
      }
    }

    // Phase 2: Handle callback
    ["auth", provider, "callback"] -> {
      let state = wisp.get_cookie(req, "auth_state", wisp.Signed)
      let params = wisp.get_query(req)

      case auth.complete(ctx.auth_registry, provider, params, state) {
        Ok(authed) -> {
          // authed.uid, authed.info.email, authed.credentials.token
          // Create or find user, establish session, redirect
          io.println("Authenticated: " <> authed.info.name |> result.unwrap("unknown"))
          wisp.redirect("/dashboard")
        }
        Error(auth.StateMismatch) -> wisp.bad_request()
        Error(e) -> wisp.internal_server_error()
      }
    }

    _ -> wisp.ok()
  }
}
```

### Writing a Custom Strategy

```gleam
import vestibule as auth
import vestibule/strategy.{type Strategy, Strategy}
import gleam/http/request
import gleam/json

/// Create a Twitch authentication strategy.
pub fn strategy() -> Strategy {
  Strategy(
    provider: "twitch",
    authorize_url: fn(config, scopes, state) {
      // Build Twitch-specific authorize URL
      // ...
      Ok(url)
    },
    exchange_code: fn(config, code) {
      // Exchange code for Twitch token
      // ...
      Ok(credentials)
    },
    fetch_user: fn(credentials) {
      // Fetch user from Twitch API
      // ...
      Ok(user_info)
    },
  )
}
```

---

## Appendix B: Ueberauth Comparison

| Aspect | Ueberauth (Elixir) | This Library (Gleam) |
|--------|--------------------|--------------------|
| Strategy definition | Elixir behaviour + macros | Record of functions |
| Configuration | Compile-time config files | Runtime config values |
| Integration | Plug pipeline (implicit) | Explicit function calls |
| State management | Plug.Conn assigns (mutable) | Return values (pure) |
| Provider routing | Automatic via Plug | Manual pattern matching (or middleware helper) |
| OAuth2 layer | Bundled (ueberauth_strategy_helpers) | Delegates to glow_auth |
| Community strategies | ~40+ packages | Start with 3, grow organically |
