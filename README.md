# vestibule

Strategy-based OAuth2 authentication for Gleam.

The name "vestibule" refers to an entrance hall — the transitional space between outside (unauthenticated) and inside (authenticated).

[![Package Version](https://img.shields.io/hexpm/v/vestibule)](https://hex.pm/packages/vestibule)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/vestibule/)

> [!NOTE]
> vestibule follows [Semantic Versioning](https://semver.org/) for 1.0 and
> later releases. Public APIs are intended to be stable across patch and minor
> releases; breaking changes are reserved for major versions.
>
> OAuth security depends on application configuration too: production redirect
> URIs must use HTTPS. `http://localhost` and `http://127.0.0.1` redirect URIs
> are allowed for local development only.

## Quick Start

Add vestibule to your project. If you're using the Wisp middleware, add
`vestibule_wisp` too:

```sh
gleam add vestibule
gleam add vestibule_wisp
```

GitHub support is built into the core package, so you can start with the
two-phase flow directly:

```gleam
import gleam/dict
import vestibule
import vestibule/config
import vestibule/strategy/github

let strategy = github.strategy()
let cfg =
  config.new(
    "client_id",
    "client_secret",
    "http://localhost:8000/auth/github/callback",
  )

// Phase 1: Generate authorization URL and redirect user
let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
// Store auth_request.state and auth_request.code_verifier server-side,
// bound to this user's session, with an expiration time.
// Redirect user to auth_request.url

// Phase 2: Handle the callback
let params =
  dict.from_list([
    #("state", "state from callback"),
    #("code", "authorization code from callback"),
  ])

let assert Ok(auth) =
  vestibule.handle_callback(
    strategy,
    cfg,
    params,
    "expected state from session",
    "code verifier from session",
  )
// Delete the stored state and code verifier after a successful callback.
// auth.uid, auth.info.email, credentials.token(auth.credentials)
```

Store `state` and the PKCE `code_verifier` on the server, bound to the user's
session. Expire them quickly, reject callbacks with missing or mismatched
values, and delete both values after a successful callback so they cannot be
replayed.

Or use the `vestibule_wisp` middleware for a higher-level API:

```gleam
import gleam/http
import wisp
import vestibule/config
import vestibule/registry
import vestibule/strategy/github
import vestibule_wisp
import vestibule_wisp/state_store

// Initialize once at startup
let reg =
  registry.new()
  |> registry.register(
    github.strategy(),
    config.new(
      "client_id",
      "client_secret",
      "http://localhost:8000/auth/github/callback",
    ),
  )
let store = state_store.init()

// In your router
case wisp.path_segments(req), req.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase(req, reg, provider, store)
  // Accept both GET and POST — Apple uses response_mode=form_post
  ["auth", provider, "callback"], http.Get
  | ["auth", provider, "callback"], http.Post
  ->
    vestibule_wisp.callback_phase(req, reg, provider, store, fn(auth) {
      // auth.uid, auth.info.name, auth.info.email
      wisp.redirect("/dashboard")
    })
  _, _ -> wisp.not_found()
}
```

The Wisp state store creates a named ETS table, so initialize it once per BEAM
VM at startup. Use `state_store.try_init` if you want to handle duplicate-table
errors explicitly.

If you want to handle callback failures yourself instead of using the default
HTML error page, use `vestibule_wisp.callback_phase_result`. Use
`vestibule_wisp.callback_phase_auth_result` when you need structured errors such
as `UnknownProvider`, `MissingSessionCookie`, `SessionExpired`,
`InvalidCallbackParams`, or `AuthFailed`. Missing or invalid callback `state` and
`code` values are provider/authentication failures and are reported through
`AuthFailed`.

## Packages

| Package | Description | Install |
|---------|-------------|---------|
| `vestibule` | Core types, two-phase OAuth2 flow, PKCE, token refresh | `gleam add vestibule` |
| `vestibule_wisp` | Wisp middleware for request/callback routing | `gleam add vestibule_wisp` |
| `vestibule_google` | Google OAuth strategy | `gleam add vestibule_google` |
| `vestibule_microsoft` | Microsoft OAuth strategy | `gleam add vestibule_microsoft` |
| `vestibule_apple` | Apple Sign In strategy | `gleam add vestibule_apple` |

GitHub is included in the core `vestibule` package.

## How It Works

Vestibule uses a two-phase OAuth2 flow inspired by Elixir's Ueberauth:

1. **Request phase** — Generate an authorization URL with CSRF state and PKCE, redirect the user to the provider
2. **Callback phase** — Validate state, exchange the authorization code for tokens, fetch user info, return a normalized `Auth` result

Strategies are records of functions — no behaviours, macros, or magic. Each strategy tells vestibule how to talk to a specific provider.

## More Features

Use a registry to support multiple providers in one app:

```gleam
let reg =
  registry.new()
  |> registry.register(github.strategy(), github_cfg)
  |> registry.register(vestibule_google.strategy(), google_cfg)
```

Refresh access tokens when a provider issues refresh tokens:

```gleam
let assert Ok(updated) =
  vestibule.refresh_token(strategy, cfg, refresh_token)
```

Add provider-specific authorization parameters when a provider requires them:

```gleam
let assert Ok(google_cfg) =
  config.new(
    "google-client-id",
    "google-client-secret",
    "http://localhost:8000/auth/google/callback",
  )
  |> config.with_extra_params([
    #("access_type", "offline"),
    #("prompt", "consent"),
  ])
```

`config.with_extra_params` returns a `Result` because reserved OAuth
authorization parameters such as `state`, `client_id`, and `code_challenge`
cannot be overridden. Valid parameters are appended to the authorization URL.
Common examples include Google's `access_type=offline` and `prompt=consent` for
refresh tokens, or Microsoft's `prompt=select_account` and `login_hint`.

Discover OpenID Connect providers from their issuer URL:

```gleam
let assert Ok(strategy) = oidc.discover("https://accounts.google.com")
```

## Security

Vestibule implements the OAuth 2.0 / OIDC pieces that protect against
common attacks, but a few responsibilities remain with the consuming app.

**Built in**

- **PKCE (RFC 7636)** — every authorization request gets a 256-bit
  `code_verifier` and an `S256` `code_challenge`. Stored verifiers must
  be sent with the token exchange.
- **CSRF state** — every request gets a 256-bit base64url state token.
  `state.validate` does a constant-time comparison and rejects empty
  values. Validation runs before any provider response detail is surfaced.
- **HTTPS enforcement** — production redirect URIs and OIDC issuers
  must use HTTPS. `http://localhost` and `http://127.0.0.1` are
  permitted for development only.
- **JWT signature verification (Apple)** — Apple ID tokens are
  verified against Apple's published JWKS (ES256) and validated for
  `iss`, `aud`, and `exp` with a 60-second clock skew.
- **Verified-email gating (OIDC, Google, Apple)** — `UserInfo.email`
  is only populated when the provider reports `email_verified`.

**Caller responsibilities**

- **Persist `state` and `code_verifier`** server-side, bound to the
  user's session, with a short TTL. Reject callbacks that are missing
  either, and **delete both after a successful callback** so they
  cannot be replayed. The `vestibule_wisp` middleware handles this
  via single-use ETS entries.
- **Redact `Credentials` and `Auth`** in logs and error reports.
  Access tokens, refresh tokens, and ID tokens are bearer credentials —
  treat them like passwords.
- **Cookie-secret rotation** invalidates in-flight OAuth flows that
  used the signed session cookie. Time rotations accordingly.
- **OIDC `nonce`** is not currently generated or validated by the
  discover-built strategy. If you need id_token replay protection
  beyond PKCE, validate the `nonce` yourself when consuming the
  `id_token` artifact returned in `ExchangeResult`.

## API Notes

The 1.0 API intentionally keeps provider behavior explicit:

- `Credentials.expires_at` was replaced with `Credentials.expires_in`. The value
  is the provider's relative `expires_in` duration in seconds, not an absolute
  timestamp.
- OIDC configuration is opaque and validated. Create it with `oidc.new_config`
  or `oidc.discover` instead of constructing records directly.
- `config.with_extra_params` returns `Result(Config, AuthError(e))` and rejects
  reserved authorization parameters.
- `Strategy.exchange_code` returns `ExchangeResult(credentials, artifacts)`.
  Use `strategy.exchange_result(credentials)` for providers with no exchange
  artifacts. `Strategy.fetch_user(Config, ExchangeResult)` receives both the
  standard credentials and any provider-specific token response artifacts.
- Provider-support helpers are public for custom strategy authors. Prefer
  helpers such as `provider_support.parse_redirect_uri`,
  `provider_support.check_response_status`, and
  `strategy.authorization_header`, and `strategy.append_code_verifier` over
  copying built-in strategy internals.
- Supported parsers such as `provider_support.parse_oauth_token_response`,
  `oidc.parse_token_response`, and `github.parse_token_response` are public API
  for strategy authors.
- Wisp exposes structured callback errors through
  `vestibule_wisp.callback_phase_auth_result` for apps that need more control
  than the default HTML error page.

## Writing a Custom Strategy

See the [strategy authoring guide](docs/guides/writing-a-custom-strategy.md) for a complete walkthrough of building a provider strategy from scratch.

## Target

Erlang (BEAM) runtime. Core types can cross-compile to JavaScript, but OAuth callbacks require a server.

## License

MIT — see [LICENSE](LICENSE) for details.
