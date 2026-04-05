# vestibule

Strategy-based OAuth2 authentication for Gleam.

The name "vestibule" refers to an entrance hall — the transitional space between outside (unauthenticated) and inside (authenticated).

[![Package Version](https://img.shields.io/hexpm/v/vestibule)](https://hex.pm/packages/vestibule)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/vestibule/)

> [!IMPORTANT]
> vestibule is not yet 1.0. This means:
>
> - the API is unstable
> - features and APIs may be removed in minor releases
> - quality should not be considered production-ready
>
> We welcome usage and feedback in
> the meantime! We will do our best to minimize breaking changes regardless.

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
// Store auth_request.state and auth_request.code_verifier in session
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
// auth.uid, auth.info.email, auth.credentials.token
```

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
}
```

If you want to handle callback failures yourself instead of using the default
HTML error page, use `vestibule_wisp.callback_phase_result`.

## Packages

| Package | Description | Install |
|---------|-------------|---------|
| `vestibule` | Core types, two-phase OAuth2 flow, PKCE, token refresh | `gleam add vestibule` |
| `vestibule_wisp` | Wisp middleware for request/callback routing | `gleam add vestibule_wisp` |
| `vestibule_google` | Google OAuth strategy | `gleam add vestibule_google` |
| `vestibule_microsoft` | Microsoft OAuth strategy | `gleam add vestibule_microsoft` |
| `vestibule_apple` | Apple Sign In strategy | `gleam add vestibule_apple` |
| `vestibule_indieauth` | IndieAuth strategy (decentralized identity) | `gleam add vestibule_indieauth` |

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

Discover OpenID Connect providers from their issuer URL:

```gleam
let assert Ok(strategy) = oidc.discover("https://accounts.google.com")
```

## Writing a Custom Strategy

See the [strategy authoring guide](docs/guides/writing-a-custom-strategy.md) for a complete walkthrough of building a provider strategy from scratch.

## Target

Erlang (BEAM) runtime. Core types can cross-compile to JavaScript, but OAuth callbacks require a server.

## License

MIT — see [LICENSE](LICENSE) for details.
