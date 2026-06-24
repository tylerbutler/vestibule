# vestibule

Strategy-based OAuth2 authentication for Gleam.

The name "vestibule" refers to an entrance hall — the transitional space between outside (unauthenticated) and inside (authenticated).

[![Package Version](https://img.shields.io/hexpm/v/vestibule)](https://hex.pm/packages/vestibule)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/vestibule/)

> [!NOTE]
> vestibule is pre-1.0 (currently `0.x`). The public API is still subject to
> change and breaking changes may land before 1.0. Once 1.0 ships, vestibule
> will follow [Semantic Versioning](https://semver.org/): public APIs stable
> across patch and minor releases, with breaking changes reserved for major
> versions.
>
> OAuth security depends on application configuration too: production redirect
> URIs must use HTTPS. `http://localhost` and `http://127.0.0.1` redirect URIs
> are allowed for local development only.

## Quick Start

Add vestibule and a provider package to your project. If you're using the Wisp
middleware, add `vestibule_wisp` too:

```sh
gleam add vestibule
gleam add vestibule_github
gleam add vestibule_wisp
```

GitHub support is provided by `vestibule_github`, so you can start with the
two-phase flow directly:

```gleam
import gleam/dict
import vestibule
import vestibule/config
import vestibule_github

let strategy = vestibule_github.strategy()
let cfg =
  config.new(
    client_id: "client_id",
    redirect_uri: "http://localhost:8000/auth/github/callback",
    auth: config.ClientSecret("client_secret"),
  )
let options = config.authorize_options()

// Phase 1: Generate authorization URL and redirect user
let assert Ok(auth_request) =
  vestibule.create_authorization_request(
    strategy,
    cfg: cfg,
    options: options,
  )
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
// auth.uid(auth), user_info.email(auth.info(auth)), credentials.token(auth.credentials(auth))
```

`ClientConfig` is durable app/provider configuration: client ID, redirect URI,
and client authentication. Reuse it across requests. `AuthorizeOptions` carries
per-request authorization choices, such as scopes or provider-specific query
parameters. Create fresh options for each authorization request.

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
import vestibule_wisp
import vestibule/state_store
import vestibule_github

// Initialize once at startup
let assert Ok(reg) =
  registry.new()
  |> registry.register(
    vestibule_github.strategy(),
    config.new(
      client_id: "client_id",
      redirect_uri: "http://localhost:8000/auth/github/callback",
      auth: config.ClientSecret("client_secret"),
    ),
  )
let store = state_store.init()

// In your router
case wisp.path_segments(req), req.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase(
      req,
      reg,
      provider,
      store,
      authorize_options: config.authorize_options(),
    )
  // Accept both GET and POST — Apple uses response_mode=form_post
  ["auth", provider, "callback"], http.Get
  | ["auth", provider, "callback"], http.Post
  ->
    vestibule_wisp.callback_phase(req, reg, provider, store, fn(auth) {
      // auth.uid(auth), user_info.name(auth.info(auth)), user_info.email(auth.info(auth))
      wisp.redirect("/dashboard")
    })
  _, _ -> wisp.not_found()
}
```

The state store creates a named ETS table, so initialize it once per BEAM
VM at startup. Use `state_store.try_init` if you want to handle
duplicate-table errors explicitly. The same store can be shared between
`vestibule_wisp` and `vestibule_mist`.

### Logging

Vestibule emits structured OAuth lifecycle logs through Erlang/OTP Logger. It
does not configure Logger handlers or levels; your application keeps normal
BEAM control over log routing, filtering, and formatting.

Logs include safe fields such as `event`, `phase`, `outcome`, `provider`,
`transport`, `endpoint`, `status`, and `error_category`. Vestibule never logs
access tokens, refresh tokens, ID tokens, client secrets, authorization codes, PKCE code
verifiers, raw callback parameters, session IDs, cookie values, signed payloads,
or raw provider response bodies.

If you want to handle callback failures yourself instead of using the default
HTML error page, use `vestibule_wisp.callback_phase_result`. Use
`vestibule_wisp.callback_phase_auth_result` when you need structured errors such
as `UnknownProvider`, `MissingSessionCookie`, `SessionExpired`,
`InvalidCallbackParams`, or `AuthFailed`. Missing or invalid callback `state` and
`code` values are provider/authentication failures and are reported through
`AuthFailed`.

Or use the `vestibule_mist` middleware for the same ergonomics on a plain
mist server. Mist has no built-in signed-cookie helper, so you supply the
secret explicitly:

```gleam
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import mist.{type Connection, type ResponseData}
import vestibule/config
import vestibule/state_store
import vestibule_mist

let assert Ok(store) = state_store.try_init()
let options = vestibule_mist.new_options(secret_key_base)

fn handle_request(req: Request(Connection)) -> Response(ResponseData) {
  case request.path_segments(req), req.method {
    ["auth", provider], http.Get ->
      vestibule_mist.request_phase(
        req,
        reg,
        provider,
        store,
        authorize_options: config.authorize_options(),
        options: options,
      )
    ["auth", provider, "callback"], http.Get
    | ["auth", provider, "callback"], http.Post ->
      vestibule_mist.callback_phase(req, reg, provider, store, options, on_success)
    _, _ -> not_found()
  }
}
```

`vestibule_mist` sets its signed session cookie with `Secure` by default. Its
structured cookie/session errors are named `MissingOrInvalidSessionCookie` and
`SessionUnavailable`.

## Packages

| Package | Description | Install |
|---------|-------------|---------|
| `vestibule` | Core types, two-phase OAuth2 flow, PKCE, token refresh, shared state store | `gleam add vestibule` |
| `vestibule_wisp` | Wisp middleware for request/callback routing | `gleam add vestibule_wisp` |
| `vestibule_mist` | Mist middleware for request/callback routing | `gleam add vestibule_mist` |
| `vestibule_github` | GitHub OAuth strategy | `gleam add vestibule_github` |
| `vestibule_google` | Google OAuth strategy | `gleam add vestibule_google` |
| `vestibule_microsoft` | Microsoft OAuth strategy | `gleam add vestibule_microsoft` |
| `vestibule_apple` | Apple Sign In strategy | `gleam add vestibule_apple` |
| `vestibule_indieauth` | IndieAuth strategy (decentralized identity) | `gleam add vestibule_indieauth` |
| `vestibule_oidc` | OpenID Connect discovery (auto-configure any OIDC provider) | `gleam add vestibule_oidc` |

## How It Works

Vestibule uses a two-phase OAuth2 flow inspired by Elixir's Ueberauth:

1. **Request phase** — Generate an authorization URL with CSRF state and PKCE, redirect the user to the provider
2. **Callback phase** — Validate state, exchange the authorization code for tokens, fetch user info, return a normalized `Auth` result

Strategies are records of functions — no behaviours, macros, or magic. Each strategy tells vestibule how to talk to a specific provider.

## More Features

Use a registry to support multiple providers in one app:

```gleam
let assert Ok(reg) =
  registry.new()
  |> registry.register(vestibule_github.strategy(), github_cfg)
let assert Ok(reg) =
  reg
  |> registry.register(vestibule_google.strategy(), google_cfg)
```

`register` rejects a second registration under an already-registered provider
name with `Error(DuplicateProvider(name))`, so an untrusted or dynamic provider
config cannot silently replace a trusted provider. Namespace custom provider
names (for example `"custom:acme"`) when names come from untrusted input. Use
`registry.register_or_replace` only when a trusted caller intentionally needs to
overwrite an existing provider.

Refresh access tokens when a provider issues refresh tokens:

```gleam
let assert Ok(updated) =
  vestibule.refresh_token(strategy, cfg, refresh_token)
```

Add provider-specific authorization parameters to per-request options when a
provider requires them:

```gleam
let assert Ok(options) =
  config.authorize_options()
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

Discover OpenID Connect providers from their issuer URL (requires the
`vestibule_oidc` package — `gleam add vestibule_oidc`):

```gleam
let assert Ok(strategy) = vestibule_oidc.discover("https://accounts.google.com")
```

### Using Pocket ID (or any self-hosted OIDC provider)

Because `vestibule_oidc.discover` only needs an issuer URL, any standards-compliant
OpenID Connect provider works the same way — including self-hosted ones such
as [Pocket ID](https://pocket-id.org). Point `discover` at your instance's
base URL and pair the resulting strategy with a `config.new` holding your
client credentials:

```gleam
import vestibule
import vestibule/config
import vestibule_oidc

// Discovery reads https://your-pocket-id-instance/.well-known/openid-configuration
let assert Ok(strategy) = vestibule_oidc.discover("https://your-pocket-id-instance")
let cfg =
  config.new(
    client_id: "your-client-id",
    redirect_uri: "http://localhost:8000/auth/oidc/callback",
    auth: config.ClientSecret("your-client-secret"),
  )
let options = config.authorize_options()

let assert Ok(auth_request) =
  vestibule.create_authorization_request(
    strategy,
    cfg: cfg,
    options: options,
  )
```

The discovered strategy plugs into the same two-phase flow, registry, and
`vestibule_wisp` middleware shown above.

Register a client in your provider first:

- **Redirect URI** — must exactly match the one passed to `config.new`
  (for example `https://app.example.com/auth/oidc/callback`). Production
  redirect URIs and OIDC issuers must use HTTPS; `http://localhost` and
  `http://127.0.0.1` are permitted for local development only.
- **Scopes** — request `openid email profile` so vestibule can populate the
  user's id, email, and name. Note that the email accessor (`user_info.email`)
  only returns a value when the provider reports `email_verified`.
- **Client credentials** — copy the issued client ID and secret into
  `config.new`.

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
- **OIDC `nonce`** — OIDC strategies (Google, Apple, Microsoft, and the
  discover-built strategy) generate a 256-bit base64url `nonce`, send it
  on the authorization request, and constant-time validate it against the
  `id_token`'s `nonce` claim on callback. A mismatched or missing-but-
  expected nonce is rejected with an `AuthError` of kind `InvalidNonceKind`
  (see `error.kind`). This binds the
  id_token to the browser session that started the flow, defending against
  id_token replay/injection beyond what PKCE covers.
- **Verified-email gating (OIDC, Google, Apple)** — `user_info.email`
  only returns a value when the provider reports `email_verified`.

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

## API Notes

The root package has two intended public surfaces for the planned 1.0 API.
Before 1.0, this API is still subject to change.

**Application API** modules are for apps that run OAuth flows directly or through
the middleware packages:

- `vestibule`
- `vestibule/auth`
- `vestibule/authorization_request`
- `vestibule/config`
- `vestibule/credentials`
- `vestibule/error`
- `vestibule/registry`
- `vestibule/state_store`
- `vestibule/user_info`

**Provider SDK** modules are for packages that implement custom OAuth or OIDC
provider strategies:

- `vestibule/strategy`
- `vestibule/provider_support`
- `vestibule/logger`

`strategy.exchange_code` returns an opaque `ExchangeResult` carrying the OAuth
credentials plus any provider-specific artifacts. Build one with
`strategy.exchange_result(credentials)` for providers with no exchange
artifacts, or `strategy.exchange_result_with_artifacts(credentials, artifacts)`
otherwise, and read it back with `strategy.exchange_credentials` and
`strategy.exchange_artifacts`. `strategy.fetch_user(Config, ExchangeResult)`
receives both the standard credentials and any provider-specific token response
artifacts.

Prefer provider SDK helpers such as `provider_support.parse_redirect_uri`,
`provider_support.check_response_status`,
`provider_support.parse_oauth_token_response`,
`strategy.authorization_header`, and `strategy.append_code_verifier` over
copying built-in strategy internals.

`vestibule/transport_flow` remains visible for now because the shipped Wisp and
Mist middleware packages share it. It is not a finalized transport SDK; issue #85
tracks whether to hide it or promote it with a stable shape.

## Writing a Custom Strategy

See the [strategy authoring guide](docs/guides/writing-a-custom-strategy.md) for a complete walkthrough of building a provider strategy from scratch.

## Target

Erlang (BEAM) runtime. The current packages are validated on the Erlang target only.

## License

MIT — see [LICENSE](LICENSE) for details.
