---
name: vestibule
navLabel: Core + GitHub
kind: Core package
summary: Core types, two-phase OAuth2 flow, PKCE, CSRF state, token refresh, OIDC discovery, shared state store, and built-in GitHub strategy.
install:
  - gleam add vestibule
useWhen: Use the core package when you want direct control over request and callback phases, or when you are building your own transport integration.
defaultScopes: "GitHub uses user:email by default."
setup:
  - Register a provider application and copy its client ID and secret.
  - Create a config with the provider redirect URI.
  - Store state and code_verifier server-side before redirecting.
  - Delete state and code_verifier after a successful callback.
highlights:
  - PKCE is appended to every authorization URL.
  - State validation happens before provider error details are surfaced.
  - Strategies are values, not behaviours or macros.
  - GitHub support ships in the core package.
code: |
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

  let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
  // Store auth_request.state and auth_request.code_verifier server-side.
  // Redirect the user to auth_request.url.

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
notes:
  - Production redirect URIs and OIDC issuers must use HTTPS.
  - Redact Auth and Credentials values in logs; bearer tokens are secrets.
  - OIDC nonce validation is currently left to the consuming app when it needs id_token replay protection beyond PKCE.
navOrder: 10
searchTerms:
  - github
  - direct control
  - token refresh
  - oidc discovery
---
