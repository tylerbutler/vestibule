---
name: vestibule
navLabel: Core
kind: Core package
summary: Core types, two-phase OAuth2 flow, PKCE, CSRF state, token refresh, OIDC discovery, and shared state store.
install:
  - gleam add vestibule
  - gleam add vestibule_github
useWhen: Use the core package when you want direct control over request and callback phases, or when you are building your own transport integration.
setup:
  - Register a provider application and copy its client ID and secret.
  - Create a config with the provider redirect URI.
  - Store state and code_verifier server-side before redirecting.
  - Delete state and code_verifier after a successful callback.
highlights:
  - PKCE is appended to every authorization URL.
  - State validation happens before provider error details are surfaced.
  - Strategies are values, not behaviours or macros.
  - Provider strategies live in focused companion packages.
code: |
  import gleam/dict
  import vestibule
  import vestibule/auth
  import vestibule/authorization_request
  import vestibule/config
  import vestibule/credentials
  import vestibule/user_info
  import vestibule_github

  let strategy = vestibule_github.strategy()
  let cfg =
    config.new(
      "client_id",
      "client_secret",
      "http://localhost:8000/auth/github/callback",
    )

  let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
  // Store authorization_request.state(auth_request) and
  // authorization_request.code_verifier(auth_request) server-side.
  // Redirect the user to authorization_request.url(auth_request).

  let params =
    dict.from_list([
      #("state", "state from callback"),
      #("code", "authorization code from callback"),
    ])

  let assert Ok(result) =
    vestibule.handle_callback(
      strategy,
      cfg,
      params,
      "expected state from session",
      "code verifier from session",
    )

  let uid = auth.uid(result)
  let email = user_info.email(auth.info(result))
  let token = credentials.token(auth.credentials(result))

  _ = uid
  _ = email
  _ = token
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
