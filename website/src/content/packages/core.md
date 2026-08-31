---
name: vestibule
navLabel: Core
kind: Core package
summary: Core types, a two-phase OAuth2 flow, PKCE, CSRF state, token refresh, and a shared state store.
install:
  - "[dependencies]"
  - 'vestibule = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0" }'
  - 'vestibule_github = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_github" }'
useWhen: Use the core package if your app must control the request and callback phases or provide a custom transport integration.
setup:
  - Register a provider application and copy its client ID and secret.
  - Create a config with the provider redirect URI.
  - Store state and code_verifier server-side before redirecting.
  - Delete state and code_verifier after a successful callback. Expire them after a failure.
highlights:
  - PKCE is appended to every authorization URL.
  - State validation happens before provider error details are surfaced.
  - Strategies are values. They are not behaviours or macros.
  - Provider strategies live in focused companion packages.
code: |
  import gleam/dict
  import gleam/option
  import vestibule
  import vestibule/config
  import vestibule/error
  import vestibule_github

  let strategy = vestibule_github.strategy()
  let client_config =
    config.new(
      client_id: "client_id",
      redirect_uri: "http://localhost:8000/auth/github/callback",
      auth: config.ClientSecret("client_secret"),
    )

  let options = config.authorize_options()
  let assert Ok(auth_request) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: options,
    )
  // Store authorization_request.state(auth_request) and authorization_request.code_verifier(auth_request) server-side.
  // Redirect the user to authorization_request.url(auth_request).

  let params =
    dict.from_list([
      #("state", "state from callback"),
      #("code", "authorization code from callback"),
    ])

  // Validate the callback. State can mismatch and providers can reject
  // the user, so handle the error instead of asserting.
  case
    vestibule.handle_callback(
      strategy,
      client_config,
      params,
      "expected state from session",
      "code verifier from session",
      expected_nonce: option.None,
    )
  {
    Ok(auth) -> sign_in(auth)
    Error(err) ->
      case error.kind(err) {
        error.StateMismatchKind -> restart_sign_in()
        _ -> show_auth_error(err)
      }
  }
notes:
  - Non-local redirect URIs and OIDC issuers must use HTTPS.
  - Remove Auth and Credentials values from logs. Bearer tokens are secrets.
  - "Pass `expected_nonce: option.None` for plain OAuth2 callbacks. For OIDC flows, pass the stored nonce from the request phase."
navOrder: 10
searchTerms:
  - github
  - direct control
  - token refresh
  - oidc discovery
---
