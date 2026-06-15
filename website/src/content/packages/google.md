---
name: vestibule_google
navLabel: Google strategy
kind: Provider strategy
summary: Google OAuth strategy with verified-email handling, hosted-domain enforcement, and refresh-token guidance.
install:
  - gleam add vestibule_google
useWhen: Use Google when users sign in with Google or Google Workspace accounts and your app needs normalized profile data.
defaultScopes: openid email profile
setup:
  - Create a Google Cloud project.
  - Configure OAuth consent screen with openid, email, and profile scopes.
  - Create a Web application OAuth client ID.
  - Add development and HTTPS production redirect URIs exactly.
highlights:
  - UserInfo.email is only populated when email_verified is true.
  - config.with_extra_params can request offline access.
  - strategy_for_hosted_domain validates the hd claim server-side.
  - The hd authorization parameter alone is only an account-picker hint.
code: |
  import vestibule/config
  import vestibule_google

  let strategy = vestibule_google.strategy()
  let cfg =
    config.new(
      "google-client-id",
      "google-client-secret",
      "http://localhost:8000/auth/google/callback",
    )

  let workspace_strategy =
    vestibule_google.strategy_for_hosted_domain("corp.example")
notes:
  - Google only returns a refresh token on first consent for a client/user/scope combination.
  - Use access_type=offline and prompt=consent when requesting refresh tokens.
navOrder: 40
searchTerms:
  - google workspace
  - hosted domain
  - offline access
  - refresh token
---
