---
name: vestibule_google
navLabel: Google strategy
kind: Provider strategy
summary: Google OAuth strategy with verified-email handling, hosted-domain enforcement, and refresh-token guidance.
install:
  - "[dependencies]"
  - 'vestibule_google = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_google" }'
useWhen: Use Google if users sign in with Google or Google Workspace accounts and your app requires normalized profile data.
defaultScopes: openid email profile
setup:
  - Create a Google Cloud project.
  - Configure OAuth consent screen with openid, email, and profile scopes.
  - Create a Web application OAuth client ID.
  - Add the exact redirect URIs for each environment you demo from (HTTPS when not local).
highlights:
  - user_info.email only returns a value when email_verified is true.
  - Use config.with_extra_params to request offline access.
  - strategy_for_hosted_domain validates the hd claim server-side.
  - The hd authorization parameter alone is only an account-picker hint.
code: |
  import vestibule/config
  import vestibule_google

  let strategy = vestibule_google.strategy()
  let client_config =
    config.new(
      client_id: "google-client-id",
      redirect_uri: "http://localhost:8000/auth/google/callback",
      auth: config.ClientSecret("google-client-secret"),
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
