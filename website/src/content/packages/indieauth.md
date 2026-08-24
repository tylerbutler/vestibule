---
name: vestibule_indieauth
navLabel: IndieAuth strategy
kind: Provider strategy
summary: Decentralized IndieAuth strategy for sign-in with a user-controlled URL and endpoints discovered at run time.
install:
  - "[dependencies]"
  - 'vestibule_indieauth = { git = "https://github.com/tylerbutler/vestibule.git", ref = "vestibule-v0.0", path = "packages/vestibule_indieauth" }'
useWhen: Use IndieAuth if users sign in with their own domains instead of a centralized provider. The strategy discovers endpoints for each user and does not require an app client secret.
defaultScopes: "profile"
setup:
  - Host your application at a stable HTTPS URL. This URL is your client_id.
  - "Use `auth: config.PublicClient`. IndieAuth clients are public and do not send a client secret."
  - Register the redirect URI your app uses for the callback.
  - Call discover with the user-supplied profile URL before starting the flow.
highlights:
  - The identity is a URL. auth.uid(auth) returns the user's canonical me URL.
  - Endpoints are discovered per user from their homepage (metadata, Link headers, then HTML link tags).
  - The strategy uses a public client. It does not send a client_secret during token exchange.
  - PKCE is used for the authorization code flow.
  - Profile name, email, and photo are populated from the token or userinfo response when available.
code: |
  import vestibule
  import vestibule/config
  import vestibule_indieauth

  // Discover the user's IndieAuth endpoints from their URL.
  let assert Ok(strategy) =
    vestibule_indieauth.discover("https://user.example.com")

  // client_id is your app's URL; no client_secret is required.
  let client_config =
    config.new(
      client_id: "https://myapp.example.com/",
      redirect_uri: "https://myapp.example.com/auth/indieauth/callback",
      auth: config.PublicClient,
    )

  let options = config.authorize_options()
  let assert Ok(auth_request) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: options,
    )
notes:
  - Discovery performs HTTP requests, so the strategy targets the Erlang (BEAM) runtime only.
  - Each user can use different authorization and token endpoints. Run discovery for each login.
  - The strategy requests profile data from a discovered userinfo endpoint. If no endpoint is available, it uses the me URL as the identity.
navOrder: 65
searchTerms:
  - indieauth
  - decentralized identity
  - indieweb
  - self-hosted login
  - endpoint discovery
---
