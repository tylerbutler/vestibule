---
name: vestibule_indieauth
navLabel: IndieAuth strategy
kind: Provider strategy
summary: Decentralized IndieAuth strategy where users sign in with a URL they control and endpoints are discovered dynamically.
install:
  - gleam add vestibule_indieauth
useWhen: Use IndieAuth when you want users to authenticate with their own domain instead of a centralized provider, with no per-app client secret and per-user endpoints discovered at runtime.
defaultScopes: "profile"
setup:
  - Host your application at a stable HTTPS URL — this URL is your client_id.
  - Leave client_secret empty; IndieAuth clients are public.
  - Register the redirect URI your app uses for the callback.
  - Call discover with the user-supplied profile URL before starting the flow.
highlights:
  - Identity is a URL — auth.uid is the user's canonical me URL.
  - Endpoints are discovered per user from their homepage (metadata, Link headers, then HTML link tags).
  - Public-client semantics — no client_secret is sent during token exchange.
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
  let cfg =
    config.new(
      "https://myapp.example.com/",
      "",
      "https://myapp.example.com/auth/indieauth/callback",
    )

  let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
notes:
  - Discovery performs HTTP requests, so the strategy targets the Erlang (BEAM) runtime only.
  - Each user may resolve to different authorization and token endpoints; always discover per login.
  - When a userinfo endpoint is discovered it is queried for profile data; otherwise the me URL is used as the identity.
navOrder: 65
searchTerms:
  - indieauth
  - decentralized identity
  - indieweb
  - self-hosted login
  - endpoint discovery
---
