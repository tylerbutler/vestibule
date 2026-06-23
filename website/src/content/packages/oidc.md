---
name: vestibule_oidc
navLabel: OIDC discovery
kind: Provider strategy
summary: OpenID Connect discovery that auto-configures a strategy from any standards-compliant issuer URL, including self-hosted providers.
install:
  - gleam add vestibule_oidc
useWhen: Use OIDC discovery when you want to authenticate against any OpenID Connect provider — including self-hosted ones — by pointing at its issuer URL instead of hand-wiring endpoints.
defaultScopes: "openid profile email"
setup:
  - Register a client with your OIDC provider and copy the client ID and secret.
  - Configure the redirect URI to match the one passed to config.new.
  - Call discover with the provider's issuer URL to fetch its well-known configuration.
  - Pair the discovered strategy with config.new holding your client credentials.
highlights:
  - One-step discover reads /.well-known/openid-configuration and builds a Strategy.
  - Issuer validation rejects discovery documents whose issuer does not match the requested URL.
  - HTTPS and public-host enforcement on issuer and endpoints guards against SSRF.
  - Standard OIDC claims (sub, name, email, preferred_username, picture) map to UserInfo.
  - Email is only populated when the provider reports email_verified.
code: |
  import vestibule
  import vestibule/config
  import vestibule_oidc

  // Discover the provider's endpoints from its issuer URL.
  let assert Ok(strategy) =
    vestibule_oidc.discover("https://accounts.google.com")

  let cfg =
    config.new(
      "your-client-id",
      "your-client-secret",
      "https://myapp.example.com/auth/oidc/callback",
    )

  let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
notes:
  - Discovery performs HTTP requests, so the strategy targets the Erlang (BEAM) runtime only.
  - The OIDC nonce is not generated or validated; validate id_token replay protection yourself if required.
  - For multi-tenant apps, sanitize user-supplied issuer URLs before calling discover to prevent SSRF.
navOrder: 70
searchTerms:
  - oidc
  - openid connect
  - discovery
  - well-known
  - self-hosted login
  - pocket id
---
