---
name: vestibule_oidc
navLabel: OIDC discovery
kind: Provider strategy
summary: OpenID Connect discovery that builds a strategy from a standards-compliant issuer URL, including a self-hosted provider.
install:
  - "[dependencies]"
  - 'vestibule_oidc = { git = "https://github.com/tylerbutler/vestibule.git", ref = "vestibule-v0.0", path = "packages/vestibule_oidc" }'
useWhen: Use OIDC discovery to authenticate with an OpenID Connect provider, including a self-hosted provider. Supply its issuer URL instead of configuring each endpoint.
defaultScopes: "openid profile email"
setup:
  - Register a client with your OIDC provider and copy the client ID and secret.
  - Configure the redirect URI to match the one passed to config.new.
  - Call discover with the provider's issuer URL to fetch its well-known configuration.
  - Pair the discovered strategy with config.new holding your client credentials.
highlights:
  - discover reads /.well-known/openid-configuration and builds a Strategy.
  - Issuer validation rejects discovery documents whose issuer does not match the requested URL.
  - HTTPS and public-host checks on the issuer and endpoints reduce SSRF risk.
  - Standard OIDC claims map to UserInfo. These claims include sub, name, email, preferred_username, and picture.
  - Email is only populated when the provider reports email_verified.
code: |
  import vestibule
  import vestibule/config
  import vestibule_oidc

  // Discover the provider's endpoints from its issuer URL.
  let assert Ok(strategy) =
    vestibule_oidc.discover("https://accounts.google.com")

  let client_config =
    config.new(
      client_id: "your-client-id",
      redirect_uri: "https://myapp.example.com/auth/oidc/callback",
      auth: config.ClientSecret("your-client-secret"),
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
  - Store authorization_request.nonce(auth_request) and pass it as `expected_nonce` during callback handling.
  - For a multi-tenant app, allow only issuers that your application trusts. Built-in URL checks do not define your tenant policy.
navOrder: 70
searchTerms:
  - oidc
  - openid connect
  - discovery
  - well-known
  - self-hosted login
  - pocket id
---
