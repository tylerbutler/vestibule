import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/strategy
import vestibule/user_info
import vestibule_oidc
import vestibule_oidc/internal/token_request_params

// --- OidcConfig construction ---

pub fn oidc_config_construction_test() {
  let config = example_config()
  assert vestibule_oidc.issuer(config) == "https://accounts.example.com"
  assert vestibule_oidc.authorization_endpoint(config)
    == "https://accounts.example.com/authorize"
  assert vestibule_oidc.token_endpoint(config)
    == "https://accounts.example.com/token"
  assert vestibule_oidc.userinfo_endpoint(config)
    == "https://accounts.example.com/userinfo"
  assert vestibule_oidc.scopes_supported(config)
    == ["openid", "profile", "email"]
}

pub fn new_config_rejects_http_issuer_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "http://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_http_authorization_endpoint_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "http://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_http_token_endpoint_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "http://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_http_userinfo_endpoint_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "http://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_localhost_http_endpoints_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "http://localhost",
      authorization_endpoint: "http://localhost/auth",
      token_endpoint: "http://localhost/token",
      userinfo_endpoint: "http://localhost/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_https_localhost_endpoints_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://localhost",
      authorization_endpoint: "https://localhost/auth",
      token_endpoint: "https://localhost/token",
      userinfo_endpoint: "https://localhost/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_loopback_ipv4_endpoint_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://127.0.0.1/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_loopback_ipv6_endpoint_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://[::1]/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_private_network_endpoint_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://192.168.1.10/auth",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_rejects_link_local_metadata_endpoint_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://169.254.169.254/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Error(_) = result
  Nil
}

pub fn new_config_allows_public_https_endpoints_test() {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let assert Ok(_) = result
  Nil
}

// --- parse_discovery_document ---

pub fn parse_discovery_document_full_test() {
  let json =
    "{\"issuer\":\"https://accounts.example.com\",\"authorization_endpoint\":\"https://accounts.example.com/authorize\",\"token_endpoint\":\"https://accounts.example.com/token\",\"userinfo_endpoint\":\"https://accounts.example.com/userinfo\",\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\"]}"
  let result = vestibule_oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  assert vestibule_oidc.issuer(config) == "https://accounts.example.com"
  assert vestibule_oidc.authorization_endpoint(config)
    == "https://accounts.example.com/authorize"
  assert vestibule_oidc.token_endpoint(config)
    == "https://accounts.example.com/token"
  assert vestibule_oidc.userinfo_endpoint(config)
    == "https://accounts.example.com/userinfo"
  assert vestibule_oidc.scopes_supported(config)
    == ["openid", "profile", "email", "address"]
}

pub fn parse_discovery_document_without_scopes_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let result = vestibule_oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  assert vestibule_oidc.scopes_supported(config) == []
}

pub fn parse_discovery_document_rejects_http_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"http://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

pub fn parse_discovery_document_rejects_localhost_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://localhost/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

pub fn parse_discovery_document_rejects_loopback_ipv4_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://127.0.0.1/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

pub fn parse_discovery_document_rejects_loopback_ipv6_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://[::1]/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

pub fn parse_discovery_document_rejects_private_network_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://10.0.0.5/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

pub fn parse_discovery_document_invalid_json_test() {
  let json = "not valid json"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

pub fn parse_discovery_document_missing_required_field_test() {
  // Missing token_endpoint
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

// --- discovery_url ---

pub fn discovery_url_for_host_issuer_test() {
  assert vestibule_oidc.discovery_url("https://example.com")
    == Ok("https://example.com/.well-known/openid-configuration")
}

pub fn discovery_url_for_path_issuer_test() {
  assert vestibule_oidc.discovery_url("https://example.com/tenant")
    == Ok("https://example.com/.well-known/openid-configuration/tenant")
}

pub fn discovery_url_preserves_issuer_validation_test() {
  let assert Error(_) =
    vestibule_oidc.discovery_url("http://example.com/tenant")
  Nil
}

pub fn discovery_url_rejects_loopback_issuer_test() {
  let assert Error(_) = vestibule_oidc.discovery_url("https://localhost/tenant")
  Nil
}

pub fn discovery_url_rejects_loopback_ipv4_issuer_test() {
  let assert Error(_) = vestibule_oidc.discovery_url("https://127.0.0.1")
  Nil
}

// --- parse_token_response ---

pub fn parse_token_response_success_test() {
  let json =
    "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid profile email\",\"refresh_token\":\"dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4\"}"
  assert vestibule_oidc.parse_token_response(json)
    == Ok(
      credentials.new(
        token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
        refresh_token: Some("dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4"),
        token_type: "Bearer",
        expires_in: Some(3600),
        scopes: ["openid", "profile", "email"],
      ),
    )
}

pub fn parse_token_response_minimal_test() {
  let json = "{\"access_token\":\"abc123\",\"token_type\":\"bearer\"}"
  assert vestibule_oidc.parse_token_response(json)
    == Ok(
      credentials.new(
        token: "abc123",
        refresh_token: None,
        token_type: "bearer",
        expires_in: None,
        scopes: [],
      ),
    )
}

pub fn parse_token_response_empty_scope_test() {
  let json =
    "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\",\"scope\":\"\"}"
  let assert Ok(creds) = vestibule_oidc.parse_token_response(json)
  assert credentials.scopes(creds) == []
}

pub fn parse_token_response_error_test() {
  let json =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code has expired\"}"
  let assert Error(_) = vestibule_oidc.parse_token_response(json)
  Nil
}

pub fn parse_token_response_error_without_description_test() {
  let json = "{\"error\":\"invalid_grant\"}"
  assert vestibule_oidc.parse_token_response(json)
    == Error(error.provider(code: "invalid_grant", description: "", uri: None))
}

pub fn parse_token_response_invalid_json_test() {
  let assert Error(_) = vestibule_oidc.parse_token_response("not json")
  Nil
}

// --- parse_userinfo_response ---

pub fn parse_userinfo_response_full_test() {
  let json =
    "{\"sub\":\"user-id-123\",\"name\":\"Jane Doe\",\"email\":\"jane@example.com\",\"email_verified\":true,\"preferred_username\":\"janedoe\",\"picture\":\"https://example.com/jane.jpg\"}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result
  assert uid == "user-id-123"
  assert user_info.name(info) == Some("Jane Doe")
  assert user_info.email(info) == Some("jane@example.com")
  assert user_info.nickname(info) == Some("janedoe")
  assert user_info.image(info) == Some("https://example.com/jane.jpg")
  assert user_info.description(info) == None
  assert user_info.urls(info) == dict.new()
}

pub fn parse_userinfo_response_minimal_test() {
  let json = "{\"sub\":\"minimal-user\"}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result
  assert uid == "minimal-user"
  assert user_info.name(info) == None
  assert user_info.email(info) == None
  assert user_info.nickname(info) == None
  assert user_info.image(info) == None
}

pub fn parse_userinfo_response_invalid_json_test() {
  let assert Error(_) = vestibule_oidc.parse_userinfo_response("not json")
  Nil
}

pub fn parse_userinfo_response_missing_sub_test() {
  let json = "{\"name\":\"No Sub User\",\"email\":\"nosub@example.com\"}"
  let assert Error(_) = vestibule_oidc.parse_userinfo_response(json)
  Nil
}

pub fn parse_userinfo_response_unverified_email_test() {
  let json =
    "{\"sub\":\"user-id-123\",\"email\":\"jane@example.com\",\"email_verified\":false}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(_, info)) = result
  assert user_info.email(info) == None
}

// --- filter_default_scopes ---

pub fn filter_default_scopes_all_present_test() {
  let supported = ["openid", "profile", "email", "address", "phone"]
  assert vestibule_oidc.filter_default_scopes(supported)
    == ["openid", "profile", "email"]
}

pub fn filter_default_scopes_partial_test() {
  let supported = ["openid", "email"]
  assert vestibule_oidc.filter_default_scopes(supported) == ["openid", "email"]
}

pub fn filter_default_scopes_none_present_test() {
  let supported = ["custom_scope", "another_scope"]
  assert vestibule_oidc.filter_default_scopes(supported) == ["openid"]
}

pub fn filter_default_scopes_empty_test() {
  assert vestibule_oidc.filter_default_scopes([]) == ["openid"]
}

// --- strategy_from_config ---

pub fn strategy_from_config_sets_provider_name_test() {
  let oidc_config = example_config()
  let strat =
    vestibule_oidc.strategy_from_config(oidc_config, "my-oidc-provider")
  assert strategy.provider(strat) == "my-oidc-provider"
}

pub fn strategy_from_config_sets_default_scopes_test() {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email", "address"],
    )
  let strat = vestibule_oidc.strategy_from_config(oidc_config, "example")
  assert strategy.default_scopes(strat) == ["openid", "profile", "email"]
}

pub fn strategy_from_config_filters_scopes_test() {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "custom"],
    )
  let strat = vestibule_oidc.strategy_from_config(oidc_config, "example")
  assert strategy.default_scopes(strat) == ["openid"]
}

pub fn strategy_from_config_defaults_to_openid_without_scope_metadata_test() {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: [],
    )
  let strat = vestibule_oidc.strategy_from_config(oidc_config, "example")
  assert strategy.default_scopes(strat) == ["openid"]
}

pub fn strategy_from_config_defaults_to_openid_when_no_desired_scopes_supported_test() {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["custom_scope"],
    )
  let strat = vestibule_oidc.strategy_from_config(oidc_config, "example")
  assert strategy.default_scopes(strat) == ["openid"]
}

pub fn strategy_from_config_authorize_url_test() {
  let oidc_config = example_config()
  let strat = vestibule_oidc.strategy_from_config(oidc_config, "example")
  let conf =
    config.new(
      client_id: "my-client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("my-secret"),
    )
  let result =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: config.authorize_options(),
      scopes: ["openid", "profile"],
      state: "test-state",
    )
  let assert Ok(url) = result
  // Verify all expected query parameters are in the URL
  assert string.contains(url, "https://accounts.example.com/authorize")
  assert string.contains(url, "response_type=code")
  assert string.contains(url, "client_id=my-client-id")
  assert string.contains(url, "state=test-state")
  assert string.contains(url, "openid")
  assert string.contains(url, "profile")
}

pub fn strategy_from_config_authorize_url_with_extra_params_test() {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let strat = vestibule_oidc.strategy_from_config(oidc_config, "example")
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/cb",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "consent")])
  let assert Ok(url) =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: options,
      scopes: ["openid"],
      state: "state-123",
    )
  assert string.contains(url, "prompt=consent")
}

pub fn strategy_from_config_invalid_redirect_uri_returns_error_test() {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let strat = vestibule_oidc.strategy_from_config(oidc_config, "example")
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.ClientSecret("secret"),
    )
  let assert Error(_) =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: config.authorize_options(),
      scopes: ["openid"],
      state: "state-123",
    )
  Nil
}

pub fn token_request_params_include_client_secret_when_configured_test() {
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("secret"),
    )

  assert token_request_params.authorization_code(
      conf,
      code: "code-123",
      redirect_uri: "https://app.example.com/callback",
      code_verifier: Some("verifier-123"),
    )
    == [
      #("grant_type", "authorization_code"),
      #("code", "code-123"),
      #("redirect_uri", "https://app.example.com/callback"),
      #("client_id", "client-id"),
      #("client_secret", "secret"),
      #("code_verifier", "verifier-123"),
    ]

  assert token_request_params.refresh(conf, refresh_token: "refresh-123")
    == [
      #("grant_type", "refresh_token"),
      #("refresh_token", "refresh-123"),
      #("client_id", "client-id"),
      #("client_secret", "secret"),
    ]
}

pub fn token_request_params_omit_client_secret_for_public_client_test() {
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.PublicClient,
    )

  assert token_request_params.authorization_code(
      conf,
      code: "code-123",
      redirect_uri: "https://app.example.com/callback",
      code_verifier: None,
    )
    == [
      #("grant_type", "authorization_code"),
      #("code", "code-123"),
      #("redirect_uri", "https://app.example.com/callback"),
      #("client_id", "client-id"),
    ]

  assert token_request_params.refresh(conf, refresh_token: "refresh-123")
    == [
      #("grant_type", "refresh_token"),
      #("refresh_token", "refresh-123"),
      #("client_id", "client-id"),
    ]
}

pub fn token_request_params_include_client_assertion_without_secret_test() {
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientAssertion("assertion-jwt"),
    )

  assert token_request_params.authorization_code(
      conf,
      code: "code-123",
      redirect_uri: "https://app.example.com/callback",
      code_verifier: None,
    )
    == [
      #("grant_type", "authorization_code"),
      #("code", "code-123"),
      #("redirect_uri", "https://app.example.com/callback"),
      #("client_id", "client-id"),
      #(
        "client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      ),
      #("client_assertion", "assertion-jwt"),
    ]

  assert token_request_params.refresh(conf, refresh_token: "refresh-123")
    == [
      #("grant_type", "refresh_token"),
      #("refresh_token", "refresh-123"),
      #("client_id", "client-id"),
      #(
        "client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      ),
      #("client_assertion", "assertion-jwt"),
    ]
}

fn example_config() {
  let assert Ok(config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email"],
    )
  config
}
