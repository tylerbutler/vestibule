import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import startest/expect
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/oidc
import vestibule/strategy

// --- OidcConfig construction ---

pub fn oidc_config_construction_test() {
  let config = example_config()
  oidc.issuer(config) |> expect.to_equal("https://accounts.example.com")
  oidc.authorization_endpoint(config)
  |> expect.to_equal("https://accounts.example.com/authorize")
  oidc.token_endpoint(config)
  |> expect.to_equal("https://accounts.example.com/token")
  oidc.userinfo_endpoint(config)
  |> expect.to_equal("https://accounts.example.com/userinfo")
  oidc.scopes_supported(config)
  |> expect.to_equal(["openid", "profile", "email"])
}

pub fn new_config_rejects_http_issuer_test() {
  let result =
    oidc.new_config(
      issuer: "http://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ = result |> expect.to_be_error()
  Nil
}

pub fn new_config_rejects_http_authorization_endpoint_test() {
  let result =
    oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "http://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ = result |> expect.to_be_error()
  Nil
}

pub fn new_config_rejects_http_token_endpoint_test() {
  let result =
    oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "http://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ = result |> expect.to_be_error()
  Nil
}

pub fn new_config_rejects_http_userinfo_endpoint_test() {
  let result =
    oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "http://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ = result |> expect.to_be_error()
  Nil
}

pub fn new_config_allows_localhost_http_endpoints_test() {
  let result =
    oidc.new_config(
      issuer: "http://localhost",
      authorization_endpoint: "http://localhost/auth",
      token_endpoint: "http://localhost/token",
      userinfo_endpoint: "http://localhost/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ = result |> expect.to_be_ok()
  Nil
}

// --- parse_discovery_document ---

pub fn parse_discovery_document_full_test() {
  let json =
    "{\"issuer\":\"https://accounts.example.com\",\"authorization_endpoint\":\"https://accounts.example.com/authorize\",\"token_endpoint\":\"https://accounts.example.com/token\",\"userinfo_endpoint\":\"https://accounts.example.com/userinfo\",\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\"]}"
  let result = oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  oidc.issuer(config) |> expect.to_equal("https://accounts.example.com")
  oidc.authorization_endpoint(config)
  |> expect.to_equal("https://accounts.example.com/authorize")
  oidc.token_endpoint(config)
  |> expect.to_equal("https://accounts.example.com/token")
  oidc.userinfo_endpoint(config)
  |> expect.to_equal("https://accounts.example.com/userinfo")
  oidc.scopes_supported(config)
  |> expect.to_equal(["openid", "profile", "email", "address"])
}

pub fn parse_discovery_document_without_scopes_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let result = oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  oidc.scopes_supported(config) |> expect.to_equal([])
}

pub fn parse_discovery_document_rejects_http_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"http://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ =
    oidc.parse_discovery_document(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_discovery_document_invalid_json_test() {
  let json = "not valid json"
  let _ =
    oidc.parse_discovery_document(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_discovery_document_missing_required_field_test() {
  // Missing token_endpoint
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ =
    oidc.parse_discovery_document(json)
    |> expect.to_be_error()
  Nil
}

// --- discovery_url ---

pub fn discovery_url_for_host_issuer_test() {
  oidc.discovery_url("https://example.com")
  |> expect.to_equal(Ok("https://example.com/.well-known/openid-configuration"))
}

pub fn discovery_url_for_path_issuer_test() {
  oidc.discovery_url("https://example.com/tenant")
  |> expect.to_equal(Ok(
    "https://example.com/.well-known/openid-configuration/tenant",
  ))
}

pub fn discovery_url_preserves_issuer_validation_test() {
  let _ =
    oidc.discovery_url("http://example.com/tenant")
    |> expect.to_be_error()
  Nil
}

// --- parse_token_response ---

pub fn parse_token_response_success_test() {
  let json =
    "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid profile email\",\"refresh_token\":\"dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4\"}"
  oidc.parse_token_response(json)
  |> expect.to_be_ok()
  |> expect.to_equal(
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
  oidc.parse_token_response(json)
  |> expect.to_be_ok()
  |> expect.to_equal(
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
  let assert Ok(creds) = oidc.parse_token_response(json)
  credentials.scopes(creds) |> expect.to_equal([])
}

pub fn parse_token_response_error_test() {
  let json =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code has expired\"}"
  let _ =
    oidc.parse_token_response(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_token_response_error_without_description_test() {
  let json = "{\"error\":\"invalid_grant\"}"
  oidc.parse_token_response(json)
  |> expect.to_be_error()
  |> expect.to_equal(error.ProviderError(
    code: "invalid_grant",
    description: "",
    uri: None,
  ))
}

pub fn parse_token_response_invalid_json_test() {
  let _ =
    oidc.parse_token_response("not json")
    |> expect.to_be_error()
  Nil
}

// --- parse_userinfo_response ---

pub fn parse_userinfo_response_full_test() {
  let json =
    "{\"sub\":\"user-id-123\",\"name\":\"Jane Doe\",\"email\":\"jane@example.com\",\"email_verified\":true,\"preferred_username\":\"janedoe\",\"picture\":\"https://example.com/jane.jpg\"}"
  let result = oidc.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> expect.to_equal("user-id-123")
  info.name |> expect.to_equal(Some("Jane Doe"))
  info.email |> expect.to_equal(Some("jane@example.com"))
  info.nickname |> expect.to_equal(Some("janedoe"))
  info.image |> expect.to_equal(Some("https://example.com/jane.jpg"))
  info.description |> expect.to_equal(None)
  info.urls |> expect.to_equal(dict.new())
}

pub fn parse_userinfo_response_minimal_test() {
  let json = "{\"sub\":\"minimal-user\"}"
  let result = oidc.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> expect.to_equal("minimal-user")
  info.name |> expect.to_equal(None)
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(None)
  info.image |> expect.to_equal(None)
}

pub fn parse_userinfo_response_invalid_json_test() {
  let _ =
    oidc.parse_userinfo_response("not json")
    |> expect.to_be_error()
  Nil
}

pub fn parse_userinfo_response_missing_sub_test() {
  let json = "{\"name\":\"No Sub User\",\"email\":\"nosub@example.com\"}"
  let _ =
    oidc.parse_userinfo_response(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_userinfo_response_unverified_email_test() {
  let json =
    "{\"sub\":\"user-id-123\",\"email\":\"jane@example.com\",\"email_verified\":false}"
  let result = oidc.parse_userinfo_response(json)
  let assert Ok(#(_, info)) = result
  info.email |> expect.to_equal(None)
}

// --- filter_default_scopes ---

pub fn filter_default_scopes_all_present_test() {
  let supported = ["openid", "profile", "email", "address", "phone"]
  oidc.filter_default_scopes(supported)
  |> expect.to_equal(["openid", "profile", "email"])
}

pub fn filter_default_scopes_partial_test() {
  let supported = ["openid", "email"]
  oidc.filter_default_scopes(supported)
  |> expect.to_equal(["openid", "email"])
}

pub fn filter_default_scopes_none_present_test() {
  let supported = ["custom_scope", "another_scope"]
  oidc.filter_default_scopes(supported)
  |> expect.to_equal(["openid"])
}

pub fn filter_default_scopes_empty_test() {
  oidc.filter_default_scopes([])
  |> expect.to_equal(["openid"])
}

// --- strategy_from_config ---

pub fn strategy_from_config_sets_provider_name_test() {
  let oidc_config = example_config()
  let strat = oidc.strategy_from_config(oidc_config, "my-oidc-provider")
  strategy.provider(strat) |> expect.to_equal("my-oidc-provider")
}

pub fn strategy_from_config_sets_default_scopes_test() {
  let assert Ok(oidc_config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email", "address"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(strat)
  |> expect.to_equal(["openid", "profile", "email"])
}

pub fn strategy_from_config_filters_scopes_test() {
  let assert Ok(oidc_config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "custom"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(strat) |> expect.to_equal(["openid"])
}

pub fn strategy_from_config_defaults_to_openid_without_scope_metadata_test() {
  let assert Ok(oidc_config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: [],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(strat) |> expect.to_equal(["openid"])
}

pub fn strategy_from_config_defaults_to_openid_when_no_desired_scopes_supported_test() {
  let assert Ok(oidc_config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["custom_scope"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(strat) |> expect.to_equal(["openid"])
}

pub fn strategy_from_config_authorize_url_test() {
  let oidc_config = example_config()
  let strat = oidc.strategy_from_config(oidc_config, "example")
  let conf =
    config.new("my-client-id", "my-secret", "http://localhost/callback")
  let result =
    strategy.build_authorize_url(
      strat,
      conf,
      ["openid", "profile"],
      "test-state",
    )
  let assert Ok(url) = result
  // Verify all expected query parameters are in the URL
  { string.contains(url, "https://accounts.example.com/authorize") }
  |> expect.to_be_true()
  { string.contains(url, "response_type=code") } |> expect.to_be_true()
  { string.contains(url, "client_id=my-client-id") } |> expect.to_be_true()
  { string.contains(url, "state=test-state") } |> expect.to_be_true()
  { string.contains(url, "openid") } |> expect.to_be_true()
  { string.contains(url, "profile") } |> expect.to_be_true()
}

pub fn strategy_from_config_authorize_url_with_extra_params_test() {
  let assert Ok(oidc_config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  let assert Ok(conf) =
    config.new("client-id", "secret", "http://localhost/cb")
    |> config.with_extra_params([#("prompt", "consent")])
  let assert Ok(url) =
    strategy.build_authorize_url(strat, conf, ["openid"], "state-123")
  { string.contains(url, "prompt=consent") } |> expect.to_be_true()
}

pub fn strategy_from_config_invalid_redirect_uri_returns_error_test() {
  let assert Ok(oidc_config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  let conf = config.new("client-id", "secret", "not a uri")
  let _ =
    strategy.build_authorize_url(strat, conf, ["openid"], "state-123")
    |> expect.to_be_error()
  Nil
}

fn example_config() {
  let assert Ok(config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email"],
    )
  config
}
