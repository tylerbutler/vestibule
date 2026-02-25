import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import startest/expect
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule/oidc.{OidcConfig}

// --- OidcConfig construction ---

pub fn oidc_config_construction_test() {
  let config =
    OidcConfig(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email"],
    )
  config.issuer |> expect.to_equal("https://accounts.example.com")
  config.authorization_endpoint
  |> expect.to_equal("https://accounts.example.com/authorize")
  config.token_endpoint
  |> expect.to_equal("https://accounts.example.com/token")
  config.userinfo_endpoint
  |> expect.to_equal("https://accounts.example.com/userinfo")
  config.scopes_supported |> expect.to_equal(["openid", "profile", "email"])
}

// --- parse_discovery_document ---

pub fn parse_discovery_document_full_test() {
  let json =
    "{\"issuer\":\"https://accounts.example.com\",\"authorization_endpoint\":\"https://accounts.example.com/authorize\",\"token_endpoint\":\"https://accounts.example.com/token\",\"userinfo_endpoint\":\"https://accounts.example.com/userinfo\",\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\"]}"
  let result = oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  config.issuer |> expect.to_equal("https://accounts.example.com")
  config.authorization_endpoint
  |> expect.to_equal("https://accounts.example.com/authorize")
  config.token_endpoint
  |> expect.to_equal("https://accounts.example.com/token")
  config.userinfo_endpoint
  |> expect.to_equal("https://accounts.example.com/userinfo")
  config.scopes_supported
  |> expect.to_equal(["openid", "profile", "email", "address"])
}

pub fn parse_discovery_document_without_scopes_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let result = oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  config.scopes_supported |> expect.to_equal([])
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

// --- parse_token_response ---

pub fn parse_token_response_success_test() {
  let json =
    "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid profile email\",\"refresh_token\":\"dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4\"}"
  oidc.parse_token_response(json)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
      refresh_token: Some("dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4"),
      token_type: "Bearer",
      expires_at: Some(3600),
      scopes: ["openid", "profile", "email"],
    ),
  )
}

pub fn parse_token_response_minimal_test() {
  let json = "{\"access_token\":\"abc123\",\"token_type\":\"bearer\"}"
  oidc.parse_token_response(json)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "abc123",
      refresh_token: None,
      token_type: "bearer",
      expires_at: None,
      scopes: [],
    ),
  )
}

pub fn parse_token_response_error_test() {
  let json =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code has expired\"}"
  let _ =
    oidc.parse_token_response(json)
    |> expect.to_be_error()
  Nil
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
    "{\"sub\":\"user-id-123\",\"name\":\"Jane Doe\",\"email\":\"jane@example.com\",\"preferred_username\":\"janedoe\",\"picture\":\"https://example.com/jane.jpg\"}"
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
  |> expect.to_equal([])
}

pub fn filter_default_scopes_empty_test() {
  oidc.filter_default_scopes([])
  |> expect.to_equal([])
}

// --- strategy_from_config ---

pub fn strategy_from_config_sets_provider_name_test() {
  let oidc_config =
    OidcConfig(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "my-oidc-provider")
  strat.provider |> expect.to_equal("my-oidc-provider")
}

pub fn strategy_from_config_sets_default_scopes_test() {
  let oidc_config =
    OidcConfig(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email", "address"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  strat.default_scopes |> expect.to_equal(["openid", "profile", "email"])
}

pub fn strategy_from_config_filters_scopes_test() {
  let oidc_config =
    OidcConfig(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "custom"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  strat.default_scopes |> expect.to_equal(["openid"])
}

pub fn strategy_from_config_authorize_url_test() {
  let oidc_config =
    OidcConfig(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  let conf =
    config.new("my-client-id", "my-secret", "http://localhost/callback")
  let result = strat.authorize_url(conf, ["openid", "profile"], "test-state")
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
  let oidc_config =
    OidcConfig(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let strat = oidc.strategy_from_config(oidc_config, "example")
  let conf =
    config.new("client-id", "secret", "http://localhost/cb")
    |> config.with_extra_params([#("prompt", "consent")])
  let assert Ok(url) = strat.authorize_url(conf, ["openid"], "state-123")
  { string.contains(url, "prompt=consent") } |> expect.to_be_true()
}
