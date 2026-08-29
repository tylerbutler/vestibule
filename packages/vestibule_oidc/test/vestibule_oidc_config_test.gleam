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

pub fn oidc_config_construction_test() -> Nil {
  let config = example_config()
  vestibule_oidc.issuer(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com"
  }
  vestibule_oidc.authorization_endpoint(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com/authorize"
  }
  vestibule_oidc.token_endpoint(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com/token"
  }
  vestibule_oidc.userinfo_endpoint(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com/userinfo"
  }
  vestibule_oidc.scopes_supported(config)
  |> fn(actual) {
    assert actual == ["openid", "profile", "email"]
  }
}

pub fn new_config_rejects_http_issuer_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "http://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_http_authorization_endpoint_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "http://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_http_token_endpoint_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "http://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_http_userinfo_endpoint_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "http://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_localhost_http_endpoints_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "http://localhost",
      authorization_endpoint: "http://localhost/auth",
      token_endpoint: "http://localhost/token",
      userinfo_endpoint: "http://localhost/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_https_localhost_endpoints_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://localhost",
      authorization_endpoint: "https://localhost/auth",
      token_endpoint: "https://localhost/token",
      userinfo_endpoint: "https://localhost/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_loopback_ipv4_endpoint_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://127.0.0.1/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_loopback_ipv6_endpoint_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://[::1]/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_private_network_endpoint_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://192.168.1.10/auth",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_rejects_link_local_metadata_endpoint_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://169.254.169.254/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn new_config_allows_public_https_endpoints_test() -> Nil {
  let result =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/auth",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ =
    result
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
  Nil
}

// --- parse_discovery_document ---

pub fn parse_discovery_document_full_test() -> Nil {
  let json =
    "{\"issuer\":\"https://accounts.example.com\",\"authorization_endpoint\":\"https://accounts.example.com/authorize\",\"token_endpoint\":\"https://accounts.example.com/token\",\"userinfo_endpoint\":\"https://accounts.example.com/userinfo\",\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\"]}"
  let result = vestibule_oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  vestibule_oidc.issuer(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com"
  }
  vestibule_oidc.authorization_endpoint(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com/authorize"
  }
  vestibule_oidc.token_endpoint(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com/token"
  }
  vestibule_oidc.userinfo_endpoint(config)
  |> fn(actual) {
    assert actual == "https://accounts.example.com/userinfo"
  }
  vestibule_oidc.scopes_supported(config)
  |> fn(actual) {
    assert actual == ["openid", "profile", "email", "address"]
  }
}

pub fn parse_discovery_document_without_scopes_test() -> Nil {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let result = vestibule_oidc.parse_discovery_document(json)
  let assert Ok(config) = result
  vestibule_oidc.scopes_supported(config)
  |> fn(actual) {
    assert actual == []
  }
}

pub fn parse_discovery_document_rejects_http_endpoint_test() -> Nil {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"http://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ =
    vestibule_oidc.parse_discovery_document(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_discovery_document_rejects_localhost_endpoint_test() -> Nil {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://localhost/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ =
    vestibule_oidc.parse_discovery_document(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_discovery_document_rejects_loopback_ipv4_endpoint_test() -> Nil {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://127.0.0.1/userinfo\"}"
  let _ =
    vestibule_oidc.parse_discovery_document(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_discovery_document_rejects_loopback_ipv6_endpoint_test() -> Nil {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://[::1]/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ =
    vestibule_oidc.parse_discovery_document(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_discovery_document_rejects_private_network_endpoint_test() -> Nil {
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://10.0.0.5/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ =
    vestibule_oidc.parse_discovery_document(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_discovery_document_invalid_json_test() -> Nil {
  let json = "not valid json"
  let _ =
    vestibule_oidc.parse_discovery_document(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_discovery_document_missing_required_field_test() -> Nil {
  // Missing token_endpoint
  let json =
    "{\"issuer\":\"https://example.com\",\"authorization_endpoint\":\"https://example.com/auth\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ =
    vestibule_oidc.parse_discovery_document(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// --- discovery_url ---

pub fn discovery_url_for_host_issuer_test() -> Nil {
  vestibule_oidc.discovery_url("https://example.com")
  |> fn(actual) {
    assert actual == Ok("https://example.com/.well-known/openid-configuration")
  }
}

pub fn discovery_url_for_path_issuer_test() -> Nil {
  vestibule_oidc.discovery_url("https://example.com/tenant")
  |> fn(actual) {
    assert actual
      == Ok("https://example.com/.well-known/openid-configuration/tenant")
  }
}

pub fn discovery_url_preserves_issuer_validation_test() -> Nil {
  let _ =
    vestibule_oidc.discovery_url("http://example.com/tenant")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn discovery_url_rejects_loopback_issuer_test() -> Nil {
  let _ =
    vestibule_oidc.discovery_url("https://localhost/tenant")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn discovery_url_rejects_loopback_ipv4_issuer_test() -> Nil {
  let _ =
    vestibule_oidc.discovery_url("https://127.0.0.1")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// --- parse_token_response ---

pub fn parse_token_response_success_test() -> Nil {
  let json =
    "{\"access_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid profile email\",\"refresh_token\":\"dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4\"}"
  vestibule_oidc.parse_token_response(json)
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual
      == credentials.new(
        token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
        refresh_token: Some("dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4"),
        token_type: "Bearer",
        expires_in: Some(3600),
        scopes: ["openid", "profile", "email"],
      )
  }
}

pub fn parse_token_response_minimal_test() -> Nil {
  let json = "{\"access_token\":\"abc123\",\"token_type\":\"bearer\"}"
  vestibule_oidc.parse_token_response(json)
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual
      == credentials.new(
        token: "abc123",
        refresh_token: None,
        token_type: "bearer",
        expires_in: None,
        scopes: [],
      )
  }
}

pub fn parse_token_response_empty_scope_test() -> Nil {
  let json =
    "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\",\"scope\":\"\"}"
  let assert Ok(oauth_credentials) = vestibule_oidc.parse_token_response(json)
  credentials.scopes(oauth_credentials)
  |> fn(actual) {
    assert actual == []
  }
}

pub fn parse_token_response_error_test() -> Nil {
  let json =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The authorization code has expired\"}"
  let _ =
    vestibule_oidc.parse_token_response(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_token_response_error_without_description_test() -> Nil {
  let json = "{\"error\":\"invalid_grant\"}"
  let _ =
    vestibule_oidc.parse_token_response(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
    |> fn(actual) {
      assert actual
        == error.provider(code: "invalid_grant", description: "", uri: None)
    }
  Nil
}

pub fn parse_token_response_invalid_json_test() -> Nil {
  let _ =
    vestibule_oidc.parse_token_response("not json")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// --- parse_userinfo_response ---

pub fn parse_userinfo_response_full_test() -> Nil {
  let json =
    "{\"sub\":\"user-id-123\",\"name\":\"Jane Doe\",\"email\":\"jane@example.com\",\"email_verified\":true,\"preferred_username\":\"janedoe\",\"picture\":\"https://example.com/jane.jpg\"}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result
  uid
  |> fn(actual) {
    assert actual == "user-id-123"
  }
  user_info.name(info)
  |> fn(actual) {
    assert actual == Some("Jane Doe")
  }
  user_info.email(info)
  |> fn(actual) {
    assert actual == Some("jane@example.com")
  }
  user_info.nickname(info)
  |> fn(actual) {
    assert actual == Some("janedoe")
  }
  user_info.image(info)
  |> fn(actual) {
    assert actual == Some("https://example.com/jane.jpg")
  }
  user_info.description(info)
  |> fn(actual) {
    assert actual == None
  }
  user_info.urls(info)
  |> fn(actual) {
    assert actual == dict.new()
  }
}

pub fn parse_userinfo_response_minimal_test() -> Nil {
  let json = "{\"sub\":\"minimal-user\"}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result
  uid
  |> fn(actual) {
    assert actual == "minimal-user"
  }
  user_info.name(info)
  |> fn(actual) {
    assert actual == None
  }
  user_info.email(info)
  |> fn(actual) {
    assert actual == None
  }
  user_info.nickname(info)
  |> fn(actual) {
    assert actual == None
  }
  user_info.image(info)
  |> fn(actual) {
    assert actual == None
  }
}

pub fn parse_userinfo_response_invalid_json_test() -> Nil {
  let _ =
    vestibule_oidc.parse_userinfo_response("not json")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_userinfo_response_missing_sub_test() -> Nil {
  let json = "{\"name\":\"No Sub User\",\"email\":\"nosub@example.com\"}"
  let _ =
    vestibule_oidc.parse_userinfo_response(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_userinfo_response_unverified_email_test() -> Nil {
  let json =
    "{\"sub\":\"user-id-123\",\"email\":\"jane@example.com\",\"email_verified\":false}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(_, info)) = result
  user_info.email(info)
  |> fn(actual) {
    assert actual == None
  }
}

// --- filter_default_scopes ---

pub fn filter_default_scopes_all_present_test() -> Nil {
  let supported = ["openid", "profile", "email", "address", "phone"]
  vestibule_oidc.filter_default_scopes(supported)
  |> fn(actual) {
    assert actual == ["openid", "profile", "email"]
  }
}

pub fn filter_default_scopes_partial_test() -> Nil {
  let supported = ["openid", "email"]
  vestibule_oidc.filter_default_scopes(supported)
  |> fn(actual) {
    assert actual == ["openid", "email"]
  }
}

pub fn filter_default_scopes_none_present_test() -> Nil {
  let supported = ["custom_scope", "another_scope"]
  vestibule_oidc.filter_default_scopes(supported)
  |> fn(actual) {
    assert actual == ["openid"]
  }
}

pub fn filter_default_scopes_empty_test() -> Nil {
  vestibule_oidc.filter_default_scopes([])
  |> fn(actual) {
    assert actual == ["openid"]
  }
}

// --- strategy_from_config ---

pub fn strategy_from_config_sets_provider_name_test() -> Nil {
  let oidc_config = example_config()
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "my-oidc-provider")
  strategy.provider(oidc_strategy)
  |> fn(actual) {
    assert actual == "my-oidc-provider"
  }
}

pub fn strategy_from_config_sets_default_scopes_test() -> Nil {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email", "address"],
    )
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(oidc_strategy)
  |> fn(actual) {
    assert actual == ["openid", "profile", "email"]
  }
}

pub fn strategy_from_config_filters_scopes_test() -> Nil {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid", "custom"],
    )
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(oidc_strategy)
  |> fn(actual) {
    assert actual == ["openid"]
  }
}

pub fn strategy_from_config_defaults_to_openid_without_scope_metadata_test() -> Nil {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: [],
    )
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(oidc_strategy)
  |> fn(actual) {
    assert actual == ["openid"]
  }
}

pub fn strategy_from_config_defaults_to_openid_when_no_desired_scopes_supported_test() -> Nil {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["custom_scope"],
    )
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "example")
  strategy.default_scopes(oidc_strategy)
  |> fn(actual) {
    assert actual == ["openid"]
  }
}

pub fn strategy_from_config_authorize_url_test() -> Nil {
  let oidc_config = example_config()
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "example")
  let client_config =
    config.new(
      client_id: "my-client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("my-secret"),
    )
  let result =
    strategy.build_authorize_url(
      oidc_strategy,
      config: client_config,
      options: config.authorize_options(),
      scopes: ["openid", "profile"],
      state: "test-state",
    )
  let assert Ok(url) = result
  // Verify all expected query parameters are in the URL
  { string.contains(url, "https://accounts.example.com/authorize") }
  |> fn(actual) {
    assert actual
  }
  { string.contains(url, "response_type=code") }
  |> fn(actual) {
    assert actual
  }
  { string.contains(url, "client_id=my-client-id") }
  |> fn(actual) {
    assert actual
  }
  { string.contains(url, "state=test-state") }
  |> fn(actual) {
    assert actual
  }
  { string.contains(url, "openid") }
  |> fn(actual) {
    assert actual
  }
  { string.contains(url, "profile") }
  |> fn(actual) {
    assert actual
  }
}

pub fn strategy_from_config_authorize_url_with_extra_params_test() -> Nil {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "example")
  let client_config =
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
      oidc_strategy,
      config: client_config,
      options: options,
      scopes: ["openid"],
      state: "state-123",
    )
  { string.contains(url, "prompt=consent") }
  |> fn(actual) {
    assert actual
  }
}

pub fn strategy_from_config_invalid_redirect_uri_returns_error_test() -> Nil {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let oidc_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, "example")
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.ClientSecret("secret"),
    )
  let _ =
    strategy.build_authorize_url(
      oidc_strategy,
      config: client_config,
      options: config.authorize_options(),
      scopes: ["openid"],
      state: "state-123",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn token_request_params_include_client_secret_when_configured_test() -> Nil {
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("secret"),
    )

  token_request_params.authorization_code(
    client_config,
    code: "code-123",
    redirect_uri: "https://app.example.com/callback",
    code_verifier: Some("verifier-123"),
  )
  |> fn(actual) {
    assert actual
      == [
        #("grant_type", "authorization_code"),
        #("code", "code-123"),
        #("redirect_uri", "https://app.example.com/callback"),
        #("client_id", "client-id"),
        #("client_secret", "secret"),
        #("code_verifier", "verifier-123"),
      ]
  }

  token_request_params.refresh(client_config, refresh_token: "refresh-123")
  |> fn(actual) {
    assert actual
      == [
        #("grant_type", "refresh_token"),
        #("refresh_token", "refresh-123"),
        #("client_id", "client-id"),
        #("client_secret", "secret"),
      ]
  }
}

pub fn token_request_params_omit_client_secret_for_public_client_test() -> Nil {
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.PublicClient,
    )

  token_request_params.authorization_code(
    client_config,
    code: "code-123",
    redirect_uri: "https://app.example.com/callback",
    code_verifier: None,
  )
  |> fn(actual) {
    assert actual
      == [
        #("grant_type", "authorization_code"),
        #("code", "code-123"),
        #("redirect_uri", "https://app.example.com/callback"),
        #("client_id", "client-id"),
      ]
  }

  token_request_params.refresh(client_config, refresh_token: "refresh-123")
  |> fn(actual) {
    assert actual
      == [
        #("grant_type", "refresh_token"),
        #("refresh_token", "refresh-123"),
        #("client_id", "client-id"),
      ]
  }
}

pub fn token_request_params_include_client_assertion_without_secret_test() -> Nil {
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientAssertion("assertion-jwt"),
    )

  token_request_params.authorization_code(
    client_config,
    code: "code-123",
    redirect_uri: "https://app.example.com/callback",
    code_verifier: None,
  )
  |> fn(actual) {
    assert actual
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
  }

  token_request_params.refresh(client_config, refresh_token: "refresh-123")
  |> fn(actual) {
    assert actual
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
}

fn example_config() -> vestibule_oidc.OidcConfig {
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
