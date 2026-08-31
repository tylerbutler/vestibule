import gleam/bit_array
import gleam/dict
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import vestibule/config
import vestibule/credential
import vestibule/strategy
import vestibule/user_info
import vestibule_microsoft

pub fn main() -> Nil {
  gleeunit.main()
}

/// Build a minimal unsigned JWT (header.payload.signature) whose payload is the
/// given JSON. Only the payload segment is meaningful for tenant verification.
fn fake_id_token(payload_json: String) -> String {
  let header = bit_array.base64_url_encode(<<"{\"alg\":\"none\"}":utf8>>, False)
  let payload = bit_array.base64_url_encode(<<payload_json:utf8>>, False)
  header <> "." <> payload <> ".sig"
}

pub fn verify_tenant_match_test() -> Nil {
  let token =
    fake_id_token("{\"tid\":\"72f988bf-86f1-41af-91ab-2d7cd011db47\"}")
  let _ =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "72f988bf-86f1-41af-91ab-2d7cd011db47",
      id_token: token,
    )
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual == "72f988bf-86f1-41af-91ab-2d7cd011db47"
    }
  Nil
}

pub fn verify_tenant_case_insensitive_test() -> Nil {
  let token =
    fake_id_token("{\"tid\":\"72F988BF-86F1-41AF-91AB-2D7CD011DB47\"}")
  let _ =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "72f988bf-86f1-41af-91ab-2d7cd011db47",
      id_token: token,
    )
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
  Nil
}

pub fn verify_tenant_mismatch_rejected_test() -> Nil {
  let token = fake_id_token("{\"tid\":\"other-tenant-guid\"}")
  let _ =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "expected-tenant-guid",
      id_token: token,
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn verify_tenant_missing_tid_rejected_test() -> Nil {
  let token = fake_id_token("{\"sub\":\"abc\"}")
  let _ =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "expected-tenant-guid",
      id_token: token,
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn verify_tenant_malformed_token_rejected_test() -> Nil {
  let _ =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "expected-tenant-guid",
      id_token: "not-a-jwt",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn id_token_tenant_extracts_tid_test() -> Nil {
  let token = fake_id_token("{\"tid\":\"abc-123\",\"sub\":\"u1\"}")
  let _ =
    vestibule_microsoft.id_token_tenant(token)
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual == "abc-123"
    }
  Nil
}

pub fn strategy_for_tenant_authorize_url_uses_tenant_endpoint_test() -> Nil {
  let microsoft_strategy =
    vestibule_microsoft.strategy_for_tenant("my-tenant-id")
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(authorize_url) =
    strategy.build_authorize_url(
      microsoft_strategy,
      config: client_configuration,
      options: config.authorize_options(),
      scopes: ["openid", "User.Read"],
      state: "state",
    )
  let _ =
    {
      string.contains(
        authorize_url,
        "login.microsoftonline.com/my-tenant-id/oauth2/v2.0",
      )
    }
    |> fn(actual) {
      assert actual
    }
  Nil
}

pub fn strategy_for_tenant_default_scopes_include_openid_test() -> Nil {
  let microsoft_strategy =
    vestibule_microsoft.strategy_for_tenant("my-tenant-id")
  let _ =
    strategy.default_scopes(microsoft_strategy)
    |> fn(actual) {
      assert actual == ["openid", "User.Read"]
    }
  Nil
}

pub fn common_strategy_default_scopes_include_openid_test() -> Nil {
  let microsoft_strategy = vestibule_microsoft.strategy()
  let _ =
    strategy.default_scopes(microsoft_strategy)
    |> fn(actual) {
      assert actual == ["openid", "User.Read"]
    }
  Nil
}

pub fn common_strategy_authorize_url_uses_common_endpoint_test() -> Nil {
  let microsoft_strategy = vestibule_microsoft.strategy()
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(authorize_url) =
    strategy.build_authorize_url(
      microsoft_strategy,
      config: client_configuration,
      options: config.authorize_options(),
      scopes: ["User.Read"],
      state: "state",
    )
  let _ =
    {
      string.contains(
        authorize_url,
        "login.microsoftonline.com/common/oauth2/v2.0",
      )
    }
    |> fn(actual) {
      assert actual
    }
  Nil
}

pub fn custom_scopes_add_openid_for_nonce_test() -> Nil {
  let microsoft_strategy = vestibule_microsoft.strategy()
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(authorize_url) =
    strategy.build_authorize_url(
      microsoft_strategy,
      config: client_configuration,
      options: config.authorize_options(),
      scopes: ["User.Read"],
      state: "state",
    )
  let _ =
    { string.contains(authorize_url, "openid") }
    |> fn(actual) {
      assert actual
    }
  let _ =
    { string.contains(authorize_url, "User.Read") }
    |> fn(actual) {
      assert actual
    }
  Nil
}

pub fn parse_token_response_success_test() -> Nil {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read profile openid email\",\"expires_in\":3736,\"ext_expires_in\":3736,\"access_token\":\"eyJ0eXAi_test_token\",\"refresh_token\":\"AwABAAAA_test_refresh\"}"
  let _ =
    vestibule_microsoft.parse_token_response(body)
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual
        == credential.new(
          token: "eyJ0eXAi_test_token",
          refresh_token: Some("AwABAAAA_test_refresh"),
          token_type: "Bearer",
          expires_in: Some(3736),
          scopes: ["User.Read", "profile", "openid", "email"],
        )
    }
  Nil
}

pub fn parse_token_response_without_refresh_token_test() -> Nil {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read\",\"expires_in\":3600,\"access_token\":\"test_token\"}"
  let _ =
    vestibule_microsoft.parse_token_response(body)
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual
        == credential.new(
          token: "test_token",
          refresh_token: None,
          token_type: "Bearer",
          expires_in: Some(3600),
          scopes: ["User.Read"],
        )
    }
  Nil
}

pub fn parse_token_response_empty_scope_test() -> Nil {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"\",\"expires_in\":3600,\"access_token\":\"test_token\"}"
  let assert Ok(oauth_credentials) =
    vestibule_microsoft.parse_token_response(body)
  let _ =
    credential.scopes(oauth_credentials)
    |> fn(actual) {
      assert actual == []
    }
  Nil
}

pub fn parse_token_response_error_test() -> Nil {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS70000: The provided value for the input parameter 'code' is not valid.\"}"
  let _ =
    vestibule_microsoft.parse_token_response(body)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_user_response_full_test() -> Nil {
  let body =
    "{\"id\":\"87d349ed-44d7-43e1-9a83-5f2406dee5bd\",\"displayName\":\"Adele Vance\",\"mail\":\"AdeleV@contoso.com\",\"userPrincipalName\":\"AdeleV@contoso.com\",\"jobTitle\":\"Retail Manager\"}"
  let assert Ok(#(user_id, user_information)) =
    vestibule_microsoft.parse_user_response(body)
  let _ =
    user_id
    |> fn(actual) {
      assert actual == "87d349ed-44d7-43e1-9a83-5f2406dee5bd"
    }
  let _ =
    user_info.name(user_information)
    |> fn(actual) {
      assert actual == Some("Adele Vance")
    }
  let _ =
    user_info.email(user_information)
    |> fn(actual) {
      assert actual == Some("AdeleV@contoso.com")
    }
  let _ =
    user_info.nickname(user_information)
    |> fn(actual) {
      assert actual == Some("AdeleV@contoso.com")
    }
  let _ =
    user_info.description(user_information)
    |> fn(actual) {
      assert actual == Some("Retail Manager")
    }
  // Microsoft Graph doesn't provide a direct image URL
  let _ =
    user_info.image(user_information)
    |> fn(actual) {
      assert actual == None
    }
  Nil
}

pub fn parse_user_response_minimal_test() -> Nil {
  let body = "{\"id\":\"abc-123\",\"userPrincipalName\":\"user@example.com\"}"
  let assert Ok(#(user_id, user_information)) =
    vestibule_microsoft.parse_user_response(body)
  let _ =
    user_id
    |> fn(actual) {
      assert actual == "abc-123"
    }
  let _ =
    user_info.name(user_information)
    |> fn(actual) {
      assert actual == None
    }
  // UPN is not a verified email, so email should be None
  let _ =
    user_info.email(user_information)
    |> fn(actual) {
      assert actual == None
    }
  let _ =
    user_info.nickname(user_information)
    |> fn(actual) {
      assert actual == Some("user@example.com")
    }
  let _ =
    user_info.description(user_information)
    |> fn(actual) {
      assert actual == None
    }
  // No gravatar when no verified email
  let _ =
    user_info.image(user_information)
    |> fn(actual) {
      assert actual == None
    }
  Nil
}

pub fn parse_user_response_mail_preferred_over_user_principal_name_test() -> Nil {
  let body =
    "{\"id\":\"abc\",\"mail\":\"real@example.com\",\"userPrincipalName\":\"upn@example.com\"}"
  let assert Ok(#(_user_id, user_information)) =
    vestibule_microsoft.parse_user_response(body)
  let _ =
    user_info.email(user_information)
    |> fn(actual) {
      assert actual == Some("real@example.com")
    }
  Nil
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() -> Nil {
  let microsoft_strategy = vestibule_microsoft.strategy()
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.ClientSecret("secret"),
    )
  let _ =
    strategy.build_authorize_url(
      microsoft_strategy,
      config: client_configuration,
      options: config.authorize_options(),
      scopes: ["User.Read"],
      state: "state",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn authorize_url_includes_extra_parameters_test() -> Nil {
  let microsoft_strategy = vestibule_microsoft.strategy()
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "select_account")])
  let assert Ok(authorize_url) =
    strategy.build_authorize_url(
      microsoft_strategy,
      config: client_configuration,
      options: options,
      scopes: ["User.Read"],
      state: "state",
    )
  let _ =
    { string.contains(authorize_url, "prompt=select_account") }
    |> fn(actual) {
      assert actual
    }
  Nil
}

pub fn sans_io_token_request_and_response_test() -> Nil {
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("client-secret"),
    )
  let assert Ok(http_request) =
    vestibule_microsoft.build_authorization_code_request(
      "tenant-id",
      client_configuration,
      "code-123",
      Some("verifier-123"),
    )
  assert http_request.method == http.Post
  assert http_request.host == "login.microsoftonline.com"
  assert string.contains(http_request.path, "/tenant-id/oauth2/v2.0/")
  assert string.ends_with(http_request.path, "/token")
  assert string.contains(http_request.body, "code_verifier=verifier-123")
  assert request.get_header(http_request, "accept") == Ok("application/json")

  let id_token = fake_id_token("{\"tid\":\"tenant-id\"}")
  let http_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"access-123\",\"token_type\":\"Bearer\",\"scope\":\"openid User.Read\",\"id_token\":\""
        <> id_token
        <> "\"}",
    )
  let assert Ok(exchange) =
    vestibule_microsoft.parse_authorization_code_response(http_response)
  assert exchange
    |> strategy.exchange_credentials
    |> credential.token
    == "access-123"
  let assert Ok(id_token_artifact) =
    dict.get(strategy.exchange_artifacts(exchange), "id_token")
  let assert Ok(parsed_id_token) = decode.run(id_token_artifact, decode.string)
  let assert Ok(_) =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "tenant-id",
      id_token: parsed_id_token,
    )
  Nil
}

pub fn sans_io_refresh_and_user_info_test() -> Nil {
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("client-secret"),
    )
  let assert Ok(refresh_request) =
    vestibule_microsoft.build_refresh_token_request(
      "common",
      client_configuration,
      "refresh-123",
    )
  assert string.contains(refresh_request.body, "grant_type=refresh_token")
  let refresh_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"new-access\",\"token_type\":\"Bearer\",\"scope\":\"User.Read\"}",
    )
  let assert Ok(refreshed_credentials) =
    vestibule_microsoft.parse_refresh_token_response(refresh_response)
  assert credential.token(refreshed_credentials) == "new-access"

  let oauth_credentials =
    credential.new(
      token: "access-123",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: [],
    )
  let assert Ok(user_request) =
    vestibule_microsoft.build_user_info_request(oauth_credentials)
  assert user_request.host == "graph.microsoft.com"
  assert request.get_header(user_request, "authorization")
    == Ok("Bearer access-123")

  let user_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"id\":\"user-123\",\"userPrincipalName\":\"user@example.com\"}",
    )
  let assert Ok(#(user_id, _)) =
    vestibule_microsoft.parse_user_info_response(user_response)
  assert user_id == "user-123"
}
