import gleam/bit_array
import gleam/dict
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/string
import gleam/time/duration
import gleeunit
import vestibule
import vestibule/auth
import vestibule/config
import vestibule/credential
import vestibule/error
import vestibule/oidc
import vestibule/strategy
import vestibule/user_info
import vestibule_microsoft
import vestibule_microsoft/jwt_signing
import ywt/claim

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

fn test_jwks() -> oidc.Jwks {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  keys
}

pub fn forged_tenant_token_is_rejected_test() -> Nil {
  let token =
    fake_id_token(
      "{\"iss\":\"https://login.microsoftonline.com/trusted/v2.0\",\"aud\":\"client-id\",\"exp\":4102444800,\"sub\":\"user\",\"tid\":\"trusted\",\"oid\":\"object-id\"}",
    )
  let assert Error(authentication_error) =
    vestibule_microsoft.verify_id_token(
      token,
      test_jwks(),
      "client-id",
      Some("trusted"),
    )
  assert error.kind(authentication_error) == error.UserInfoKind
}

pub fn expired_signed_tenant_token_is_rejected_test() -> Nil {
  assert_verified_token_rejected(
    microsoft_token(
      "https://login.microsoftonline.com/trusted/v2.0",
      "client-id",
      "trusted",
      "object-id",
      "nonce",
      duration.seconds(-120),
    ),
    Some("trusted"),
  )
}

pub fn wrong_audience_signed_tenant_token_is_rejected_test() -> Nil {
  assert_verified_token_rejected(
    microsoft_token(
      "https://login.microsoftonline.com/trusted/v2.0",
      "other-client",
      "trusted",
      "object-id",
      "nonce",
      duration.minutes(5),
    ),
    Some("trusted"),
  )
}

pub fn wrong_issuer_signed_tenant_token_is_rejected_test() -> Nil {
  assert_verified_token_rejected(
    microsoft_token(
      "https://evil.example",
      "client-id",
      "trusted",
      "object-id",
      "nonce",
      duration.minutes(5),
    ),
    Some("trusted"),
  )
}

pub fn wrong_signed_tenant_is_rejected_test() -> Nil {
  assert_verified_token_rejected(
    microsoft_token(
      "https://login.microsoftonline.com/other/v2.0",
      "client-id",
      "other",
      "object-id",
      "nonce",
      duration.minutes(5),
    ),
    Some("trusted"),
  )
}

pub fn malformed_tenant_token_is_rejected_test() -> Nil {
  let assert Error(authentication_error) =
    vestibule_microsoft.verify_id_token(
      "not-a-jwt",
      test_jwks(),
      "client-id",
      Some("trusted"),
    )
  assert error.kind(authentication_error) == error.UserInfoKind
}

pub fn strategy_for_tenant_authorize_url_uses_tenant_endpoint_test() -> Nil {
  let microsoft_strategy =
    vestibule_microsoft.strategy_for_tenant("my-tenant-id")
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth("secret"),
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
      auth: config.client_secret_auth("secret"),
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
      auth: config.client_secret_auth("secret"),
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
      auth: config.client_secret_auth("secret"),
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
      auth: config.client_secret_auth("secret"),
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
      auth: config.client_secret_auth("client-secret"),
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
  assert parsed_id_token == id_token
  Nil
}

pub fn sans_io_refresh_and_user_info_test() -> Nil {
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.client_secret_auth("client-secret"),
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

pub fn jwks_request_and_invalid_response_test() -> Nil {
  let assert Ok(http_request) = vestibule_microsoft.build_jwks_request()
  assert http_request.host == "login.microsoftonline.com"
  assert http_request.path == "/common/discovery/v2.0/keys"
  assert request.get_header(http_request, "accept") == Ok("application/json")

  let invalid_response =
    response.Response(status: 200, headers: [], body: "{\"keys\":[]}")
  let assert Error(authentication_error) =
    vestibule_microsoft.parse_jwks_response(invalid_response)
  assert error.kind(authentication_error) == error.UserInfoKind
}

pub fn callback_accepts_signed_tenant_and_graph_identity_test() -> Nil {
  let assert Ok(auth_result) =
    microsoft_callback("trusted", "object-id", "object-id", "nonce", "nonce")
  assert auth.uid(auth_result) == "object-id"
}

pub fn callback_rejects_graph_identity_substitution_test() -> Nil {
  let assert Error(auth_error) =
    microsoft_callback("trusted", "object-id", "victim", "nonce", "nonce")
  assert error.kind(auth_error) == error.UserInfoKind
}

pub fn callback_rejects_wrong_signed_tenant_test() -> Nil {
  let assert Error(auth_error) =
    microsoft_callback("other", "object-id", "object-id", "nonce", "nonce")
  assert error.kind(auth_error) == error.UserInfoKind
}

pub fn callback_rejects_wrong_signed_nonce_test() -> Nil {
  let assert Error(auth_error) =
    microsoft_callback("trusted", "object-id", "object-id", "wrong", "nonce")
  assert error.kind(auth_error) == error.InvalidNonceKind
}

fn assert_verified_token_rejected(
  id_token: String,
  expected_tenant: Option(String),
) -> Nil {
  let assert Error(auth_error) =
    vestibule_microsoft.verify_id_token(
      id_token,
      test_jwks(),
      "client-id",
      expected_tenant,
    )
  assert error.kind(auth_error) == error.UserInfoKind
}

fn microsoft_token(
  issuer: String,
  audience: String,
  tenant: String,
  object_id: String,
  nonce: String,
  max_age: duration.Duration,
) -> String {
  jwt_signing.encode(
    [
      #("sub", json.string("user-123")),
      #("tid", json.string(tenant)),
      #("oid", json.string(object_id)),
    ],
    [
      claim.issuer(issuer, []),
      claim.audience(audience, []),
      claim.custom(
        name: "nonce",
        value: nonce,
        encode: json.string,
        decoder: decode.string,
      ),
      claim.expires_at(max_age: max_age, leeway: duration.seconds(0)),
    ],
  )
}

fn microsoft_callback(
  tenant: String,
  token_object_id: String,
  graph_object_id: String,
  token_nonce: String,
  expected_nonce: String,
) {
  let id_token =
    microsoft_token(
      "https://login.microsoftonline.com/" <> tenant <> "/v2.0",
      "client-id",
      tenant,
      token_object_id,
      token_nonce,
      duration.minutes(5),
    )
  let sender = fn(http_request: request.Request(String)) {
    case
      http_request.host,
      string.ends_with(http_request.path, "/token"),
      http_request.path
    {
      "login.microsoftonline.com", True, _ ->
        Ok(response.Response(
          status: 200,
          headers: [],
          body: json.object([
            #("access_token", json.string("access-token")),
            #("token_type", json.string("Bearer")),
            #("scope", json.string("openid User.Read")),
            #("id_token", json.string(id_token)),
          ])
            |> json.to_string(),
        ))
      "login.microsoftonline.com", False, "/common/discovery/v2.0/keys" ->
        Ok(response.Response(status: 200, headers: [], body: jwt_signing.jwks()))
      "graph.microsoft.com", False, "/v1.0/me" ->
        Ok(response.Response(
          status: 200,
          headers: [],
          body: json.object([
            #("id", json.string(graph_object_id)),
            #("displayName", json.string("User")),
            #("userPrincipalName", json.string("user@example.com")),
          ])
            |> json.to_string(),
        ))
      _, _, _ -> Error(Nil)
    }
  }
  vestibule.handle_callback(
    vestibule_microsoft.strategy_for_tenant_with_sender("trusted", sender),
    config: config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example/callback",
      auth: config.client_secret_auth("secret"),
    ),
    callback_params: dict.from_list([
      #("state", "state"),
      #("code", "code"),
    ]),
    expected_state: "state",
    code_verifier: "verifier",
    expected_nonce: Some(expected_nonce),
  )
}
