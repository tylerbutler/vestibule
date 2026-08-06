import gleam/bit_array
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import vestibule/config
import vestibule/credentials
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

pub fn verify_tenant_match_test() {
  let token =
    fake_id_token("{\"tid\":\"72f988bf-86f1-41af-91ab-2d7cd011db47\"}")
  assert vestibule_microsoft.verify_tenant(
      expected_tenant: "72f988bf-86f1-41af-91ab-2d7cd011db47",
      id_token: token,
    )
    == Ok("72f988bf-86f1-41af-91ab-2d7cd011db47")
}

pub fn verify_tenant_case_insensitive_test() {
  let token =
    fake_id_token("{\"tid\":\"72F988BF-86F1-41AF-91AB-2D7CD011DB47\"}")
  let assert Ok(_) =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "72f988bf-86f1-41af-91ab-2d7cd011db47",
      id_token: token,
    )
  Nil
}

pub fn verify_tenant_mismatch_rejected_test() {
  let token = fake_id_token("{\"tid\":\"other-tenant-guid\"}")
  let assert Error(_) =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "expected-tenant-guid",
      id_token: token,
    )
  Nil
}

pub fn verify_tenant_missing_tid_rejected_test() {
  let token = fake_id_token("{\"sub\":\"abc\"}")
  let assert Error(_) =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "expected-tenant-guid",
      id_token: token,
    )
  Nil
}

pub fn verify_tenant_malformed_token_rejected_test() {
  let assert Error(_) =
    vestibule_microsoft.verify_tenant(
      expected_tenant: "expected-tenant-guid",
      id_token: "not-a-jwt",
    )
  Nil
}

pub fn id_token_tenant_extracts_tid_test() {
  let token = fake_id_token("{\"tid\":\"abc-123\",\"sub\":\"u1\"}")
  assert vestibule_microsoft.id_token_tenant(token) == Ok("abc-123")
}

pub fn strategy_for_tenant_authorize_url_uses_tenant_endpoint_test() {
  let strat = vestibule_microsoft.strategy_for_tenant("my-tenant-id")
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(url) =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: config.authorize_options(),
      scopes: ["openid", "User.Read"],
      state: "state",
    )
  assert string.contains(
    url,
    "login.microsoftonline.com/my-tenant-id/oauth2/v2.0",
  )
}

pub fn strategy_for_tenant_default_scopes_include_openid_test() {
  let strat = vestibule_microsoft.strategy_for_tenant("my-tenant-id")
  assert strategy.default_scopes(strat) == ["openid", "User.Read"]
}

pub fn common_strategy_default_scopes_include_openid_test() {
  let strat = vestibule_microsoft.strategy()
  assert strategy.default_scopes(strat) == ["openid", "User.Read"]
}

pub fn common_strategy_authorize_url_uses_common_endpoint_test() {
  let strat = vestibule_microsoft.strategy()
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(url) =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: config.authorize_options(),
      scopes: ["User.Read"],
      state: "state",
    )
  assert string.contains(url, "login.microsoftonline.com/common/oauth2/v2.0")
}

pub fn custom_scopes_add_openid_for_nonce_test() {
  let strat = vestibule_microsoft.strategy()
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(url) =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: config.authorize_options(),
      scopes: ["User.Read"],
      state: "state",
    )
  assert string.contains(url, "openid")
  assert string.contains(url, "User.Read")
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read profile openid email\",\"expires_in\":3736,\"ext_expires_in\":3736,\"access_token\":\"eyJ0eXAi_test_token\",\"refresh_token\":\"AwABAAAA_test_refresh\"}"
  assert vestibule_microsoft.parse_token_response(body)
    == Ok(
      credentials.new(
        token: "eyJ0eXAi_test_token",
        refresh_token: Some("AwABAAAA_test_refresh"),
        token_type: "Bearer",
        expires_in: Some(3736),
        scopes: ["User.Read", "profile", "openid", "email"],
      ),
    )
}

pub fn parse_token_response_without_refresh_token_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read\",\"expires_in\":3600,\"access_token\":\"test_token\"}"
  assert vestibule_microsoft.parse_token_response(body)
    == Ok(
      credentials.new(
        token: "test_token",
        refresh_token: None,
        token_type: "Bearer",
        expires_in: Some(3600),
        scopes: ["User.Read"],
      ),
    )
}

pub fn parse_token_response_empty_scope_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"\",\"expires_in\":3600,\"access_token\":\"test_token\"}"
  let assert Ok(creds) = vestibule_microsoft.parse_token_response(body)
  assert credentials.scopes(creds) == []
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS70000: The provided value for the input parameter 'code' is not valid.\"}"
  let assert Error(_) = vestibule_microsoft.parse_token_response(body)
  Nil
}

pub fn parse_user_response_full_test() {
  let body =
    "{\"id\":\"87d349ed-44d7-43e1-9a83-5f2406dee5bd\",\"displayName\":\"Adele Vance\",\"mail\":\"AdeleV@contoso.com\",\"userPrincipalName\":\"AdeleV@contoso.com\",\"jobTitle\":\"Retail Manager\"}"
  let assert Ok(#(uid, info)) = vestibule_microsoft.parse_user_response(body)
  assert uid == "87d349ed-44d7-43e1-9a83-5f2406dee5bd"
  assert user_info.name(info) == Some("Adele Vance")
  assert user_info.email(info) == Some("AdeleV@contoso.com")
  assert user_info.nickname(info) == Some("AdeleV@contoso.com")
  assert user_info.description(info) == Some("Retail Manager")
  // Microsoft Graph doesn't provide a direct image URL
  assert user_info.image(info) == None
}

pub fn parse_user_response_minimal_test() {
  let body = "{\"id\":\"abc-123\",\"userPrincipalName\":\"user@example.com\"}"
  let assert Ok(#(uid, info)) = vestibule_microsoft.parse_user_response(body)
  assert uid == "abc-123"
  assert user_info.name(info) == None
  // UPN is not a verified email, so email should be None
  assert user_info.email(info) == None
  assert user_info.nickname(info) == Some("user@example.com")
  assert user_info.description(info) == None
  // No gravatar when no verified email
  assert user_info.image(info) == None
}

pub fn parse_user_response_mail_preferred_over_upn_test() {
  let body =
    "{\"id\":\"abc\",\"mail\":\"real@example.com\",\"userPrincipalName\":\"upn@example.com\"}"
  let assert Ok(#(_uid, info)) = vestibule_microsoft.parse_user_response(body)
  assert user_info.email(info) == Some("real@example.com")
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() {
  let strat = vestibule_microsoft.strategy()
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
      scopes: ["User.Read"],
      state: "state",
    )
  Nil
}

pub fn authorize_url_includes_extra_params_test() {
  let strat = vestibule_microsoft.strategy()
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "select_account")])
  let assert Ok(url) =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: options,
      scopes: ["User.Read"],
      state: "state",
    )
  assert string.contains(url, "prompt=select_account")
}
