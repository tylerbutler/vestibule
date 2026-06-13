import gleam/bit_array
import gleam/option.{None, Some}
import gleam/string
import startest
import startest/expect
import vestibule/config
import vestibule/credentials
import vestibule/strategy
import vestibule_microsoft

pub fn main() -> Nil {
  startest.run(startest.default_config())
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
  vestibule_microsoft.verify_tenant(
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    token,
  )
  |> expect.to_be_ok()
  |> expect.to_equal("72f988bf-86f1-41af-91ab-2d7cd011db47")
}

pub fn verify_tenant_case_insensitive_test() {
  let token =
    fake_id_token("{\"tid\":\"72F988BF-86F1-41AF-91AB-2D7CD011DB47\"}")
  vestibule_microsoft.verify_tenant(
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    token,
  )
  |> expect.to_be_ok()
  Nil
}

pub fn verify_tenant_mismatch_rejected_test() {
  let token = fake_id_token("{\"tid\":\"other-tenant-guid\"}")
  let _ =
    vestibule_microsoft.verify_tenant("expected-tenant-guid", token)
    |> expect.to_be_error()
  Nil
}

pub fn verify_tenant_missing_tid_rejected_test() {
  let token = fake_id_token("{\"sub\":\"abc\"}")
  let _ =
    vestibule_microsoft.verify_tenant("expected-tenant-guid", token)
    |> expect.to_be_error()
  Nil
}

pub fn verify_tenant_malformed_token_rejected_test() {
  let _ =
    vestibule_microsoft.verify_tenant("expected-tenant-guid", "not-a-jwt")
    |> expect.to_be_error()
  Nil
}

pub fn id_token_tenant_extracts_tid_test() {
  let token = fake_id_token("{\"tid\":\"abc-123\",\"sub\":\"u1\"}")
  vestibule_microsoft.id_token_tenant(token)
  |> expect.to_be_ok()
  |> expect.to_equal("abc-123")
}

pub fn strategy_for_tenant_authorize_url_uses_tenant_endpoint_test() {
  let strat = vestibule_microsoft.strategy_for_tenant("my-tenant-id")
  let conf = config.new("client-id", "secret", "http://localhost/callback")
  let assert Ok(url) =
    strategy.build_authorize_url(strat, conf, ["openid", "User.Read"], "state")
  { string.contains(url, "login.microsoftonline.com/my-tenant-id/oauth2/v2.0") }
  |> expect.to_be_true()
}

pub fn strategy_for_tenant_default_scopes_include_openid_test() {
  let strat = vestibule_microsoft.strategy_for_tenant("my-tenant-id")
  strategy.default_scopes(strat)
  |> expect.to_equal(["openid", "User.Read"])
}

pub fn common_strategy_authorize_url_uses_common_endpoint_test() {
  let strat = vestibule_microsoft.strategy()
  let conf = config.new("client-id", "secret", "http://localhost/callback")
  let assert Ok(url) =
    strategy.build_authorize_url(strat, conf, ["User.Read"], "state")
  { string.contains(url, "login.microsoftonline.com/common/oauth2/v2.0") }
  |> expect.to_be_true()
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read profile openid email\",\"expires_in\":3736,\"ext_expires_in\":3736,\"access_token\":\"eyJ0eXAi_test_token\",\"refresh_token\":\"AwABAAAA_test_refresh\"}"
  vestibule_microsoft.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
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
  vestibule_microsoft.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
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
  credentials.scopes(creds) |> expect.to_equal([])
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS70000: The provided value for the input parameter 'code' is not valid.\"}"
  let _ =
    vestibule_microsoft.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn parse_user_response_full_test() {
  let body =
    "{\"id\":\"87d349ed-44d7-43e1-9a83-5f2406dee5bd\",\"displayName\":\"Adele Vance\",\"mail\":\"AdeleV@contoso.com\",\"userPrincipalName\":\"AdeleV@contoso.com\",\"jobTitle\":\"Retail Manager\"}"
  let assert Ok(#(uid, info)) = vestibule_microsoft.parse_user_response(body)
  uid |> expect.to_equal("87d349ed-44d7-43e1-9a83-5f2406dee5bd")
  info.name |> expect.to_equal(Some("Adele Vance"))
  info.email |> expect.to_equal(Some("AdeleV@contoso.com"))
  info.nickname |> expect.to_equal(Some("AdeleV@contoso.com"))
  info.description |> expect.to_equal(Some("Retail Manager"))
  // Microsoft Graph doesn't provide a direct image URL
  info.image |> expect.to_equal(None)
}

pub fn parse_user_response_minimal_test() {
  let body = "{\"id\":\"abc-123\",\"userPrincipalName\":\"user@example.com\"}"
  let assert Ok(#(uid, info)) = vestibule_microsoft.parse_user_response(body)
  uid |> expect.to_equal("abc-123")
  info.name |> expect.to_equal(None)
  // UPN is not a verified email, so email should be None
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(Some("user@example.com"))
  info.description |> expect.to_equal(None)
  // No gravatar when no verified email
  info.image |> expect.to_equal(None)
}

pub fn parse_user_response_mail_preferred_over_upn_test() {
  let body =
    "{\"id\":\"abc\",\"mail\":\"real@example.com\",\"userPrincipalName\":\"upn@example.com\"}"
  let assert Ok(#(_uid, info)) = vestibule_microsoft.parse_user_response(body)
  info.email |> expect.to_equal(Some("real@example.com"))
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() {
  let strat = vestibule_microsoft.strategy()
  let conf = config.new("client-id", "secret", "not a uri")
  let _ =
    strategy.build_authorize_url(strat, conf, ["User.Read"], "state")
    |> expect.to_be_error()
  Nil
}

pub fn authorize_url_includes_extra_params_test() {
  let strat = vestibule_microsoft.strategy()
  let assert Ok(conf) =
    config.new("client-id", "secret", "http://localhost/callback")
    |> config.with_extra_params([#("prompt", "select_account")])
  let assert Ok(url) =
    strategy.build_authorize_url(strat, conf, ["User.Read"], "state")
  { string.contains(url, "prompt=select_account") } |> expect.to_be_true()
}
