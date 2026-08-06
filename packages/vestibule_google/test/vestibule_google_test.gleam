import gleam/option.{None, Some}
import gleam/string
import gleeunit
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/strategy
import vestibule/user_info
import vestibule_google

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"ya29.test_token\",\"expires_in\":3599,\"scope\":\"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile\",\"token_type\":\"Bearer\"}"
  assert vestibule_google.parse_token_response(body)
    == Ok(
      credentials.new(
        token: "ya29.test_token",
        refresh_token: None,
        token_type: "Bearer",
        expires_in: Some(3599),
        scopes: [
          "openid",
          "https://www.googleapis.com/auth/userinfo.email",
          "https://www.googleapis.com/auth/userinfo.profile",
        ],
      ),
    )
}

pub fn parse_token_response_with_refresh_token_test() {
  let body =
    "{\"access_token\":\"ya29.test\",\"expires_in\":3600,\"refresh_token\":\"1//test_refresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}"
  assert vestibule_google.parse_token_response(body)
    == Ok(
      credentials.new(
        token: "ya29.test",
        refresh_token: Some("1//test_refresh"),
        token_type: "Bearer",
        expires_in: Some(3600),
        scopes: ["openid"],
      ),
    )
}

pub fn parse_token_response_empty_scope_test() {
  let body =
    "{\"access_token\":\"ya29.test\",\"expires_in\":3600,\"scope\":\"\",\"token_type\":\"Bearer\"}"
  let assert Ok(creds) = vestibule_google.parse_token_response(body)
  assert credentials.scopes(creds) == []
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been expired or revoked.\"}"
  let assert Error(_) = vestibule_google.parse_token_response(body)
  Nil
}

pub fn parse_token_response_error_without_description_test() {
  let body = "{\"error\":\"invalid_grant\"}"
  assert vestibule_google.parse_token_response(body)
    == Error(error.provider(code: "invalid_grant", description: "", uri: None))
}

pub fn parse_user_response_full_test() {
  let body =
    "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"given_name\":\"Jane\",\"family_name\":\"Doe\",\"picture\":\"https://lh3.googleusercontent.com/photo.jpg\",\"email\":\"jane@example.com\",\"email_verified\":true}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  assert uid == "1234567890"
  assert user_info.name(info) == Some("Jane Doe")
  assert user_info.email(info) == Some("jane@example.com")
  assert user_info.nickname(info) == Some("jane@example.com")
  assert user_info.image(info)
    == Some("https://lh3.googleusercontent.com/photo.jpg")
  assert user_info.description(info) == None
}

pub fn parse_user_response_unverified_email_test() {
  let body =
    "{\"sub\":\"999\",\"name\":\"Test\",\"email\":\"unverified@example.com\",\"email_verified\":false}"
  let assert Ok(#(_uid, info)) = vestibule_google.parse_user_response(body)
  assert user_info.email(info) == None
  assert user_info.nickname(info) == Some("unverified@example.com")
}

pub fn parse_user_response_minimal_test() {
  let body = "{\"sub\":\"abc-123\"}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  assert uid == "abc-123"
  assert user_info.name(info) == None
  assert user_info.email(info) == None
  assert user_info.nickname(info) == None
  assert user_info.image(info) == None
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() {
  let strat = vestibule_google.strategy()
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
      state: "state",
    )
  Nil
}

pub fn authorize_url_includes_extra_params_test() {
  let strat = vestibule_google.strategy()
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
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
      state: "state",
    )
  assert string.contains(url, "prompt=consent")
}

// --- Hosted-domain (hd) enforcement ---

pub fn parse_user_response_with_hd_present_test() {
  let body =
    "{\"sub\":\"42\",\"email\":\"jane@corp.example\",\"email_verified\":true,\"hd\":\"corp.example\"}"
  let assert Ok(#(uid, _info, hd)) =
    vestibule_google.parse_user_response_with_hd(body)
  assert uid == "42"
  assert hd == Some("corp.example")
}

pub fn parse_user_response_with_hd_absent_test() {
  let body =
    "{\"sub\":\"42\",\"email\":\"jane@gmail.com\",\"email_verified\":true}"
  let assert Ok(#(_uid, _info, hd)) =
    vestibule_google.parse_user_response_with_hd(body)
  assert hd == None
}

pub fn validate_hosted_domain_match_test() {
  assert vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: Some("corp.example"),
    )
    == Ok(Some("corp.example"))
}

pub fn validate_hosted_domain_mismatch_fails_test() {
  let assert Error(err) =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: Some("evil.com"),
    )
  case error.kind(err) {
    error.UserInfoKind -> Nil
    error.OtherKind ->
      panic as "expected UserInfoKind for hosted-domain mismatch"
    _ -> panic as "expected UserInfoKind for hosted-domain mismatch"
  }
}

pub fn validate_hosted_domain_missing_claim_fails_test() {
  let assert Error(err) =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: None,
    )
  case error.kind(err) {
    error.UserInfoKind -> Nil
    error.OtherKind -> panic as "expected UserInfoKind when hd claim is missing"
    _ -> panic as "expected UserInfoKind when hd claim is missing"
  }
}

pub fn validate_hosted_domain_not_required_passes_through_test() {
  assert vestibule_google.validate_hosted_domain(
      required: None,
      returned: Some("corp.example"),
    )
    == Ok(Some("corp.example"))

  assert vestibule_google.validate_hosted_domain(required: None, returned: None)
    == Ok(None)
}

pub fn strategy_for_hosted_domain_authorize_url_includes_hd_hint_test() {
  let strat = vestibule_google.strategy_for_hosted_domain("corp.example")
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
      scopes: ["openid"],
      state: "state",
    )
  assert string.contains(url, "hd=corp.example")
}
