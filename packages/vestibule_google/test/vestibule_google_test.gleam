import gleam/option.{None, Some}
import gleam/string
import startest
import startest/expect
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/strategy
import vestibule/user_info
import vestibule_google

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"ya29.test_token\",\"expires_in\":3599,\"scope\":\"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile\",\"token_type\":\"Bearer\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> expect.to_be_ok()
    |> expect.to_equal(
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
  Nil
}

pub fn parse_token_response_with_refresh_token_test() {
  let body =
    "{\"access_token\":\"ya29.test\",\"expires_in\":3600,\"refresh_token\":\"1//test_refresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> expect.to_be_ok()
    |> expect.to_equal(
      credentials.new(
        token: "ya29.test",
        refresh_token: Some("1//test_refresh"),
        token_type: "Bearer",
        expires_in: Some(3600),
        scopes: ["openid"],
      ),
    )
  Nil
}

pub fn parse_token_response_empty_scope_test() {
  let body =
    "{\"access_token\":\"ya29.test\",\"expires_in\":3600,\"scope\":\"\",\"token_type\":\"Bearer\"}"
  let assert Ok(creds) = vestibule_google.parse_token_response(body)
  let _ = credentials.scopes(creds) |> expect.to_equal([])
  Nil
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been expired or revoked.\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn parse_token_response_error_without_description_test() {
  let body = "{\"error\":\"invalid_grant\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> expect.to_be_error()
    |> expect.to_equal(error.provider(
      code: "invalid_grant",
      description: "",
      uri: None,
    ))
  Nil
}

pub fn parse_user_response_full_test() {
  let body =
    "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"given_name\":\"Jane\",\"family_name\":\"Doe\",\"picture\":\"https://lh3.googleusercontent.com/photo.jpg\",\"email\":\"jane@example.com\",\"email_verified\":true}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  let _ = uid |> expect.to_equal("1234567890")
  let _ = user_info.name(info) |> expect.to_equal(Some("Jane Doe"))
  let _ = user_info.email(info) |> expect.to_equal(Some("jane@example.com"))
  let _ = user_info.nickname(info) |> expect.to_equal(Some("jane@example.com"))
  let _ =
    user_info.image(info)
    |> expect.to_equal(Some("https://lh3.googleusercontent.com/photo.jpg"))
  let _ = user_info.description(info) |> expect.to_equal(None)
  Nil
}

pub fn parse_user_response_unverified_email_test() {
  let body =
    "{\"sub\":\"999\",\"name\":\"Test\",\"email\":\"unverified@example.com\",\"email_verified\":false}"
  let assert Ok(#(_uid, info)) = vestibule_google.parse_user_response(body)
  let _ = user_info.email(info) |> expect.to_equal(None)
  let _ =
    user_info.nickname(info) |> expect.to_equal(Some("unverified@example.com"))
  Nil
}

pub fn parse_user_response_minimal_test() {
  let body = "{\"sub\":\"abc-123\"}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  let _ = uid |> expect.to_equal("abc-123")
  let _ = user_info.name(info) |> expect.to_equal(None)
  let _ = user_info.email(info) |> expect.to_equal(None)
  let _ = user_info.nickname(info) |> expect.to_equal(None)
  let _ = user_info.image(info) |> expect.to_equal(None)
  Nil
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() {
  let strat = vestibule_google.strategy()
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.ClientSecret("secret"),
    )
  let _ =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: config.authorize_options(),
      scopes: ["openid"],
      state: "state",
    )
    |> expect.to_be_error()
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
  let _ = { string.contains(url, "prompt=consent") } |> expect.to_be_true()
  Nil
}

// --- Hosted-domain (hd) enforcement ---

pub fn parse_user_response_with_hd_present_test() {
  let body =
    "{\"sub\":\"42\",\"email\":\"jane@corp.example\",\"email_verified\":true,\"hd\":\"corp.example\"}"
  let assert Ok(#(uid, _info, hd)) =
    vestibule_google.parse_user_response_with_hd(body)
  let _ = uid |> expect.to_equal("42")
  let _ = hd |> expect.to_equal(Some("corp.example"))
  Nil
}

pub fn parse_user_response_with_hd_absent_test() {
  let body =
    "{\"sub\":\"42\",\"email\":\"jane@gmail.com\",\"email_verified\":true}"
  let assert Ok(#(_uid, _info, hd)) =
    vestibule_google.parse_user_response_with_hd(body)
  let _ = hd |> expect.to_equal(None)
  Nil
}

pub fn validate_hosted_domain_match_test() {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: Some("corp.example"),
    )
    |> expect.to_be_ok()
    |> expect.to_equal(Some("corp.example"))
  Nil
}

pub fn validate_hosted_domain_mismatch_fails_test() {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: Some("evil.com"),
    )
    |> expect.to_be_error()
    |> fn(err) {
      case error.kind(err) {
        error.UserInfoKind -> Nil
        error.OtherKind ->
          panic as "expected UserInfoKind for hosted-domain mismatch"
        _ -> panic as "expected UserInfoKind for hosted-domain mismatch"
      }
    }
  Nil
}

pub fn validate_hosted_domain_missing_claim_fails_test() {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: None,
    )
    |> expect.to_be_error()
    |> fn(err) {
      case error.kind(err) {
        error.UserInfoKind -> Nil
        error.OtherKind ->
          panic as "expected UserInfoKind when hd claim is missing"
        _ -> panic as "expected UserInfoKind when hd claim is missing"
      }
    }
  Nil
}

pub fn validate_hosted_domain_not_required_passes_through_test() {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: None,
      returned: Some("corp.example"),
    )
    |> expect.to_be_ok()
    |> expect.to_equal(Some("corp.example"))

  let _ =
    vestibule_google.validate_hosted_domain(required: None, returned: None)
    |> expect.to_be_ok()
    |> expect.to_equal(None)
  Nil
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
  let _ = { string.contains(url, "hd=corp.example") } |> expect.to_be_true()
  Nil
}
