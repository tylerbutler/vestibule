import gleam/option.{None, Some}
import startest
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule_google

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"ya29.test_token\",\"expires_in\":3599,\"scope\":\"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile\",\"token_type\":\"Bearer\"}"
  vestibule_google.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "ya29.test_token",
      refresh_token: None,
      token_type: "Bearer",
      expires_at: Some(3599),
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
  vestibule_google.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "ya29.test",
      refresh_token: Some("1//test_refresh"),
      token_type: "Bearer",
      expires_at: Some(3600),
      scopes: ["openid"],
    ),
  )
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been expired or revoked.\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn parse_user_response_full_test() {
  let body =
    "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"given_name\":\"Jane\",\"family_name\":\"Doe\",\"picture\":\"https://lh3.googleusercontent.com/photo.jpg\",\"email\":\"jane@example.com\",\"email_verified\":true}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  uid |> expect.to_equal("1234567890")
  info.name |> expect.to_equal(Some("Jane Doe"))
  info.email |> expect.to_equal(Some("jane@example.com"))
  info.nickname |> expect.to_equal(Some("jane@example.com"))
  info.image
  |> expect.to_equal(Some("https://lh3.googleusercontent.com/photo.jpg"))
  info.description |> expect.to_equal(None)
}

pub fn parse_user_response_unverified_email_test() {
  let body =
    "{\"sub\":\"999\",\"name\":\"Test\",\"email\":\"unverified@example.com\",\"email_verified\":false}"
  let assert Ok(#(_uid, info)) = vestibule_google.parse_user_response(body)
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(Some("unverified@example.com"))
}

pub fn parse_user_response_minimal_test() {
  let body = "{\"sub\":\"abc-123\"}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  uid |> expect.to_equal("abc-123")
  info.name |> expect.to_equal(None)
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(None)
  info.image |> expect.to_equal(None)
}
