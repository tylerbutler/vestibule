import gleam/option.{None, Some}
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule/strategy/microsoft

pub fn parse_token_response_success_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read profile openid email\",\"expires_in\":3736,\"ext_expires_in\":3736,\"access_token\":\"eyJ0eXAi_test_token\",\"refresh_token\":\"AwABAAAA_test_refresh\"}"
  microsoft.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(Credentials(
    token: "eyJ0eXAi_test_token",
    refresh_token: Some("AwABAAAA_test_refresh"),
    token_type: "Bearer",
    expires_at: Some(3736),
    scopes: ["User.Read", "profile", "openid", "email"],
  ))
}

pub fn parse_token_response_without_refresh_token_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read\",\"expires_in\":3600,\"access_token\":\"test_token\"}"
  microsoft.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(Credentials(
    token: "test_token",
    refresh_token: None,
    token_type: "Bearer",
    expires_at: Some(3600),
    scopes: ["User.Read"],
  ))
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS70000: The provided value for the input parameter 'code' is not valid.\"}"
  let _ =
    microsoft.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}
