import gleam/option.{None, Some}
import startest/expect
import vestibule
import vestibule/credentials.{Credentials}
import vestibule/error

pub fn parse_refresh_response_success_with_all_fields_test() {
  let body =
    "{\"access_token\":\"new_access_token\",\"token_type\":\"Bearer\",\"refresh_token\":\"new_refresh_token\",\"expires_in\":3600,\"scope\":\"openid profile email\"}"
  vestibule.parse_refresh_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "new_access_token",
      refresh_token: Some("new_refresh_token"),
      token_type: "Bearer",
      expires_at: Some(3600),
      scopes: ["openid", "profile", "email"],
    ),
  )
}

pub fn parse_refresh_response_success_minimal_test() {
  let body = "{\"access_token\":\"token_abc\",\"token_type\":\"bearer\"}"
  vestibule.parse_refresh_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "token_abc",
      refresh_token: None,
      token_type: "bearer",
      expires_at: None,
      scopes: [],
    ),
  )
}

pub fn parse_refresh_response_with_refresh_token_rotation_test() {
  let body =
    "{\"access_token\":\"rotated_access\",\"token_type\":\"Bearer\",\"refresh_token\":\"rotated_refresh\",\"expires_in\":7200,\"scope\":\"user:email\"}"
  vestibule.parse_refresh_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "rotated_access",
      refresh_token: Some("rotated_refresh"),
      token_type: "Bearer",
      expires_at: Some(7200),
      scopes: ["user:email"],
    ),
  )
}

pub fn parse_refresh_response_error_invalid_grant_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The refresh token has expired.\"}"
  vestibule.parse_refresh_response(body)
  |> expect.to_be_error()
  |> expect.to_equal(error.ProviderError(
    code: "invalid_grant",
    description: "The refresh token has expired.",
  ))
}

pub fn parse_refresh_response_error_invalid_client_test() {
  let body =
    "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}"
  vestibule.parse_refresh_response(body)
  |> expect.to_be_error()
  |> expect.to_equal(error.ProviderError(
    code: "invalid_client",
    description: "Client authentication failed.",
  ))
}

pub fn parse_refresh_response_malformed_json_test() {
  let body = "not valid json at all"
  vestibule.parse_refresh_response(body)
  |> expect.to_be_error()
  |> expect.to_equal(error.CodeExchangeFailed(
    reason: "Failed to parse token refresh response",
  ))
}

pub fn parse_refresh_response_without_scope_has_empty_scopes_test() {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
  let assert Ok(creds) = vestibule.parse_refresh_response(body)
  creds.scopes |> expect.to_equal([])
}
