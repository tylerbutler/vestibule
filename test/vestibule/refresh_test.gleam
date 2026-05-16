import gleam/option.{None, Some}
import startest/expect
import vestibule/credentials
import vestibule/error
import vestibule/provider_support

pub fn parse_refresh_response_success_with_all_fields_test() {
  let body =
    "{\"access_token\":\"new_access_token\",\"token_type\":\"Bearer\",\"refresh_token\":\"new_refresh_token\",\"expires_in\":3600,\"scope\":\"openid profile email\"}"
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_ok()
  |> expect.to_equal(
    credentials.new(
      token: "new_access_token",
      refresh_token: Some("new_refresh_token"),
      token_type: "Bearer",
      expires_in: Some(3600),
      scopes: ["openid", "profile", "email"],
    ),
  )
}

pub fn parse_refresh_response_success_minimal_test() {
  let body = "{\"access_token\":\"token_abc\",\"token_type\":\"bearer\"}"
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_ok()
  |> expect.to_equal(
    credentials.new(
      token: "token_abc",
      refresh_token: None,
      token_type: "bearer",
      expires_in: None,
      scopes: [],
    ),
  )
}

pub fn parse_refresh_response_with_refresh_token_rotation_test() {
  let body =
    "{\"access_token\":\"rotated_access\",\"token_type\":\"Bearer\",\"refresh_token\":\"rotated_refresh\",\"expires_in\":7200,\"scope\":\"user:email\"}"
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_ok()
  |> expect.to_equal(
    credentials.new(
      token: "rotated_access",
      refresh_token: Some("rotated_refresh"),
      token_type: "Bearer",
      expires_in: Some(7200),
      scopes: ["user:email"],
    ),
  )
}

pub fn parse_refresh_response_rotation_without_refresh_token_test() {
  let body =
    "{\"access_token\":\"rotated_access\",\"token_type\":\"Bearer\",\"expires_in\":7200,\"scope\":\"user:email\"}"
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_ok()
  |> expect.to_equal(
    credentials.new(
      token: "rotated_access",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: Some(7200),
      scopes: ["user:email"],
    ),
  )
}

pub fn parse_refresh_response_error_invalid_grant_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The refresh token has expired.\"}"
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_error()
  |> expect.to_equal(error.ProviderError(
    code: "invalid_grant",
    description: "The refresh token has expired.",
    uri: None,
  ))
}

pub fn parse_refresh_response_error_invalid_client_test() {
  let body =
    "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}"
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_error()
  |> expect.to_equal(error.ProviderError(
    code: "invalid_client",
    description: "Client authentication failed.",
    uri: None,
  ))
}

pub fn parse_refresh_response_malformed_json_test() {
  let body = "not valid json at all"
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_error()
  |> expect.to_equal(error.DecodeError(
    context: "token response",
    reason: "UnexpectedByte(\"0x6F\")",
  ))
}

pub fn parse_refresh_response_without_scope_has_empty_scopes_test() {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
  let assert Ok(creds) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  credentials.scopes(creds) |> expect.to_equal([])
}

pub fn parse_refresh_response_empty_scope_has_empty_scopes_test() {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"\"}"
  let assert Ok(creds) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  credentials.scopes(creds) |> expect.to_equal([])
}
