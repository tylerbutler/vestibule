import gleam/option.{None, Some}
import vestibule/credential
import vestibule/error
import vestibule/provider_support

pub fn parse_refresh_response_success_with_all_fields_test() -> Nil {
  let body =
    "{\"access_token\":\"new_access_token\",\"token_type\":\"Bearer\",\"refresh_token\":\"new_refresh_token\",\"expires_in\":3600,\"scope\":\"openid profile email\"}"
  let assert Ok(parsed) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  assert parsed
    == credential.new(
      token: "new_access_token",
      refresh_token: Some("new_refresh_token"),
      token_type: "Bearer",
      expires_in: Some(3600),
      scopes: ["openid", "profile", "email"],
    )
}

pub fn parse_refresh_response_success_minimal_test() -> Nil {
  let body = "{\"access_token\":\"token_abc\",\"token_type\":\"bearer\"}"
  let assert Ok(parsed) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  assert parsed
    == credential.new(
      token: "token_abc",
      refresh_token: None,
      token_type: "bearer",
      expires_in: None,
      scopes: [],
    )
}

pub fn parse_refresh_response_with_refresh_token_rotation_test() -> Nil {
  let body =
    "{\"access_token\":\"rotated_access\",\"token_type\":\"Bearer\",\"refresh_token\":\"rotated_refresh\",\"expires_in\":7200,\"scope\":\"user:email\"}"
  let assert Ok(parsed) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  assert parsed
    == credential.new(
      token: "rotated_access",
      refresh_token: Some("rotated_refresh"),
      token_type: "Bearer",
      expires_in: Some(7200),
      scopes: ["user:email"],
    )
}

pub fn parse_refresh_response_rotation_without_refresh_token_test() -> Nil {
  let body =
    "{\"access_token\":\"rotated_access\",\"token_type\":\"Bearer\",\"expires_in\":7200,\"scope\":\"user:email\"}"
  let assert Ok(parsed) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  assert parsed
    == credential.new(
      token: "rotated_access",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: Some(7200),
      scopes: ["user:email"],
    )
}

pub fn parse_refresh_response_error_invalid_grant_test() -> Nil {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The refresh token has expired.\"}"
  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
    == Error(error.provider(
      code: "invalid_grant",
      description: "The refresh token has expired.",
      uri: None,
    ))
}

pub fn parse_refresh_response_error_invalid_client_test() -> Nil {
  let body =
    "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}"
  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
    == Error(error.provider(
      code: "invalid_client",
      description: "Client authentication failed.",
      uri: None,
    ))
}

pub fn parse_refresh_response_malformed_json_test() -> Nil {
  let body = "not valid json at all"
  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
    == Error(error.decode(
      context: "token response",
      reason: "UnexpectedByte(\"0x6F\")",
    ))
}

pub fn parse_refresh_response_without_scope_has_empty_scopes_test() -> Nil {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
  let assert Ok(oauth_credentials) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  assert credential.scopes(oauth_credentials) == []
}

pub fn parse_refresh_response_empty_scope_has_empty_scopes_test() -> Nil {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"\"}"
  let assert Ok(oauth_credentials) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  assert credential.scopes(oauth_credentials) == []
}
