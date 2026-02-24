import gleam/dynamic/decode
import gleam/json
import gleam/option.{None}
import gleam/string

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info.{type UserInfo}

/// Create a GitHub authentication strategy.
pub fn strategy() -> Strategy {
  Strategy(
    provider: "github",
    default_scopes: ["user:email"],
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
}

/// Parse a GitHub token exchange response into Credentials.
/// Exported for testing.
pub fn parse_token_response(
  body: String,
) -> Result(Credentials, AuthError) {
  // First check if it's an error response
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.field("error_description", decode.string)
    decode.success(#(error_code, description))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description)) ->
      Error(error.ProviderError(code: code, description: description))
    _ -> parse_success_token(body)
  }
}

fn parse_success_token(body: String) -> Result(Credentials, AuthError) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use scope <- decode.field("scope", decode.string)
    decode.success(Credentials(
      token: access_token,
      refresh_token: None,
      token_type: token_type,
      expires_at: None,
      scopes: string.split(scope, ","),
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse token response",
      ))
  }
}

// Placeholder implementations — will be filled in subsequent tasks
fn do_authorize_url(
  _config: Config,
  _scopes: List(String),
  _state: String,
) -> Result(String, AuthError) {
  Error(error.ConfigError(reason: "Not implemented"))
}

fn do_exchange_code(
  _config: Config,
  _code: String,
) -> Result(Credentials, AuthError) {
  Error(error.ConfigError(reason: "Not implemented"))
}

fn do_fetch_user(
  _credentials: Credentials,
) -> Result(#(String, UserInfo), AuthError) {
  Error(error.ConfigError(reason: "Not implemented"))
}
