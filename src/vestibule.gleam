/// Vestibule — a strategy-based authentication library for Gleam.
///
/// Provides a consistent interface across OAuth2 identity providers
/// using a two-phase flow: redirect to provider, then handle callback.
/// All flows use PKCE (Proof Key for Code Exchange) for enhanced security.
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/option.{None}
import gleam/result
import gleam/string
import gleam/uri

import vestibule/auth.{type Auth, Auth}
import vestibule/authorization_request.{
  type AuthorizationRequest, AuthorizationRequest,
}
import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/pkce
import vestibule/state
import vestibule/strategy.{type Strategy}

/// Phase 1: Generate the authorization URL to redirect the user to.
///
/// Returns an `AuthorizationRequest` containing the URL, CSRF state,
/// and PKCE code verifier. The caller must store both the state and
/// code_verifier in their session for use during the callback phase.
///
/// PKCE parameters (`code_challenge` and `code_challenge_method=S256`)
/// are automatically appended to the authorization URL.
pub fn authorize_url(
  strategy: Strategy(e),
  config: Config,
) -> Result(AuthorizationRequest, AuthError(e)) {
  let csrf_state = state.generate()
  let code_verifier = pkce.generate_verifier()
  let code_challenge = pkce.compute_challenge(code_verifier)
  let scopes = case config.scopes {
    [] -> strategy.default_scopes
    custom -> custom
  }
  use base_url <- result.try(strategy.authorize_url(config, scopes, csrf_state))
  let url = append_pkce_params(base_url, code_challenge)
  Ok(AuthorizationRequest(
    url: url,
    state: csrf_state,
    code_verifier: code_verifier,
  ))
}

/// Phase 2: Handle the OAuth callback from the provider.
///
/// Validates the state parameter, exchanges the authorization code
/// for credentials (including the PKCE code verifier), and fetches
/// normalized user information.
pub fn handle_callback(
  strategy: Strategy(e),
  config: Config,
  callback_params: Dict(String, String),
  expected_state: String,
  code_verifier: String,
) -> Result(Auth, AuthError(e)) {
  // Extract required parameters
  use received_state <- result.try(
    dict.get(callback_params, "state")
    |> result.replace_error(error.ConfigError(
      reason: "Missing state parameter in callback",
    )),
  )
  use code <- result.try(
    dict.get(callback_params, "code")
    |> result.replace_error(error.ConfigError(
      reason: "Missing code parameter in callback",
    )),
  )

  // Check for provider errors
  use _ <- result.try(case dict.get(callback_params, "error") {
    Ok(error_code) -> {
      let description =
        dict.get(callback_params, "error_description")
        |> result.unwrap("")
      Error(error.ProviderError(code: error_code, description: description))
    }
    Error(Nil) -> Ok(Nil)
  })

  // Validate state
  use _ <- result.try(state.validate(received_state, expected_state))

  // Exchange code for credentials, passing the PKCE verifier
  use credentials <- result.try(strategy.exchange_code(
    config,
    code,
    option.Some(code_verifier),
  ))

  // Fetch user info
  use #(uid, info) <- result.try(strategy.fetch_user(credentials))

  // Assemble the Auth result
  Ok(Auth(
    uid: uid,
    provider: strategy.provider,
    info: info,
    credentials: credentials,
    extra: dict.new(),
  ))
}

/// Refresh an access token using a refresh token.
///
/// Sends a POST request to the strategy's token endpoint with the
/// `refresh_token` grant type. Returns new credentials on success.
pub fn refresh_token(
  strategy: Strategy(e),
  config: Config,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  let body =
    "grant_type=refresh_token"
    <> "&refresh_token="
    <> refresh_tok
    <> "&client_id="
    <> config.client_id
    <> "&client_secret="
    <> config.client_secret

  let req_result =
    request.to(strategy.token_url)
    |> result.replace_error(error.ConfigError(
      reason: "Invalid token URL: " <> strategy.token_url,
    ))

  use req <- result.try(req_result)

  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_header("accept", "application/json")
    |> request.set_body(body)

  case httpc.send(req) {
    Ok(response) -> parse_refresh_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to token endpoint: " <> strategy.token_url,
      ))
  }
}

/// Parse a token refresh response JSON into Credentials.
///
/// Handles both success responses and error responses from the provider.
/// Exported for testing.
pub fn parse_refresh_response(body: String) -> Result(Credentials, AuthError(e)) {
  // Check for error response first
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.field("error_description", decode.string)
    decode.success(#(error_code, description))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description)) ->
      Error(error.ProviderError(code: code, description: description))
    _ -> parse_refresh_success(body)
  }
}

fn parse_refresh_success(body: String) -> Result(Credentials, AuthError(e)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use refresh_token_val <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    use expires_in <- decode.optional_field(
      "expires_in",
      None,
      decode.optional(decode.int),
    )
    use scope <- decode.optional_field(
      "scope",
      None,
      decode.optional(decode.string),
    )
    let scopes = case scope {
      option.Some(s) -> string.split(s, " ")
      None -> []
    }
    decode.success(Credentials(
      token: access_token,
      refresh_token: refresh_token_val,
      token_type: token_type,
      expires_at: expires_in,
      scopes: scopes,
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse token refresh response",
      ))
  }
}

/// Append PKCE code_challenge and code_challenge_method to an authorization URL.
fn append_pkce_params(url: String, code_challenge: String) -> String {
  let separator = case string.contains(url, "?") {
    True -> "&"
    False -> "?"
  }
  url
  <> separator
  <> "code_challenge="
  <> uri.percent_encode(code_challenge)
  <> "&code_challenge_method=S256"
}
