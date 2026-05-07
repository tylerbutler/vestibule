import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/http/request
import gleam/option.{type Option}
import gleam/string
import gleam/uri

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/user_info.{type UserInfo}

/// Normalized user details returned by a strategy.
pub type UserResult {
  UserResult(uid: String, info: UserInfo, extra: Dict(String, Dynamic))
}

/// The result of exchanging an authorization code.
///
/// `credentials` contains the standard OAuth credentials. `artifacts` contains
/// provider-specific token response data that may be needed while resolving the
/// user, such as an OpenID Connect `id_token`.
pub type ExchangeResult {
  ExchangeResult(credentials: Credentials, artifacts: Dict(String, Dynamic))
}

/// Build an exchange result for providers with no provider-specific artifacts.
pub fn exchange_result(credentials: Credentials) -> ExchangeResult {
  ExchangeResult(credentials: credentials, artifacts: dict.new())
}

/// Build an exchange result with provider-specific artifacts.
pub fn exchange_result_with_artifacts(
  credentials: Credentials,
  artifacts: Dict(String, Dynamic),
) -> ExchangeResult {
  ExchangeResult(credentials: credentials, artifacts: artifacts)
}

/// A strategy is a record containing the functions needed
/// to authenticate with a specific provider.
///
/// The type parameter `e` corresponds to the custom error type
/// in `AuthError(e)`. Built-in strategies are polymorphic in `e`.
pub type Strategy(e) {
  Strategy(
    /// Human-readable provider name (e.g., "github", "google").
    provider: String,
    /// Default scopes for this provider.
    default_scopes: List(String),
    /// Build the authorization URL to redirect the user to.
    /// Parameters: config, scopes, state.
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError(e)),
    /// Exchange an authorization code for credentials and provider-specific artifacts.
    /// The third parameter is an optional PKCE code verifier.
    exchange_code: fn(Config, String, Option(String)) ->
      Result(ExchangeResult, AuthError(e)),
    /// Refresh credentials using a provider-specific refresh token request.
    refresh_token: fn(Config, String) -> Result(Credentials, AuthError(e)),
    /// Fetch user info using the obtained exchange result.
    fetch_user: fn(Config, ExchangeResult) -> Result(UserResult, AuthError(e)),
  )
}

/// Build the Authorization header value from credentials.
///
/// Uses the `token_type` from the credentials (e.g., "Bearer", "bearer").
/// Strategy implementations should use this instead of hardcoding `"Bearer "`.
///
/// Returns `Error` if the token type is not "bearer" (case-insensitive),
/// as vestibule only supports Bearer token authentication.
pub fn authorization_header(
  credentials: Credentials,
) -> Result(String, AuthError(e)) {
  case string.lowercase(credentials.token_type) {
    "bearer" -> Ok("Bearer " <> credentials.token)
    other ->
      Error(error.ConfigError(
        reason: "Unsupported token type: "
        <> other
        <> ". Only Bearer tokens are supported.",
      ))
  }
}

/// Append a PKCE code_verifier to a form-encoded request body when present.
///
/// Strategy implementations should call this after building the token
/// exchange request to include the PKCE verifier parameter.
pub fn append_code_verifier(
  req: request.Request(String),
  code_verifier: Option(String),
) -> request.Request(String) {
  case code_verifier {
    option.Some(verifier) -> {
      let verifier_param = uri.query_to_string([#("code_verifier", verifier)])
      let body = case req.body {
        "" -> verifier_param
        existing -> existing <> "&" <> verifier_param
      }
      request.set_body(req, body)
    }
    option.None -> req
  }
}
