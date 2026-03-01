import gleam/http/request
import gleam/option.{type Option}
import gleam/string
import gleam/uri

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/user_info.{type UserInfo}

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
    /// The provider's token endpoint URL, used for code exchange and token refresh.
    token_url: String,
    /// Build the authorization URL to redirect the user to.
    /// Parameters: config, scopes, state.
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError(e)),
    /// Exchange an authorization code for credentials.
    /// The third parameter is an optional PKCE code verifier.
    exchange_code: fn(Config, String, Option(String)) ->
      Result(Credentials, AuthError(e)),
    /// Fetch user info using the obtained credentials.
    /// Returns #(uid, user_info).
    fetch_user: fn(Credentials) -> Result(#(String, UserInfo), AuthError(e)),
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
      let body = case req.body {
        "" -> "code_verifier=" <> uri.percent_encode(verifier)
        existing ->
          existing <> "&code_verifier=" <> uri.percent_encode(verifier)
      }
      request.set_body(req, body)
    }
    option.None -> req
  }
}
