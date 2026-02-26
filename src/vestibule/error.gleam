/// Authentication error types.
///
/// The type parameter `e` allows third-party providers to define custom
/// error variants via the `Custom(e)` constructor. Built-in strategies
/// that only use standard variants are polymorphic in `e`.
pub type AuthError(e) {
  /// State parameter mismatch — possible CSRF attack.
  StateMismatch
  /// Failed to exchange authorization code for tokens.
  CodeExchangeFailed(reason: String)
  /// Failed to fetch user info from provider.
  UserInfoFailed(reason: String)
  /// Provider returned an error response.
  ProviderError(code: String, description: String)
  /// HTTP request failed.
  NetworkError(reason: String)
  /// HTTP response had a non-2xx status code.
  HttpError(status: Int, body: String)
  /// Invalid configuration.
  ConfigError(reason: String)
  /// Provider-specific custom error.
  Custom(e)
}

/// Map the custom error type, leaving standard variants unchanged.
pub fn map_custom(error: AuthError(a), f: fn(a) -> b) -> AuthError(b) {
  case error {
    StateMismatch -> StateMismatch
    CodeExchangeFailed(reason:) -> CodeExchangeFailed(reason:)
    UserInfoFailed(reason:) -> UserInfoFailed(reason:)
    ProviderError(code:, description:) -> ProviderError(code:, description:)
    NetworkError(reason:) -> NetworkError(reason:)
    HttpError(status:, body:) -> HttpError(status:, body:)
    ConfigError(reason:) -> ConfigError(reason:)
    Custom(e) -> Custom(f(e))
  }
}

/// Check that an HTTP response has a 2xx status code.
///
/// Returns Ok(body) if the status is in the 200-299 range,
/// or Error(HttpError) with the status code and body otherwise.
pub fn check_http_status(
  status: Int,
  body: String,
) -> Result(String, AuthError(e)) {
  case status >= 200 && status <= 299 {
    True -> Ok(body)
    False -> Error(HttpError(status: status, body: body))
  }
}
