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
    ConfigError(reason:) -> ConfigError(reason:)
    Custom(e) -> Custom(f(e))
  }
}
