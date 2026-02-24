/// Authentication error types.
pub type AuthError {
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
}
