/// Authentication error types.
///
/// The type parameter `e` allows third-party providers to define custom
/// error variants via the `Custom(e)` constructor. Built-in strategies
/// that only use standard variants are polymorphic in `e`.
import gleam/option

pub type AuthError(e) {
  /// State parameter mismatch — possible CSRF attack.
  StateMismatch
  /// Required OAuth callback parameter was missing.
  MissingCallbackParam(name: String)
  /// Failed to exchange authorization code for tokens.
  CodeExchangeFailed(reason: String)
  /// Failed to fetch user info from provider.
  UserInfoFailed(reason: String)
  /// Provider returned an error response.
  ProviderError(code: String, description: String, uri: option.Option(String))
  /// Provider returned a non-success HTTP response.
  HttpError(status: Int, body: String)
  /// Provider response body could not be decoded.
  DecodeError(context: String, reason: String)
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
    MissingCallbackParam(name:) -> MissingCallbackParam(name:)
    CodeExchangeFailed(reason:) -> CodeExchangeFailed(reason:)
    UserInfoFailed(reason:) -> UserInfoFailed(reason:)
    ProviderError(code:, description:, uri:) ->
      ProviderError(code:, description:, uri:)
    HttpError(status:, body:) -> HttpError(status:, body:)
    DecodeError(context:, reason:) -> DecodeError(context:, reason:)
    NetworkError(reason:) -> NetworkError(reason:)
    ConfigError(reason:) -> ConfigError(reason:)
    Custom(e) -> Custom(f(e))
  }
}
