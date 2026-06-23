//// Authentication error types.
////
//// The type parameter `e` allows third-party providers to define custom
//// error variants via the `Custom(e)` constructor. Built-in strategies
//// that only use standard variants are polymorphic in `e`.

import gleam/option

pub type AuthError(e) {
  /// State parameter mismatch — possible CSRF attack.
  StateMismatch
  /// OIDC `nonce` mismatch or missing-but-expected — possible id_token
  /// replay/injection attack.
  InvalidNonce
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
  /// The strategy does not support refreshing access tokens.
  ///
  /// Returned when `strategy.refresh_token` is called on a strategy that was
  /// built without a refresh capability (no `with_refresh`).
  RefreshUnsupported
  /// Provider-specific custom error.
  Custom(e)
}
