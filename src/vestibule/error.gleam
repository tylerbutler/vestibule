//// Authentication error types.
////
//// `AuthError(e)` is an **opaque** error value. Instead of pattern matching on
//// public variants, classify and inspect errors through the accessor functions
//// in this module:
////
//// - [`kind`](#kind) returns an [`ErrorKind`](#ErrorKind) classifier. It carries
////   an `OtherKind` catch-all so future error kinds can be added without breaking
////   exhaustive `case` expressions in consuming code.
//// - [`phase`](#phase) returns the coarse [`Phase`](#Phase) the error occurred in.
//// - [`message`](#message) returns a human-readable summary, safe to log.
//// - [`provider_error`](#provider_error) returns structured provider error data
////   (code / description / uri) when the provider returned a standard OAuth error.
//// - [`http_status`](#http_status) and [`missing_param`](#missing_param) expose
////   the few additional structured fields some errors carry.
//// - [`custom_payload`](#custom_payload) returns the provider-defined payload
////   for custom errors.
////
//// Construct errors with the constructor functions ([`config`](#config),
//// [`network`](#network), [`provider`](#provider), and friends). The type
//// parameter `e` lets third-party providers attach custom error payloads via
//// [`custom`](#custom); built-in strategies stay polymorphic in `e`.

import gleam/int
import gleam/option.{type Option, None, Some}

/// An opaque authentication error.
///
/// Inspect values of this type with [`kind`](#kind), [`phase`](#phase),
/// [`message`](#message), [`provider_error`](#provider_error),
/// [`http_status`](#http_status), [`missing_param`](#missing_param), and
/// [`custom_payload`](#custom_payload).
pub opaque type AuthError(e) {
  StateMismatch
  InvalidNonce
  MissingCallbackParam(name: String)
  CodeExchange(reason: String)
  UserInfo(reason: String)
  ProviderReturnedError(error: ProviderError)
  HttpError(status: Int, summary: String)
  DecodeError(context: String, reason: String)
  NetworkError(reason: String)
  ConfigError(reason: String)
  RefreshUnsupported
  CustomError(payload: e)
}

/// A coarse classification of where in the OAuth flow an error occurred.
pub type Phase {
  /// Validating or parsing the OAuth callback request.
  CallbackPhase
  /// Exchanging the authorization code for tokens.
  TokenExchangePhase
  /// Fetching user info from the provider.
  UserInfoPhase
  /// Reading or validating configuration.
  ConfigPhase
  /// The provider returned an explicit error response.
  ProviderPhase
  /// Network / HTTP transport.
  TransportPhase
  /// Refreshing an access token.
  RefreshPhase
}

/// A stable, machine-readable error classifier.
///
/// `OtherKind` is a catch-all: matching on it keeps consumer `case` expressions
/// exhaustive even as new kinds are introduced. Always include an `OtherKind`
/// (or `_`) arm when matching on this type.
pub type ErrorKind {
  /// State parameter mismatch — possible CSRF attack.
  StateMismatchKind
  /// OIDC `nonce` mismatch or missing-but-expected — possible id_token
  /// replay/injection attack.
  InvalidNonceKind
  /// A required OAuth callback parameter was missing.
  MissingCallbackParamKind
  /// Failed to exchange the authorization code for tokens.
  CodeExchangeKind
  /// Failed to fetch user info from the provider.
  UserInfoKind
  /// The provider returned a standard OAuth error response.
  ProviderKind
  /// The provider returned a non-success HTTP response.
  HttpKind
  /// A provider response body could not be decoded.
  DecodeKind
  /// An HTTP request failed at the network level.
  NetworkKind
  /// Invalid configuration.
  ConfigKind
  /// The strategy does not support refreshing access tokens.
  RefreshUnsupportedKind
  /// A provider-specific custom error (see [`custom`](#custom)).
  CustomKind
  /// Catch-all for kinds added in future releases.
  OtherKind
}

/// Structured data from a standard OAuth provider error response.
///
/// This deliberately excludes raw response bodies; only the standard
/// `error`, `error_description`, and `error_uri` fields are exposed.
pub opaque type ProviderError {
  ProviderError(code: String, description: String, uri: Option(String))
}

// --- Constructors ---------------------------------------------------------

/// State parameter mismatch — possible CSRF attack.
pub fn state_mismatch() -> AuthError(e) {
  StateMismatch
}

/// OIDC `nonce` mismatch or missing-but-expected — possible id_token replay.
pub fn invalid_nonce() -> AuthError(e) {
  InvalidNonce
}

/// A required OAuth callback parameter was missing.
pub fn missing_callback_param(name: String) -> AuthError(e) {
  MissingCallbackParam(name)
}

/// Failed to exchange the authorization code for tokens.
pub fn code_exchange(reason reason: String) -> AuthError(e) {
  CodeExchange(reason)
}

/// Failed to fetch user info from the provider.
pub fn user_info(reason reason: String) -> AuthError(e) {
  UserInfo(reason)
}

/// The provider returned a standard OAuth error response.
pub fn provider(
  code code: String,
  description description: String,
  uri uri: Option(String),
) -> AuthError(e) {
  ProviderReturnedError(ProviderError(
    code: code,
    description: description,
    uri: uri,
  ))
}

/// The provider returned a non-success HTTP response.
///
/// `summary` should be a short description of the failure. Helpers such as
/// `provider_support.check_response_status` pass a truncated snippet of the
/// response body here to aid debugging, so the summary may contain provider
/// response content — treat it accordingly before surfacing it to end users.
pub fn http(status status: Int, summary summary: String) -> AuthError(e) {
  HttpError(status, summary)
}

/// A provider response body could not be decoded.
pub fn decode(context context: String, reason reason: String) -> AuthError(e) {
  DecodeError(context, reason)
}

/// An HTTP request failed at the network level.
pub fn network(reason reason: String) -> AuthError(e) {
  NetworkError(reason)
}

/// Invalid configuration.
pub fn config(reason reason: String) -> AuthError(e) {
  ConfigError(reason)
}

/// The strategy does not support refreshing access tokens.
///
/// Returned when `strategy.refresh_token` is called on a strategy that was built
/// without a refresh capability (no `with_refresh`).
pub fn refresh_unsupported() -> AuthError(e) {
  RefreshUnsupported
}

/// A provider-specific custom error carrying a payload of type `e`.
pub fn custom(payload: e) -> AuthError(e) {
  CustomError(payload)
}

// --- Accessors ------------------------------------------------------------

/// The machine-readable [`ErrorKind`](#ErrorKind) classifier for this error.
pub fn kind(auth_error: AuthError(e)) -> ErrorKind {
  case auth_error {
    StateMismatch -> StateMismatchKind
    InvalidNonce -> InvalidNonceKind
    MissingCallbackParam(_) -> MissingCallbackParamKind
    CodeExchange(_) -> CodeExchangeKind
    UserInfo(_) -> UserInfoKind
    ProviderReturnedError(_) -> ProviderKind
    HttpError(_, _) -> HttpKind
    DecodeError(_, _) -> DecodeKind
    NetworkError(_) -> NetworkKind
    ConfigError(_) -> ConfigKind
    RefreshUnsupported -> RefreshUnsupportedKind
    CustomError(_) -> CustomKind
  }
}

/// The coarse [`Phase`](#Phase) this error occurred in.
pub fn phase(auth_error: AuthError(e)) -> Phase {
  case auth_error {
    StateMismatch | InvalidNonce | MissingCallbackParam(_) -> CallbackPhase
    CodeExchange(_) -> TokenExchangePhase
    UserInfo(_) -> UserInfoPhase
    ConfigError(_) -> ConfigPhase
    ProviderReturnedError(_) | CustomError(_) -> ProviderPhase
    HttpError(_, _) | DecodeError(_, _) | NetworkError(_) -> TransportPhase
    RefreshUnsupported -> RefreshPhase
  }
}

/// A human-readable, log-safe summary of this error.
pub fn message(auth_error: AuthError(e)) -> String {
  case auth_error {
    StateMismatch -> "State parameter mismatch — possible CSRF attack"
    InvalidNonce ->
      "OIDC nonce mismatch — possible id_token replay or injection"
    MissingCallbackParam(name) ->
      "Missing required callback parameter: " <> name
    CodeExchange(reason) -> "Failed to exchange authorization code: " <> reason
    UserInfo(reason) -> "Failed to fetch user info: " <> reason
    ProviderReturnedError(ProviderError(
      code: code,
      description: description,
      ..,
    )) -> "Provider returned error: " <> code <> " — " <> description
    HttpError(status, summary) ->
      "HTTP " <> int.to_string(status) <> ": " <> summary
    DecodeError(context, reason) ->
      "Failed to decode " <> context <> ": " <> reason
    NetworkError(reason) -> "Network request failed: " <> reason
    ConfigError(reason) -> "Invalid configuration: " <> reason
    RefreshUnsupported ->
      "This strategy does not support refreshing access tokens"
    CustomError(_) -> "Provider-specific error"
  }
}

/// Structured provider error data, when the provider returned a standard OAuth
/// error response.
pub fn provider_error(auth_error: AuthError(e)) -> Option(ProviderError) {
  case auth_error {
    ProviderReturnedError(provider_error) -> Some(provider_error)
    StateMismatch
    | InvalidNonce
    | MissingCallbackParam(_)
    | CodeExchange(_)
    | UserInfo(_)
    | HttpError(_, _)
    | DecodeError(_, _)
    | NetworkError(_)
    | ConfigError(_)
    | RefreshUnsupported
    | CustomError(_) -> None
  }
}

/// The HTTP status code, for errors that carry one.
pub fn http_status(auth_error: AuthError(e)) -> Option(Int) {
  case auth_error {
    HttpError(status, _) -> Some(status)
    StateMismatch
    | InvalidNonce
    | MissingCallbackParam(_)
    | CodeExchange(_)
    | UserInfo(_)
    | ProviderReturnedError(_)
    | DecodeError(_, _)
    | NetworkError(_)
    | ConfigError(_)
    | RefreshUnsupported
    | CustomError(_) -> None
  }
}

/// The short HTTP error summary, for `HttpKind` errors. May contain a
/// truncated snippet of the provider's response body.
pub fn http_summary(auth_error: AuthError(e)) -> Option(String) {
  case auth_error {
    HttpError(_, summary) -> Some(summary)
    StateMismatch
    | InvalidNonce
    | MissingCallbackParam(_)
    | CodeExchange(_)
    | UserInfo(_)
    | ProviderReturnedError(_)
    | DecodeError(_, _)
    | NetworkError(_)
    | ConfigError(_)
    | RefreshUnsupported
    | CustomError(_) -> None
  }
}

/// The name of the missing callback parameter, for `MissingCallbackParamKind`.
pub fn missing_param(auth_error: AuthError(e)) -> Option(String) {
  case auth_error {
    MissingCallbackParam(name) -> Some(name)
    StateMismatch
    | InvalidNonce
    | CodeExchange(_)
    | UserInfo(_)
    | ProviderReturnedError(_)
    | HttpError(_, _)
    | DecodeError(_, _)
    | NetworkError(_)
    | ConfigError(_)
    | RefreshUnsupported
    | CustomError(_) -> None
  }
}

/// The provider-defined custom payload, for `CustomKind` errors.
pub fn custom_payload(auth_error: AuthError(e)) -> Option(e) {
  case auth_error {
    CustomError(payload) -> Some(payload)
    StateMismatch
    | InvalidNonce
    | MissingCallbackParam(_)
    | CodeExchange(_)
    | UserInfo(_)
    | ProviderReturnedError(_)
    | HttpError(_, _)
    | DecodeError(_, _)
    | NetworkError(_)
    | ConfigError(_)
    | RefreshUnsupported -> None
  }
}

// --- ProviderError accessors ----------------------------------------------

/// The standard OAuth `error` code.
pub fn provider_code(provider_error: ProviderError) -> String {
  provider_error.code
}

/// The standard OAuth `error_description`.
pub fn provider_description(provider_error: ProviderError) -> String {
  provider_error.description
}

/// The standard OAuth `error_uri`, when present.
pub fn provider_uri(provider_error: ProviderError) -> Option(String) {
  provider_error.uri
}
