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
  AuthError(
    kind: ErrorKind,
    phase: Phase,
    message: String,
    provider_error: Option(ProviderError),
    http_status: Option(Int),
    http_summary: Option(String),
    missing_param: Option(String),
    custom: Option(e),
  )
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
  base(
    StateMismatchKind,
    CallbackPhase,
    "State parameter mismatch — possible CSRF attack",
  )
}

/// OIDC `nonce` mismatch or missing-but-expected — possible id_token replay.
pub fn invalid_nonce() -> AuthError(e) {
  base(
    InvalidNonceKind,
    CallbackPhase,
    "OIDC nonce mismatch — possible id_token replay or injection",
  )
}

/// A required OAuth callback parameter was missing.
pub fn missing_callback_param(name: String) -> AuthError(e) {
  AuthError(
    ..base(
      MissingCallbackParamKind,
      CallbackPhase,
      "Missing required callback parameter: " <> name,
    ),
    missing_param: Some(name),
  )
}

/// Failed to exchange the authorization code for tokens.
pub fn code_exchange(reason reason: String) -> AuthError(e) {
  base(
    CodeExchangeKind,
    TokenExchangePhase,
    "Failed to exchange authorization code: " <> reason,
  )
}

/// Failed to fetch user info from the provider.
pub fn user_info(reason reason: String) -> AuthError(e) {
  base(UserInfoKind, UserInfoPhase, "Failed to fetch user info: " <> reason)
}

/// The provider returned a standard OAuth error response.
pub fn provider(
  code code: String,
  description description: String,
  uri uri: Option(String),
) -> AuthError(e) {
  AuthError(
    ..base(
      ProviderKind,
      ProviderPhase,
      "Provider returned error: " <> code <> " — " <> description,
    ),
    provider_error: Some(ProviderError(
      code: code,
      description: description,
      uri: uri,
    )),
  )
}

/// The provider returned a non-success HTTP response.
///
/// `summary` should be a short description of the failure. Helpers such as
/// `provider_support.check_response_status` pass a truncated snippet of the
/// response body here to aid debugging, so the summary may contain provider
/// response content — treat it accordingly before surfacing it to end users.
pub fn http(status status: Int, summary summary: String) -> AuthError(e) {
  AuthError(
    ..base(
      HttpKind,
      TransportPhase,
      "HTTP " <> int.to_string(status) <> ": " <> summary,
    ),
    http_status: Some(status),
    http_summary: Some(summary),
  )
}

/// A provider response body could not be decoded.
pub fn decode(context context: String, reason reason: String) -> AuthError(e) {
  base(
    DecodeKind,
    TransportPhase,
    "Failed to decode " <> context <> ": " <> reason,
  )
}

/// An HTTP request failed at the network level.
pub fn network(reason reason: String) -> AuthError(e) {
  base(NetworkKind, TransportPhase, "Network request failed: " <> reason)
}

/// Invalid configuration.
pub fn config(reason reason: String) -> AuthError(e) {
  base(ConfigKind, ConfigPhase, "Invalid configuration: " <> reason)
}

/// The strategy does not support refreshing access tokens.
///
/// Returned when `strategy.refresh_token` is called on a strategy that was built
/// without a refresh capability (no `with_refresh`).
pub fn refresh_unsupported() -> AuthError(e) {
  base(
    RefreshUnsupportedKind,
    RefreshPhase,
    "This strategy does not support refreshing access tokens",
  )
}

/// A provider-specific custom error carrying a payload of type `e`.
pub fn custom(payload: e) -> AuthError(e) {
  AuthError(
    ..base(CustomKind, ProviderPhase, "Provider-specific error"),
    custom: Some(payload),
  )
}

// --- Accessors ------------------------------------------------------------

/// The machine-readable [`ErrorKind`](#ErrorKind) classifier for this error.
pub fn kind(err: AuthError(e)) -> ErrorKind {
  err.kind
}

/// The coarse [`Phase`](#Phase) this error occurred in.
pub fn phase(err: AuthError(e)) -> Phase {
  err.phase
}

/// A human-readable, log-safe summary of this error.
pub fn message(err: AuthError(e)) -> String {
  err.message
}

/// Structured provider error data, when the provider returned a standard OAuth
/// error response.
pub fn provider_error(err: AuthError(e)) -> Option(ProviderError) {
  err.provider_error
}

/// The HTTP status code, for errors that carry one.
pub fn http_status(err: AuthError(e)) -> Option(Int) {
  err.http_status
}

/// The short HTTP error summary, for `HttpKind` errors. May contain a
/// truncated snippet of the provider's response body.
pub fn http_summary(err: AuthError(e)) -> Option(String) {
  err.http_summary
}

/// The name of the missing callback parameter, for `MissingCallbackParamKind`.
pub fn missing_param(err: AuthError(e)) -> Option(String) {
  err.missing_param
}

/// The provider-defined custom payload, for `CustomKind` errors.
pub fn custom_payload(err: AuthError(e)) -> Option(e) {
  err.custom
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

// --- Internal helpers -----------------------------------------------------

fn base(kind: ErrorKind, phase: Phase, message: String) -> AuthError(e) {
  AuthError(
    kind: kind,
    phase: phase,
    message: message,
    provider_error: None,
    http_status: None,
    http_summary: None,
    missing_param: None,
    custom: None,
  )
}
