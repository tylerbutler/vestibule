//// Bearer credentials returned by a provider after a successful token
//// exchange or refresh.
////
//// > **Security**: `Credentials` values contain access/refresh/id tokens.
//// > Treat them like passwords — never log them, never include them in
//// > error reports, and store them encrypted at rest.

import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/string

/// OAuth credentials from the provider.
///
/// Opaque so raw access and refresh tokens are not exposed through pattern
/// matching or casual field access. Use `new` to construct credentials in
/// strategies and accessors to read fields when needed.
pub opaque type Credentials {
  Credentials(
    token: String,
    refresh_token: Option(String),
    token_type: String,
    /// Seconds until the access token expires, as returned by the provider's
    /// `expires_in` field. This is not an absolute timestamp.
    expires_in: Option(Int),
    scopes: List(String),
  )
}

/// Construct OAuth credentials from a provider token response.
pub fn new(
  token token: String,
  refresh_token refresh_token: Option(String),
  token_type token_type: String,
  expires_in expires_in: Option(Int),
  scopes scopes: List(String),
) -> Credentials {
  Credentials(
    token: token,
    refresh_token: refresh_token,
    token_type: token_type,
    expires_in: expires_in,
    scopes: scopes,
  )
}

/// Return the access token.
pub fn token(credentials: Credentials) -> String {
  credentials.token
}

/// Return the refresh token, when the provider supplied one.
pub fn refresh_token(credentials: Credentials) -> Option(String) {
  credentials.refresh_token
}

/// Return the token type, usually `Bearer`.
pub fn token_type(credentials: Credentials) -> String {
  credentials.token_type
}

/// Return the provider-reported lifetime in seconds.
pub fn expires_in(credentials: Credentials) -> Option(Int) {
  credentials.expires_in
}

/// Return the scopes granted by the provider.
pub fn scopes(credentials: Credentials) -> List(String) {
  credentials.scopes
}

/// Return a human-readable representation that never includes token values.
pub fn redacted(credentials: Credentials) -> String {
  let refresh = case credentials.refresh_token {
    Some(_) -> "present"
    None -> "absent"
  }
  let expires = case credentials.expires_in {
    Some(seconds) -> int.to_string(seconds)
    None -> "unknown"
  }
  "Credentials(token: [REDACTED], refresh_token: "
  <> refresh
  <> ", token_type: "
  <> credentials.token_type
  <> ", expires_in: "
  <> expires
  <> ", scopes: ["
  <> string.join(credentials.scopes, ", ")
  <> "])"
}
