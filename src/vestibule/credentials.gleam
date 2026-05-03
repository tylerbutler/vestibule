import gleam/option.{type Option}

/// OAuth credentials from the provider.
///
/// **Security warning:** This type contains sensitive tokens. Avoid logging
/// or debugging `Credentials` values — `io.debug()` will print the access
/// token and refresh token in plain text. Store tokens securely and treat
/// them as secrets.
pub type Credentials {
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
