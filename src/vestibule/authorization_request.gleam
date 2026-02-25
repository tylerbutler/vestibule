/// Represents the result of generating an authorization URL.
///
/// Contains all values needed for the OAuth2 authorization phase,
/// including PKCE parameters that must be stored for the callback phase.
pub type AuthorizationRequest {
  AuthorizationRequest(
    /// The authorization URL to redirect the user to.
    url: String,
    /// The CSRF state parameter (must be stored for validation).
    state: String,
    /// The PKCE code verifier (must be stored for token exchange).
    code_verifier: String,
  )
}
