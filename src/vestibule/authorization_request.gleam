//// An opaque value carrying everything the middleware needs to start an
//// authorization flow: the URL to redirect the browser to, the CSRF
//// `state`, the PKCE `code_verifier`, and an optional OIDC `nonce`, all of
//// which must be stored for the callback.

import gleam/option.{type Option}
import vestibule/internal/secret.{type Secret}

/// Represents the result of generating an authorization URL.
///
/// Contains all values needed for the OAuth2 authorization phase,
/// including PKCE parameters that must be stored for the callback phase.
///
/// Opaque so that new artifacts can be added without breaking consumers.
/// Construct with `new` and read fields via the `url`, `state`,
/// `code_verifier`, and `nonce` accessors.
pub opaque type AuthorizationRequest {
  AuthorizationRequest(
    url: Secret,
    state: Secret,
    code_verifier: Secret,
    nonce: Option(Secret),
  )
}

/// Build an `AuthorizationRequest`.
///
/// `nonce` is `Some` for OIDC strategies that emit an id_token `nonce`, and
/// `None` for plain OAuth2 strategies.
pub fn new(
  url url: String,
  state state: String,
  code_verifier code_verifier: String,
  nonce nonce: Option(String),
) -> AuthorizationRequest {
  AuthorizationRequest(
    url: secret.from_string(url),
    state: secret.from_string(state),
    code_verifier: secret.from_string(code_verifier),
    nonce: option.map(nonce, secret.from_string),
  )
}

/// The authorization URL to redirect the user to.
pub fn url(authorization_request: AuthorizationRequest) -> String {
  secret.expose(authorization_request.url)
}

/// The CSRF state parameter (must be stored for validation).
///
/// Store a timestamp alongside it if you need time-based expiration.
pub fn state(authorization_request: AuthorizationRequest) -> String {
  secret.expose(authorization_request.state)
}

/// The PKCE code verifier (must be stored for token exchange).
pub fn code_verifier(authorization_request: AuthorizationRequest) -> String {
  secret.expose(authorization_request.code_verifier)
}

/// The OIDC `nonce` (must be stored for id_token validation).
///
/// `Some` for OIDC strategies, `None` for plain OAuth2 strategies.
pub fn nonce(authorization_request: AuthorizationRequest) -> Option(String) {
  option.map(authorization_request.nonce, secret.expose)
}
