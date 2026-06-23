//// An opaque value carrying everything the middleware needs to start an
//// authorization flow: the URL to redirect the browser to, the CSRF
//// `state`, the PKCE `code_verifier`, and an optional OIDC `nonce`, all of
//// which must be stored for the callback.

import gleam/option.{type Option}

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
    url: String,
    state: String,
    code_verifier: String,
    nonce: Option(String),
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
    url: url,
    state: state,
    code_verifier: code_verifier,
    nonce: nonce,
  )
}

/// The authorization URL to redirect the user to.
pub fn url(req: AuthorizationRequest) -> String {
  req.url
}

/// The CSRF state parameter (must be stored for validation).
///
/// Store a timestamp alongside it if you need time-based expiration.
pub fn state(req: AuthorizationRequest) -> String {
  req.state
}

/// The PKCE code verifier (must be stored for token exchange).
pub fn code_verifier(req: AuthorizationRequest) -> String {
  req.code_verifier
}

/// The OIDC `nonce` (must be stored for id_token validation).
///
/// `Some` for OIDC strategies, `None` for plain OAuth2 strategies.
pub fn nonce(req: AuthorizationRequest) -> Option(String) {
  req.nonce
}
