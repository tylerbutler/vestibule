/// Vestibule — a strategy-based authentication library for Gleam.
///
/// Provides a consistent interface across OAuth2 identity providers
/// using a two-phase flow: redirect to provider, then handle callback.
/// All flows use PKCE (Proof Key for Code Exchange) for enhanced security.
import gleam/dict.{type Dict}
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

import vestibule/auth.{type Auth, Auth}
import vestibule/authorization_request.{
  type AuthorizationRequest, AuthorizationRequest,
}
import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/pkce
import vestibule/state
import vestibule/strategy.{type Strategy}

/// Phase 1: Generate the authorization URL to redirect the user to.
///
/// Returns an `AuthorizationRequest` containing the URL, CSRF state,
/// and PKCE code verifier. The caller must store both the state and
/// code_verifier in their session for use during the callback phase.
///
/// PKCE parameters (`code_challenge` and `code_challenge_method=S256`)
/// are automatically appended to the authorization URL.
///
/// **State expiration:** This library generates the state token but does
/// not enforce expiration. If you need time-based expiration, store a
/// timestamp alongside the state when saving it to your session and
/// check it before calling `handle_callback`.
pub fn authorize_url(
  strategy: Strategy(e),
  cfg: Config,
) -> Result(AuthorizationRequest, AuthError(e)) {
  let csrf_state = state.generate()
  let code_verifier = pkce.generate_verifier()
  let code_challenge = pkce.compute_challenge(code_verifier)
  let scopes = case config.scopes(cfg) {
    [] -> strategy.default_scopes
    custom -> custom
  }
  use base_url <- result.try(strategy.authorize_url(cfg, scopes, csrf_state))
  let url = append_pkce_params(base_url, code_challenge)
  Ok(AuthorizationRequest(
    url: url,
    state: csrf_state,
    code_verifier: code_verifier,
  ))
}

/// Phase 2: Handle the OAuth callback from the provider.
///
/// Validates the state parameter, exchanges the authorization code
/// for credentials (including the PKCE code verifier), and fetches
/// normalized user information.
///
/// **Caller responsibilities:** This function checks that the callback
/// state matches `expected_state`, but does not enforce single-use or
/// expiration. Callers should delete the stored state after a successful
/// call to prevent replay attacks. The wisp middleware's `uset.take`
/// provides one-time-use semantics automatically. For time-based
/// expiration, check the timestamp you stored alongside the state
/// before calling this function.
pub fn handle_callback(
  strategy: Strategy(e),
  cfg: Config,
  callback_params: Dict(String, String),
  expected_state: String,
  code_verifier: String,
) -> Result(Auth, AuthError(e)) {
  // Extract state (needed for CSRF validation)
  use received_state <- result.try(
    dict.get(callback_params, "state")
    |> result.replace_error(error.MissingCallbackParam("state")),
  )

  // Validate state before surfacing any provider response details.
  use _ <- result.try(state.validate(received_state, expected_state))

  // Check for provider errors before requiring code
  use _ <- result.try(check_provider_error(callback_params))

  // Extract authorization code
  use code <- result.try(
    dict.get(callback_params, "code")
    |> result.replace_error(error.MissingCallbackParam("code")),
  )

  // Exchange code for credentials, passing the PKCE verifier
  use credentials <- result.try(strategy.exchange_code(
    cfg,
    code,
    option.Some(code_verifier),
  ))

  // Fetch user info
  use user <- result.try(strategy.fetch_user(cfg, credentials))

  // Assemble the Auth result
  Ok(Auth(
    uid: user.uid,
    provider: strategy.provider,
    info: user.info,
    credentials: credentials,
    extra: user.extra,
  ))
}

/// Refresh an access token using a refresh token.
///
/// Delegates to the provider strategy so refresh semantics remain provider-owned.
pub fn refresh_token(
  strategy: Strategy(e),
  cfg: Config,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  strategy.refresh_token(cfg, refresh_tok)
}

/// Check callback params for a provider error response.
fn check_provider_error(
  params: Dict(String, String),
) -> Result(Nil, AuthError(e)) {
  case dict.get(params, "error") {
    Ok(error_code) -> {
      let description =
        dict.get(params, "error_description")
        |> result.unwrap("")
      let uri = dict.get(params, "error_uri") |> option.from_result()
      Error(error.ProviderError(
        code: error_code,
        description: description,
        uri: uri,
      ))
    }
    Error(Nil) -> Ok(Nil)
  }
}

/// Append PKCE code_challenge and code_challenge_method to an authorization URL.
fn append_pkce_params(url: String, code_challenge: String) -> String {
  let pkce_query =
    uri.query_to_string([
      #("code_challenge", code_challenge),
      #("code_challenge_method", "S256"),
    ])

  case uri.parse(url) {
    Ok(parsed) -> {
      let query = case parsed.query {
        option.Some(existing) -> existing <> "&" <> pkce_query
        option.None -> pkce_query
      }
      uri.to_string(uri.Uri(..parsed, query: option.Some(query)))
    }
    Error(_) -> append_pkce_params_raw(url, pkce_query)
  }
}

fn append_pkce_params_raw(url: String, pkce_query: String) -> String {
  let separator = case string.contains(url, "?") {
    True -> "&"
    False -> "?"
  }
  url <> separator <> pkce_query
}
