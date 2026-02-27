import gleam/dict
import gleam/result
import gleam/string
import wisp.{type Request, type Response}

import vestibule
import vestibule/auth.{type Auth}
import vestibule/error
import vestibule/registry.{type Registry}
import vestibule_wisp/state_store.{type StateStore}

/// Phase 1: Redirect user to the OAuth provider.
///
/// Looks up the provider in the registry, generates an authorization URL
/// with PKCE parameters, stores the CSRF state and code verifier in the
/// state store, sets a signed session cookie, and returns a redirect response.
///
/// Returns 404 if the provider is not registered.
pub fn request_phase(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
) -> Response {
  case registry.get(reg, provider) {
    Error(Nil) -> wisp.not_found()
    Ok(#(strategy, config)) ->
      case vestibule.authorize_url(strategy, config) {
        Ok(auth_request) -> {
          let session_id =
            state_store.store(
              state_store,
              auth_request.state,
              auth_request.code_verifier,
            )
          wisp.redirect(auth_request.url)
          |> wisp.set_cookie(
            req,
            "vestibule_session",
            session_id,
            wisp.Signed,
            600,
          )
        }
        Error(err) -> error_response(err)
      }
  }
}

/// Phase 2: Handle the OAuth callback and return the Auth result
/// to the provided callback function.
///
/// On success, calls `on_success` with the Auth result.
/// On error, returns an HTML error page.
/// Returns 404 if the provider is not registered.
pub fn callback_phase(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
  on_success: fn(Auth) -> Response,
) -> Response {
  case do_callback(req, reg, provider, state_store) {
    Ok(auth) -> on_success(auth)
    Error(response) -> response
  }
}

/// Phase 2 (Result variant): Handle the OAuth callback and return
/// either the Auth result or an error Response.
///
/// Use this instead of `callback_phase` when you want to handle
/// errors yourself rather than using the default error pages.
pub fn callback_phase_result(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
) -> Result(Auth, Response) {
  do_callback(req, reg, provider, state_store)
}

fn do_callback(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
) -> Result(Auth, Response) {
  use #(strategy, config) <- result.try(
    registry.get(reg, provider)
    |> result.map_error(fn(_) { wisp.not_found() }),
  )

  use session_id <- result.try(
    wisp.get_cookie(req, "vestibule_session", wisp.Signed)
    |> result.map_error(fn(_) {
      error_response(error.ConfigError(reason: "Missing session cookie"))
    }),
  )

  use #(expected_state, code_verifier) <- result.try(
    state_store.retrieve(state_store, session_id)
    |> result.map_error(fn(_) {
      error_response(error.ConfigError(
        reason: "Session expired or already used",
      ))
    }),
  )

  let params =
    wisp.get_query(req)
    |> dict.from_list()

  vestibule.handle_callback(
    strategy,
    config,
    params,
    expected_state,
    code_verifier,
  )
  |> result.map_error(error_response)
}

fn error_response(err: error.AuthError(e)) -> Response {
  let message = case err {
    error.StateMismatch -> "State mismatch — possible CSRF attack"
    error.CodeExchangeFailed(reason:) -> "Code exchange failed: " <> reason
    error.UserInfoFailed(reason:) -> "User info fetch failed: " <> reason
    error.ProviderError(code:, description:) ->
      "Provider error [" <> code <> "]: " <> description
    error.NetworkError(reason:) -> "Network error: " <> reason
    error.ConfigError(reason:) -> "Configuration error: " <> reason
    error.Custom(_) -> "Custom provider error"
  }
  let safe_message = html_escape(message)
  wisp.html_response("<html>
<head><title>Authentication Error</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authentication Failed</h1>
  <p style=\"color: #c0392b;\">" <> safe_message <> "</p>
  <a href=\"/\">Try again</a>
</body>
</html>", 400)
}

fn html_escape(text: String) -> String {
  text
  |> string.replace("&", "&amp;")
  |> string.replace("<", "&lt;")
  |> string.replace(">", "&gt;")
  |> string.replace("\"", "&quot;")
  |> string.replace("'", "&#x27;")
}
