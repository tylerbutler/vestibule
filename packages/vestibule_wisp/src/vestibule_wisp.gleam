//// Wisp middleware that wires a `Registry` of `Strategy` values into HTTP
//// endpoints.
////
//// Provides `request_phase` (start an authorization flow, persist `state`
//// and `code_verifier`) and `callback_phase` (validate state, exchange
//// code, fetch user, invoke caller's success handler). Uses a `StateStore`
//// for single-use storage of in-flight flow state.

import gleam/bit_array
import gleam/dict
import gleam/http
import gleam/result
import gleam/uri
import wisp.{type Request, type Response}

import vestibule
import vestibule/auth.{type Auth}
import vestibule/authorization_request
import vestibule/error
import vestibule/registry.{type Registry}
import vestibule/state
import vestibule_wisp/state_store.{type StateStore}

/// Middleware configuration options.
pub type Options {
  Options(cookie_name: String, session_ttl_seconds: Int)
}

/// Structured errors that can occur during the OAuth callback phase.
pub type CallbackError(e) {
  /// The requested provider is not registered.
  UnknownProvider(provider: String)
  /// The signed session cookie set during the request phase is missing or invalid.
  MissingSessionCookie
  /// The session state was not found, expired, or already used.
  SessionExpired
  /// Callback parameters could not be extracted from the request.
  InvalidCallbackParams
  /// Provider authentication failed.
  AuthFailed(error.AuthError(e))
}

/// Default middleware options.
///
/// Uses the `vestibule_session` signed cookie with a 600-second session TTL.
pub fn default_options() -> Options {
  Options(cookie_name: "vestibule_session", session_ttl_seconds: 600)
}

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
  request_phase_with_options(req, reg, provider, state_store, default_options())
}

/// Phase 1: Redirect user to the OAuth provider using custom middleware
/// options.
pub fn request_phase_with_options(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
  options: Options,
) -> Response {
  case registry.get(reg, provider) {
    Error(Nil) -> wisp.not_found()
    Ok(#(strategy, config)) ->
      case vestibule.authorize_url(strategy, config) {
        Ok(auth_request) -> {
          case
            state_store.try_store_with_ttl(
              state_store,
              authorization_request.state(auth_request),
              authorization_request.code_verifier(auth_request),
              options.session_ttl_seconds,
            )
          {
            Ok(session_id) ->
              wisp.redirect(authorization_request.url(auth_request))
              |> wisp.set_cookie(
                req,
                options.cookie_name,
                session_id,
                wisp.Signed,
                options.session_ttl_seconds,
              )
            Error(_) ->
              error_response(error.ConfigError(
                reason: "Failed to store OAuth session state",
              ))
          }
        }
        Error(err) -> error_response(err)
      }
  }
}

/// Phase 2: Handle the OAuth callback and return the Auth result
/// to the provided callback function.
///
/// Supports both GET callbacks (query parameters) and POST callbacks
/// (form-encoded body), as required by providers like Apple that use
/// `response_mode=form_post`. For POST requests, form body parameters
/// take precedence over query parameters.
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
  callback_phase_with_options(
    req,
    reg,
    provider,
    state_store,
    on_success,
    default_options(),
  )
}

/// Phase 2: Handle the OAuth callback using custom middleware options.
pub fn callback_phase_with_options(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
  on_success: fn(Auth) -> Response,
  options: Options,
) -> Response {
  case
    callback_phase_auth_result_with_options(
      req,
      reg,
      provider,
      state_store,
      options,
    )
  {
    Ok(auth) -> on_success(auth)
    Error(err) -> callback_error_response(err)
  }
}

/// Phase 2 (Result variant): Handle the OAuth callback and return
/// either the Auth result or an error Response.
///
/// Supports both GET callbacks (query parameters) and POST callbacks
/// (form-encoded body). See `callback_phase` for details.
///
/// Use this instead of `callback_phase` when you want to decide how to use the
/// success value or generated error response yourself.
pub fn callback_phase_result(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
) -> Result(Auth, Response) {
  callback_phase_result_with_options(
    req,
    reg,
    provider,
    state_store,
    default_options(),
  )
}

/// Phase 2 (Result variant): Handle the OAuth callback using custom middleware
/// options.
pub fn callback_phase_result_with_options(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
  options: Options,
) -> Result(Auth, Response) {
  callback_phase_auth_result_with_options(
    req,
    reg,
    provider,
    state_store,
    options,
  )
  |> result.map_error(callback_error_response)
}

/// Phase 2 (structured Result variant): Handle the OAuth callback and return
/// either the Auth result or a structured callback error.
///
/// Use this when you want to distinguish provider lookup, session, callback
/// parameter, and provider authentication failures without parsing responses.
pub fn callback_phase_auth_result(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
) -> Result(Auth, CallbackError(e)) {
  callback_phase_auth_result_with_options(
    req,
    reg,
    provider,
    state_store,
    default_options(),
  )
}

/// Phase 2 (structured Result variant): Handle the OAuth callback using custom
/// middleware options.
///
/// Callback parameters are parsed and state is validated before the stored
/// session is consumed, so malformed or wrong-state callbacks do not burn a
/// valid in-flight login.
pub fn callback_phase_auth_result_with_options(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
  options: Options,
) -> Result(Auth, CallbackError(e)) {
  use #(strategy, config) <- result.try(
    registry.get(reg, provider)
    |> result.map_error(fn(_) { UnknownProvider(provider) }),
  )

  use params <- result.try(get_callback_params(req))

  use received_state <- result.try(
    dict.get(params, "state")
    |> result.replace_error(AuthFailed(error.MissingCallbackParam("state"))),
  )

  use session_id <- result.try(
    wisp.get_cookie(req, options.cookie_name, wisp.Signed)
    |> result.map_error(fn(_) { MissingSessionCookie }),
  )

  use #(expected_state, _code_verifier) <- result.try(
    state_store.peek(state_store, session_id)
    |> result.map_error(fn(_) { SessionExpired }),
  )

  use _ <- result.try(
    state.validate(received_state, expected_state)
    |> result.map_error(AuthFailed),
  )

  use #(expected_state, code_verifier) <- result.try(
    state_store.retrieve(state_store, session_id)
    |> result.map_error(fn(_) { SessionExpired }),
  )

  vestibule.handle_callback(
    strategy,
    config,
    params,
    expected_state,
    code_verifier,
  )
  |> result.map_error(AuthFailed)
}

/// Extract callback parameters from either query string (GET) or
/// form-encoded body (POST). For POST requests, body parameters
/// are merged over query parameters so they take precedence.
fn get_callback_params(
  req: Request,
) -> Result(dict.Dict(String, String), CallbackError(e)) {
  let query_params = wisp.get_query(req)
  case req.method {
    http.Post -> {
      case wisp.read_body_bits(req) {
        Ok(body_bits) -> {
          case bit_array.to_string(body_bits) {
            Ok(body_string) -> {
              case uri.parse_query(body_string) {
                Ok(body_params) -> {
                  // Merge: body params take precedence over query params
                  Ok(dict.merge(
                    dict.from_list(query_params),
                    dict.from_list(body_params),
                  ))
                }
                Error(_) -> Error(InvalidCallbackParams)
              }
            }
            Error(_) -> Error(InvalidCallbackParams)
          }
        }
        Error(_) -> Error(InvalidCallbackParams)
      }
    }
    _ -> Ok(dict.from_list(query_params))
  }
}

fn callback_error_response(err: CallbackError(e)) -> Response {
  case err {
    UnknownProvider(_) -> wisp.not_found()
    MissingSessionCookie ->
      error_response(error.ConfigError(reason: "Missing session cookie"))
    SessionExpired ->
      error_response(error.ConfigError(
        reason: "Session expired or already used",
      ))
    InvalidCallbackParams ->
      error_response(error.ConfigError(reason: "Invalid callback parameters"))
    AuthFailed(err) -> error_response(err)
  }
}

fn error_response(_err: error.AuthError(e)) -> Response {
  wisp.html_response(
    "<html>
<head><title>Authentication Error</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authentication Failed</h1>
  <p style=\"color: #c0392b;\">Authentication failed. Please try again.</p>
  <a href=\"/\">Try again</a>
</body>
</html>",
    400,
  )
}
