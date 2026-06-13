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
import gleam/string
import gleam/uri
import wisp.{type Request, type Response}

import vestibule/auth.{type Auth}
import vestibule/error
import vestibule/registry.{type Registry}
import vestibule/state_store.{type StateStore}
import vestibule/transport_flow

/// Middleware configuration options.
///
/// `cookie_name` should be host-bound (use the `__Host-` prefix) to defend
/// against OAuth session cookie tossing / fixation. A non-host-bound name such
/// as `vestibule_session` can be overwritten by a sibling subdomain setting a
/// `Domain=.example.com` cookie of the same name, which lets an attacker plant
/// their own in-flight flow state and fixate the victim's session — especially
/// dangerous in account-linking flows. The default options use a host-bound
/// name; keep the `__Host-` prefix for any custom `cookie_name`. See
/// `is_host_bound_cookie_name`.
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
/// Uses the host-bound `__Host-vestibule_session` signed cookie with a
/// 600-second session TTL. The `__Host-` prefix makes browsers reject the
/// cookie unless it is set with `Secure`, `Path=/`, and no `Domain` attribute,
/// which prevents a sibling subdomain from tossing/fixating the OAuth session
/// (see the `Options` docs). `wisp.set_cookie` already sets `Secure` (over
/// HTTPS), `Path=/`, and no `Domain`, so this cookie meets the `__Host-`
/// requirements.
pub fn default_options() -> Options {
  Options(cookie_name: host_bound_cookie_name, session_ttl_seconds: 600)
}

/// Prefix that makes a cookie host-bound under the `__Host-` cookie name rule.
const host_cookie_prefix: String = "__Host-"

/// The default host-bound OAuth session cookie name.
const host_bound_cookie_name: String = "__Host-vestibule_session"

/// Returns `True` when `name` is host-bound (uses the `__Host-` prefix).
///
/// Host-bound cookie names resist cookie tossing / session fixation from
/// sibling subdomains: browsers only accept a `__Host-` cookie when it is set
/// with `Secure`, `Path=/`, and no `Domain` attribute, so a sibling subdomain
/// cannot overwrite it with a `Domain=.example.com` cookie of the same name.
/// Prefer keeping the `__Host-` prefix for any custom `Options.cookie_name`;
/// use this to validate names supplied by callers.
pub fn is_host_bound_cookie_name(name: String) -> Bool {
  string.starts_with(name, host_cookie_prefix)
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
  case
    transport_flow.start_authorization(
      reg,
      provider,
      state_store,
      options.session_ttl_seconds,
    )
  {
    Error(transport_flow.UnknownProvider(_)) -> wisp.not_found()
    Error(transport_flow.AuthFailed(err)) -> error_response(err)
    Error(transport_flow.StoreFailed(_)) ->
      error_response(error.ConfigError(
        reason: "Failed to store OAuth session state",
      ))
    Ok(#(url, session_id)) ->
      wisp.redirect(url)
      |> wisp.set_cookie(
        req,
        options.cookie_name,
        session_id,
        wisp.Signed,
        options.session_ttl_seconds,
      )
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
  use _ <- result.try(
    transport_flow.ensure_callback_provider(reg, provider)
    |> result.map_error(map_callback_flow_error),
  )

  use params <- result.try(get_callback_params(req))

  use session_id <- result.try(
    wisp.get_cookie(req, options.cookie_name, wisp.Signed)
    |> result.map_error(fn(_) { MissingSessionCookie }),
  )

  transport_flow.finish_callback(reg, provider, state_store, params, session_id)
  |> result.map_error(map_callback_flow_error)
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

fn map_callback_flow_error(
  err: transport_flow.CallbackFlowError(e),
) -> CallbackError(e) {
  case err {
    transport_flow.CallbackUnknownProvider(provider) ->
      UnknownProvider(provider)
    transport_flow.CallbackSessionUnavailable -> SessionExpired
    transport_flow.CallbackAuthFailed(err) -> AuthFailed(err)
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
