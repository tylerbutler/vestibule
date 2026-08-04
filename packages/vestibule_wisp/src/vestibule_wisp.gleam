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
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import wisp.{type Request, type Response}

import vestibule/auth.{type Auth}
import vestibule/config.{type AuthorizeOptions}
import vestibule/error
import vestibule/logger
import vestibule/registry.{type Registry}
import vestibule/state_store.{type StateStore}
import vestibule/transport_flow

/// Middleware configuration options.
///
/// Construct with `default_options` and customize with `with_cookie_name`
/// and `with_session_ttl_seconds`. The type is opaque so the session cookie
/// name is always host-bound (`__Host-` prefixed): a non-host-bound name such
/// as `vestibule_session` can be overwritten by a sibling subdomain setting a
/// `Domain=.example.com` cookie of the same name, which lets an attacker plant
/// their own in-flight flow state and fixate the victim's session — especially
/// dangerous in account-linking flows. Read the effective name with
/// `cookie_name`.
pub opaque type Options {
  Options(
    // Base cookie name without the `__Host-` prefix; the effective name is
    // produced by the `cookie_name` accessor.
    cookie_name: String,
    session_ttl_seconds: Int,
  )
}

/// Structured errors that can occur during the OAuth callback phase.
pub type CallbackError(e) {
  /// The requested provider is not registered.
  UnknownProvider(provider: String)
  /// The signed session cookie set during the request phase is missing or
  /// invalid (no cookie present, signature mismatch, tampered payload).
  MissingOrInvalidSessionCookie
  /// The session state was not found, expired, or already used.
  SessionUnavailable
  /// Callback parameters could not be extracted from the request; `reason`
  /// says why.
  InvalidCallbackParams(reason: CallbackParamsError)
  /// Provider authentication failed.
  AuthFailed(error.AuthError(e))
}

/// Why callback parameters could not be extracted from a POST callback body.
pub type CallbackParamsError {
  /// The request body could not be read.
  BodyReadFailed
  /// The request body was not valid UTF-8.
  BodyNotUtf8
  /// The request body was not valid form/query encoding.
  BodyNotFormEncoded
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
  Options(cookie_name: default_cookie_base_name, session_ttl_seconds: 600)
}

/// Prefix that makes a cookie host-bound under the `__Host-` cookie name rule.
const host_cookie_prefix: String = "__Host-"

/// The default session cookie name, before the `__Host-` prefix is applied.
const default_cookie_base_name: String = "vestibule_session"

/// Set a custom session cookie name.
///
/// The name is always made host-bound: a `__Host-` prefix is added when
/// `name` does not already carry one, so both `"my_session"` and
/// `"__Host-my_session"` produce the effective cookie name
/// `__Host-my_session`. See the `Options` docs for why the prefix is
/// mandatory.
pub fn with_cookie_name(options: Options, name: String) -> Options {
  let base = case string.starts_with(name, host_cookie_prefix) {
    True -> string.drop_start(name, string.length(host_cookie_prefix))
    False -> name
  }
  Options(..options, cookie_name: base)
}

/// Set how long an in-flight authorization flow (and its session cookie)
/// stays valid.
pub fn with_session_ttl_seconds(options: Options, seconds: Int) -> Options {
  Options(..options, session_ttl_seconds: seconds)
}

/// The effective (host-bound) session cookie name for these options.
pub fn cookie_name(options: Options) -> String {
  host_cookie_prefix <> options.cookie_name
}

/// The session TTL in seconds for these options.
pub fn session_ttl_seconds(options: Options) -> Int {
  options.session_ttl_seconds
}

/// Returns `True` when `name` is host-bound (uses the `__Host-` prefix).
///
/// Host-bound cookie names resist cookie tossing / session fixation from
/// sibling subdomains: browsers only accept a `__Host-` cookie when it is set
/// with `Secure`, `Path=/`, and no `Domain` attribute, so a sibling subdomain
/// cannot overwrite it with a `Domain=.example.com` cookie of the same name.
/// `Options` enforces the prefix for its own cookie name; use this to check
/// names from other sources.
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
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
  authorize_options authorize_options: AuthorizeOptions,
) -> Response {
  request_phase_with_options(
    req,
    registry: registry,
    provider: provider,
    state_store: state_store,
    authorize_options: authorize_options,
    middleware_options: default_options(),
  )
}

/// Phase 1: Redirect user to the OAuth provider using custom middleware
/// options.
pub fn request_phase_with_options(
  req: Request,
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
  authorize_options authorize_options: AuthorizeOptions,
  middleware_options middleware_options: Options,
) -> Response {
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.adapter.request.start",
      phase: "request",
      outcome: "start",
      provider: option.Some(provider),
      fields: [logger.field("transport", "wisp")],
    ),
  )
  case
    transport_flow.start_authorization(
      registry,
      provider: provider,
      store: state_store,
      ttl_seconds: session_ttl_seconds(middleware_options),
      options: authorize_options,
    )
  {
    Error(transport_flow.UnknownProvider(_)) -> {
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.adapter.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("transport", "wisp"),
            logger.field("error_category", "unknown_provider"),
          ],
        ),
      )
      wisp.not_found()
    }
    Error(transport_flow.AuthFailed(err)) -> {
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.adapter.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("transport", "wisp"),
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
      error_response(err)
    }
    Error(transport_flow.StoreFailed(_)) -> {
      logger.emit(
        logger.new(
          level: logger.Error,
          event: "vestibule.adapter.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("transport", "wisp"),
            logger.field("error_category", "state_store_failed"),
          ],
        ),
      )
      error_response(error.config(reason: "Failed to store OAuth session state"))
    }
    Ok(#(url, session_id)) -> {
      logger.emit(
        logger.new(
          level: logger.Info,
          event: "vestibule.adapter.request.success",
          phase: "request",
          outcome: "success",
          provider: option.Some(provider),
          fields: [logger.field("transport", "wisp")],
        ),
      )
      wisp.redirect(url)
      |> wisp.set_cookie(
        req,
        cookie_name(middleware_options),
        session_id,
        wisp.Signed,
        session_ttl_seconds(middleware_options),
      )
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
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
  on_success on_success: fn(Auth) -> Response,
) -> Response {
  callback_phase_with_options(
    req,
    registry: registry,
    provider: provider,
    state_store: state_store,
    on_success: on_success,
    options: default_options(),
  )
}

/// Phase 2: Handle the OAuth callback using custom middleware options.
pub fn callback_phase_with_options(
  req: Request,
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
  on_success on_success: fn(Auth) -> Response,
  options options: Options,
) -> Response {
  case
    callback_phase_auth_result_with_options(
      req,
      registry: registry,
      provider: provider,
      state_store: state_store,
      options: options,
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
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
) -> Result(Auth, Response) {
  callback_phase_result_with_options(
    req,
    registry: registry,
    provider: provider,
    state_store: state_store,
    options: default_options(),
  )
}

/// Phase 2 (Result variant): Handle the OAuth callback using custom middleware
/// options.
pub fn callback_phase_result_with_options(
  req: Request,
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
  options options: Options,
) -> Result(Auth, Response) {
  case
    callback_phase_auth_result_with_options(
      req,
      registry: registry,
      provider: provider,
      state_store: state_store,
      options: options,
    )
  {
    Ok(auth) -> Ok(auth)
    Error(err) -> Error(callback_error_response(err))
  }
}

/// Phase 2 (structured Result variant): Handle the OAuth callback and return
/// either the Auth result or a structured callback error.
///
/// Use this when you want to distinguish provider lookup, session, callback
/// parameter, and provider authentication failures without parsing responses.
pub fn callback_phase_auth_result(
  req: Request,
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
) -> Result(Auth, CallbackError(e)) {
  callback_phase_auth_result_with_options(
    req,
    registry: registry,
    provider: provider,
    state_store: state_store,
    options: default_options(),
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
  registry registry: Registry(e),
  provider provider: String,
  state_store state_store: StateStore,
  options options: Options,
) -> Result(Auth, CallbackError(e)) {
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.adapter.callback.start",
      phase: "callback",
      outcome: "start",
      provider: option.Some(provider),
      fields: [logger.field("transport", "wisp")],
    ),
  )
  let outcome = {
    use strategy_config <- result.try(
      transport_flow.ensure_callback_provider(registry, provider)
      |> result.map_error(to_callback_error),
    )

    use params <- result.try(get_callback_params(req))

    use session_id <- result.try(
      wisp.get_cookie(req, cookie_name(options), wisp.Signed)
      |> result.map_error(fn(_) { MissingOrInvalidSessionCookie }),
    )

    transport_flow.finish_callback(
      strategy_config,
      store: state_store,
      params: params,
      session_id: session_id,
    )
    |> result.map_error(to_callback_error)
  }
  case outcome {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Info,
          event: "vestibule.adapter.callback.success",
          phase: "callback",
          outcome: "success",
          provider: option.Some(provider),
          fields: [logger.field("transport", "wisp")],
        ),
      )
    Error(err) -> log_callback_error(provider, err)
  }
  outcome
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
      use body_bits <- result.try(
        wisp.read_body_bits(req)
        |> result.replace_error(InvalidCallbackParams(BodyReadFailed)),
      )
      use body_string <- result.try(
        bit_array.to_string(body_bits)
        |> result.replace_error(InvalidCallbackParams(BodyNotUtf8)),
      )
      use body_params <- result.try(
        uri.parse_query(body_string)
        |> result.replace_error(InvalidCallbackParams(BodyNotFormEncoded)),
      )
      // Merge: body params take precedence over query params
      Ok(dict.merge(dict.from_list(query_params), dict.from_list(body_params)))
    }
    _ -> Ok(dict.from_list(query_params))
  }
}

fn to_callback_error(
  err: transport_flow.CallbackFlowError(e),
) -> CallbackError(e) {
  case err {
    transport_flow.CallbackUnknownProvider(provider) ->
      UnknownProvider(provider)
    transport_flow.CallbackSessionUnavailable -> SessionUnavailable
    transport_flow.CallbackAuthFailed(err) -> AuthFailed(err)
  }
}

fn log_callback_error(provider: String, err: CallbackError(e)) -> Nil {
  let category = case err {
    UnknownProvider(_) -> "unknown_provider"
    MissingOrInvalidSessionCookie -> "missing_or_invalid_session_cookie"
    SessionUnavailable -> "session_unavailable"
    InvalidCallbackParams(_) -> "invalid_callback_params"
    AuthFailed(auth_err) -> logger.auth_error_category(auth_err)
  }
  logger.emit(
    logger.new(
      level: logger.Warning,
      event: "vestibule.adapter.callback.failure",
      phase: "callback",
      outcome: "failure",
      provider: option.Some(provider),
      fields: [
        logger.field("transport", "wisp"),
        logger.field("error_category", category),
      ],
    ),
  )
}

fn callback_error_response(err: CallbackError(e)) -> Response {
  case err {
    UnknownProvider(_) -> wisp.not_found()
    MissingOrInvalidSessionCookie ->
      error_response(error.config(reason: "Missing or invalid session cookie"))
    SessionUnavailable ->
      error_response(error.config(reason: "Session expired or already used"))
    InvalidCallbackParams(_) ->
      error_response(error.config(reason: "Invalid callback parameters"))
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
