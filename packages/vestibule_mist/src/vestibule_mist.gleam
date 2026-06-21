//// Mist middleware that wires a `Registry` of `Strategy` values into HTTP
//// endpoints.
////
//// Provides `request_phase` (start an authorization flow, persist `state`
//// and `code_verifier`) and `callback_phase` (validate state, exchange
//// code, fetch user, invoke caller's success handler). Uses the shared
//// `vestibule/state_store` for single-use storage of in-flight flow state
//// and an HMAC-SHA256 signed cookie to bind a browser session to a stored
//// state entry.
////
//// Unlike `vestibule_wisp`, mist has no built-in signed cookie helper, so
//// the secret key base must be supplied via `new_options/1`. There is no
//// `default_options` — callers must construct `Options` explicitly so the
//// type system enforces a conscious secret choice.

import gleam/bit_array
import gleam/bytes_tree
import gleam/dict
import gleam/http
import gleam/http/cookie
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/list
import gleam/option
import gleam/result
import gleam/uri
import mist.{type Connection, type ResponseData}

import vestibule/auth.{type Auth}
import vestibule/error
import vestibule/internal/logger
import vestibule/registry.{type Registry}
import vestibule/state_store.{type StateStore}
import vestibule/transport_flow
import vestibule_mist/signed_cookie

/// Maximum body size accepted from a POST callback. 64 KiB is well above the
/// largest realistic OAuth form_post payload (an Apple identity_token is a few
/// KiB) and small enough to reject obvious abuse without risking truncation.
const max_callback_body_bytes: Int = 65_536

/// Middleware configuration options.
///
/// Construct with `new_options/1`. There is no `default_options` because the
/// HMAC `secret_key_base` is mandatory and has no safe default.
pub type Options {
  Options(
    secret_key_base: BitArray,
    cookie_name: String,
    session_ttl_seconds: Int,
    secure_cookie: Bool,
  )
}

/// Structured errors that can occur during the OAuth callback phase.
pub type CallbackError(e) {
  /// The requested provider is not registered.
  UnknownProvider(provider: String)
  /// The signed session cookie set during the request phase is missing or
  /// invalid (no cookie present, signature mismatch, wrong secret, tampered
  /// payload).
  MissingOrInvalidSessionCookie
  /// The session state was not found, expired, or already used.
  SessionUnavailable
  /// Callback parameters could not be extracted from the request (e.g.
  /// malformed POST body, body too large, non-UTF-8 body).
  InvalidCallbackParams
  /// Provider authentication failed.
  AuthFailed(error.AuthError(e))
}

/// Build middleware options with the given HMAC `secret_key_base`.
///
/// Defaults: cookie name `vestibule_session`, session TTL 600 seconds. Update
/// fields directly to customize (`Options(..options, session_ttl_seconds: 300)`).
pub fn new_options(secret_key_base: BitArray) -> Options {
  Options(
    secret_key_base: secret_key_base,
    cookie_name: "vestibule_session",
    session_ttl_seconds: 600,
    secure_cookie: True,
  )
}

/// Phase 1: Redirect the user to the OAuth provider.
///
/// Looks up the provider in the registry, generates an authorization URL with
/// PKCE parameters, stores the CSRF state and code verifier in `store`, sets
/// a signed session cookie, and returns a 302 response.
///
/// Returns 404 if the provider is not registered, or a generic 400 HTML error
/// if URL generation or state persistence fails.
///
/// Generic over the request body type: the body is never read, only request
/// metadata (scheme, cookies) is inspected.
pub fn request_phase(
  _req: Request(body),
  reg: Registry(e),
  provider: String,
  store: StateStore,
  options: Options,
) -> Response(ResponseData) {
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.adapter.request.start",
      phase: "request",
      outcome: "start",
      provider: option.Some(provider),
      fields: [
        logger.field("transport", "mist"),
        logger.bool_field("secure_cookie", options.secure_cookie),
      ],
    ),
  )
  case
    transport_flow.start_authorization(
      reg,
      provider: provider,
      store: store,
      ttl_seconds: options.session_ttl_seconds,
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
            logger.field("transport", "mist"),
            logger.field("error_category", "unknown_provider"),
          ],
        ),
      )
      not_found_response()
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
            logger.field("transport", "mist"),
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
      generic_error_response()
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
            logger.field("transport", "mist"),
            logger.field("error_category", "state_store_failed"),
          ],
        ),
      )
      generic_error_response()
    }
    Ok(#(url, session_id)) -> {
      logger.emit(
        logger.new(
          level: logger.Info,
          event: "vestibule.adapter.request.success",
          phase: "request",
          outcome: "success",
          provider: option.Some(provider),
          fields: [logger.field("transport", "mist")],
        ),
      )
      let token =
        signed_cookie.sign(
          payload: session_id,
          secret_key_base: options.secret_key_base,
        )
      let attrs =
        cookie.Attributes(
          max_age: option.Some(options.session_ttl_seconds),
          domain: option.None,
          path: option.Some("/"),
          secure: options.secure_cookie,
          http_only: True,
          same_site: option.Some(cookie.Lax),
        )
      redirect(url)
      |> response.set_cookie(options.cookie_name, token, attrs)
    }
  }
}

/// Phase 2: Handle the OAuth callback and return the `Auth` result to the
/// provided callback function.
///
/// Supports both GET callbacks (query parameters) and POST callbacks
/// (form-encoded body), as required by providers like Apple that use
/// `response_mode=form_post`. For POST requests, form body parameters take
/// precedence over query parameters.
///
/// On success, calls `on_success` with the `Auth`. On error, returns a
/// generic HTML error page. Returns 404 if the provider is not registered.
pub fn callback_phase(
  req: Request(Connection),
  reg: Registry(e),
  provider: String,
  store: StateStore,
  options: Options,
  on_success: fn(Auth) -> Response(ResponseData),
) -> Response(ResponseData) {
  case
    callback_phase_auth_result(
      req,
      reg: reg,
      provider: provider,
      store: store,
      options: options,
    )
  {
    Ok(auth) -> on_success(auth)
    Error(err) -> callback_error_response(err)
  }
}

/// Phase 2 (Result variant): Handle the OAuth callback and return either the
/// `Auth` result or an error `Response`.
///
/// Use this instead of `callback_phase` when you want to decide how to use the
/// success value or generated error response yourself.
pub fn callback_phase_result(
  req: Request(Connection),
  reg reg: Registry(e),
  provider provider: String,
  store store: StateStore,
  options options: Options,
) -> Result(Auth, Response(ResponseData)) {
  case
    callback_phase_auth_result(
      req,
      reg: reg,
      provider: provider,
      store: store,
      options: options,
    )
  {
    Ok(auth) -> Ok(auth)
    Error(err) -> Error(callback_error_response(err))
  }
}

/// Phase 2 (structured Result variant): Handle the OAuth callback and return
/// either the `Auth` result or a structured `CallbackError`.
///
/// Use this when you want to distinguish provider lookup, session, callback
/// parameter, and provider authentication failures without parsing responses.
///
/// Callback parameters are parsed and state is validated before the stored
/// session is consumed, so malformed or wrong-state callbacks do not burn a
/// valid in-flight login.
pub fn callback_phase_auth_result(
  req: Request(Connection),
  reg reg: Registry(e),
  provider provider: String,
  store store: StateStore,
  options options: Options,
) -> Result(Auth, CallbackError(e)) {
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.adapter.callback.start",
      phase: "callback",
      outcome: "start",
      provider: option.Some(provider),
      fields: [logger.field("transport", "mist")],
    ),
  )
  case get_callback_params(req) {
    Error(err) -> {
      log_callback_error(provider, err)
      Error(err)
    }
    Ok(params) ->
      do_callback_phase_auth_result_with_params(
        req,
        params: params,
        reg: reg,
        provider: provider,
        store: store,
        options: options,
      )
  }
}

/// Phase 2 with pre-extracted callback parameters.
///
/// Useful when the caller has already read the request body (or otherwise
/// resolved the form/query parameters) and wants to hand them in directly.
/// Generic over the request body type so it can be used in unit tests with
/// `Request(BitArray)` or any other body.
pub fn callback_phase_auth_result_with_params(
  req: Request(body),
  params params: dict.Dict(String, String),
  reg reg: Registry(e),
  provider provider: String,
  store store: StateStore,
  options options: Options,
) -> Result(Auth, CallbackError(e)) {
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.adapter.callback.start",
      phase: "callback",
      outcome: "start",
      provider: option.Some(provider),
      fields: [logger.field("transport", "mist")],
    ),
  )
  do_callback_phase_auth_result_with_params(
    req,
    params: params,
    reg: reg,
    provider: provider,
    store: store,
    options: options,
  )
}

fn do_callback_phase_auth_result_with_params(
  req: Request(body),
  params params: dict.Dict(String, String),
  reg reg: Registry(e),
  provider provider: String,
  store store: StateStore,
  options options: Options,
) -> Result(Auth, CallbackError(e)) {
  let outcome = {
    use strategy_config <- result.try(
      transport_flow.ensure_callback_provider(reg, provider)
      |> result.map_error(map_callback_flow_error),
    )

    use session_id <- result.try(get_signed_cookie(
      req,
      options.cookie_name,
      options.secret_key_base,
    ))

    transport_flow.finish_callback(
      strategy_config,
      store: store,
      params: params,
      session_id: session_id,
    )
    |> result.map_error(map_callback_flow_error)
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
          fields: [logger.field("transport", "mist")],
        ),
      )
    Error(err) -> log_callback_error(provider, err)
  }
  outcome
}

fn get_signed_cookie(
  req: Request(body),
  cookie_name: String,
  secret_key_base: BitArray,
) -> Result(String, CallbackError(e)) {
  let cookies = request.get_cookies(req)
  case list.key_find(cookies, cookie_name) {
    Error(Nil) -> Error(MissingOrInvalidSessionCookie)
    Ok(token) ->
      signed_cookie.verify(token: token, secret_key_base: secret_key_base)
      |> result.map_error(fn(_) { MissingOrInvalidSessionCookie })
  }
}

/// Extract callback parameters from either query string (GET) or
/// form-encoded body (POST). For POST requests, body parameters are merged
/// over query parameters so body values take precedence.
fn get_callback_params(
  req: Request(Connection),
) -> Result(dict.Dict(String, String), CallbackError(e)) {
  let query_params = case req.query {
    option.Some(q) -> uri.parse_query(q) |> result.unwrap([])
    option.None -> []
  }
  case req.method {
    http.Post -> {
      use req_with_body <- result.try(
        mist.read_body(req, max_callback_body_bytes)
        |> result.map_error(fn(_) { InvalidCallbackParams }),
      )
      use body_string <- result.try(
        bit_array.to_string(req_with_body.body)
        |> result.map_error(fn(_) { InvalidCallbackParams }),
      )
      use body_params <- result.try(
        uri.parse_query(body_string)
        |> result.map_error(fn(_) { InvalidCallbackParams }),
      )
      Ok(dict.merge(dict.from_list(query_params), dict.from_list(body_params)))
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
    transport_flow.CallbackSessionUnavailable -> SessionUnavailable
    transport_flow.CallbackAuthFailed(err) -> AuthFailed(err)
  }
}

fn log_callback_error(provider: String, err: CallbackError(e)) -> Nil {
  let category = case err {
    UnknownProvider(_) -> "unknown_provider"
    MissingOrInvalidSessionCookie -> "missing_or_invalid_session_cookie"
    SessionUnavailable -> "session_unavailable"
    InvalidCallbackParams -> "invalid_callback_params"
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
        logger.field("transport", "mist"),
        logger.field("error_category", category),
      ],
    ),
  )
}

fn callback_error_response(err: CallbackError(e)) -> Response(ResponseData) {
  case err {
    UnknownProvider(_) -> not_found_response()
    MissingOrInvalidSessionCookie -> generic_error_response()
    SessionUnavailable -> generic_error_response()
    InvalidCallbackParams -> generic_error_response()
    AuthFailed(_) -> generic_error_response()
  }
}

fn redirect(location: String) -> Response(ResponseData) {
  response.new(302)
  |> response.set_header("location", location)
  |> response.set_body(mist.Bytes(bytes_tree.new()))
}

fn not_found_response() -> Response(ResponseData) {
  response.new(404)
  |> response.set_header("content-type", "text/plain; charset=utf-8")
  |> response.set_body(mist.Bytes(bytes_tree.from_string("Not Found")))
}

fn generic_error_response() -> Response(ResponseData) {
  let body =
    "<html>
<head><title>Authentication Error</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authentication Failed</h1>
  <p style=\"color: #c0392b;\">Authentication failed. Please try again.</p>
  <a href=\"/\">Try again</a>
</body>
</html>"
  response.new(400)
  |> response.set_header("content-type", "text/html; charset=utf-8")
  |> response.set_body(mist.Bytes(bytes_tree.from_string(body)))
}
