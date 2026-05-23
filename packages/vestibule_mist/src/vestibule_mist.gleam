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

import vestibule
import vestibule/auth.{type Auth}
import vestibule/authorization_request
import vestibule/error
import vestibule/registry.{type Registry}
import vestibule/state
import vestibule/state_store.{type StateStore}
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
  )
}

/// Structured errors that can occur during the OAuth callback phase.
pub type CallbackError(e) {
  /// The requested provider is not registered.
  UnknownProvider(provider: String)
  /// The signed session cookie set during the request phase is missing or
  /// invalid (no cookie present, signature mismatch, wrong secret, tampered
  /// payload).
  MissingSessionCookie
  /// The session state was not found, expired, or already used.
  SessionExpired
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
  req: Request(body),
  reg: Registry(e),
  provider: String,
  store: StateStore,
  options: Options,
) -> Response(ResponseData) {
  case registry.get(reg, provider) {
    Error(Nil) -> not_found_response()
    Ok(#(strategy, config)) ->
      case vestibule.authorize_url(strategy, config) {
        Ok(auth_request) ->
          case
            state_store.try_store_with_ttl(
              store,
              authorization_request.state(auth_request),
              authorization_request.code_verifier(auth_request),
              options.session_ttl_seconds,
            )
          {
            Ok(session_id) -> {
              let token =
                signed_cookie.sign(session_id, options.secret_key_base)
              let attrs =
                cookie.Attributes(
                  max_age: option.Some(options.session_ttl_seconds),
                  domain: option.None,
                  path: option.Some("/"),
                  secure: req.scheme == http.Https,
                  http_only: True,
                  same_site: option.Some(cookie.Lax),
                )
              redirect(authorization_request.url(auth_request))
              |> response.set_cookie(options.cookie_name, token, attrs)
            }
            Error(_) ->
              error_response(error.ConfigError(
                reason: "Failed to store OAuth session state",
              ))
          }
        Error(err) -> error_response(err)
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
  case callback_phase_auth_result(req, reg, provider, store, options) {
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
  reg: Registry(e),
  provider: String,
  store: StateStore,
  options: Options,
) -> Result(Auth, Response(ResponseData)) {
  callback_phase_auth_result(req, reg, provider, store, options)
  |> result.map_error(callback_error_response)
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
  reg: Registry(e),
  provider: String,
  store: StateStore,
  options: Options,
) -> Result(Auth, CallbackError(e)) {
  use params <- result.try(get_callback_params(req))
  callback_phase_auth_result_with_params(req, params, reg, provider, store, options)
}

/// Phase 2 with pre-extracted callback parameters.
///
/// Useful when the caller has already read the request body (or otherwise
/// resolved the form/query parameters) and wants to hand them in directly.
/// Generic over the request body type so it can be used in unit tests with
/// `Request(BitArray)` or any other body.
pub fn callback_phase_auth_result_with_params(
  req: Request(body),
  params: dict.Dict(String, String),
  reg: Registry(e),
  provider: String,
  store: StateStore,
  options: Options,
) -> Result(Auth, CallbackError(e)) {
  use #(strategy, config) <- result.try(
    registry.get(reg, provider)
    |> result.map_error(fn(_) { UnknownProvider(provider) }),
  )

  use received_state <- result.try(
    dict.get(params, "state")
    |> result.replace_error(AuthFailed(error.MissingCallbackParam("state"))),
  )

  use session_id <- result.try(get_signed_cookie(
    req,
    options.cookie_name,
    options.secret_key_base,
  ))

  use #(expected_state, _code_verifier) <- result.try(
    state_store.peek(store, session_id)
    |> result.map_error(fn(_) { SessionExpired }),
  )

  use _ <- result.try(
    state.validate(received_state, expected_state)
    |> result.map_error(AuthFailed),
  )

  use #(expected_state, code_verifier) <- result.try(
    state_store.retrieve(store, session_id)
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

fn get_signed_cookie(
  req: Request(body),
  cookie_name: String,
  secret_key_base: BitArray,
) -> Result(String, CallbackError(e)) {
  let cookies = request.get_cookies(req)
  case list.key_find(cookies, cookie_name) {
    Error(Nil) -> Error(MissingSessionCookie)
    Ok(token) ->
      signed_cookie.verify(token, secret_key_base)
      |> result.map_error(fn(_) { MissingSessionCookie })
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
      case mist.read_body(req, max_callback_body_bytes) {
        Ok(req_with_body) ->
          case bit_array.to_string(req_with_body.body) {
            Ok(body_string) ->
              case uri.parse_query(body_string) {
                Ok(body_params) ->
                  Ok(dict.merge(
                    dict.from_list(query_params),
                    dict.from_list(body_params),
                  ))
                Error(_) -> Error(InvalidCallbackParams)
              }
            Error(_) -> Error(InvalidCallbackParams)
          }
        Error(_) -> Error(InvalidCallbackParams)
      }
    }
    _ -> Ok(dict.from_list(query_params))
  }
}

fn callback_error_response(err: CallbackError(e)) -> Response(ResponseData) {
  case err {
    UnknownProvider(_) -> not_found_response()
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

fn error_response(_err: error.AuthError(e)) -> Response(ResponseData) {
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
