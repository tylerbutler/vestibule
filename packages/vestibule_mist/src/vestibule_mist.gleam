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
//// `default_options` — callers must start from `new_options` so the type
//// system enforces a conscious secret choice.

import gleam/bit_array
import gleam/bool
import gleam/bytes_tree
import gleam/dict
import gleam/http
import gleam/http/cookie
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import mist.{type Connection, type ResponseData}

import vestibule/auth.{type Auth}
import vestibule/config.{type AuthorizeOptions}
import vestibule/error
import vestibule/logger
import vestibule/registry.{type Registry}
import vestibule/state_store.{type StateStore}
import vestibule/transport_flow
import vestibule_mist/signed_cookie

/// Maximum body size accepted from a POST callback. 64 KiB is well above the
/// largest realistic OAuth form_post payload (an Apple identity_token is a few
/// KiB) and small enough to reject obvious abuse without risking truncation.
const max_callback_body_bytes: Int = 65_536

/// Whether the session cookie is set with the `Secure` attribute.
pub type CookieSecurity {
  /// Set `Secure` so the cookie is only sent over HTTPS, and use a host-bound
  /// (`__Host-` prefixed) cookie name. Use in production.
  SecureOnly
  /// Omit `Secure` so the cookie also works over plain HTTP, e.g. local
  /// development without TLS. The cookie name is not host-bound, since
  /// browsers reject `__Host-` cookies that are not `Secure`.
  AllowInsecure
}

/// Minimum length of the HMAC `secret_key_base`, in bytes. 32 bytes is the
/// output size of the HMAC-SHA256 used to sign the session cookie; anything
/// shorter weakens the signature below the hash's own strength.
pub const min_secret_key_base_bytes: Int = 32

/// Errors returned by `new_options`.
pub type OptionsError {
  /// `secret_key_base` is shorter than `min_secret_key_base_bytes`.
  SecretKeyBaseTooShort(minimum_bytes: Int, actual_bytes: Int)
}

/// How the session cookie's `SameSite` attribute is set.
pub type CookieSameSite {
  /// `SameSite=Lax` (default). Sent on top-level GET navigations, which is
  /// how every provider that redirects back with query parameters delivers
  /// its callback.
  Lax
  /// `SameSite=None; Secure`. Required for providers that deliver the
  /// callback with a cross-site POST (`response_mode=form_post`, e.g. Apple):
  /// browsers do not send `Lax` cookies on cross-site POSTs, so the callback
  /// would fail with `MissingOrInvalidSessionCookie(CookieAbsent)`. Browsers
  /// only honour `SameSite=None` together with `Secure`, so `Secure` is set
  /// even under `AllowInsecure`.
  CrossSite
}

/// Middleware configuration options.
///
/// Construct with `new_options` — the HMAC `secret_key_base` is mandatory and
/// has no safe default — then customize with `with_cookie_name`,
/// `with_session_ttl_seconds`, `with_cookie_security`, and `with_same_site`. The type is opaque
/// so the effective cookie name always matches the cookie security: host-bound
/// (`__Host-` prefixed) under `SecureOnly`, unprefixed under `AllowInsecure`
/// (browsers reject `__Host-` cookies that are not `Secure`). A host-bound
/// name prevents a sibling subdomain from overwriting the session cookie with
/// a `Domain=.example.com` cookie of the same name (cookie tossing / session
/// fixation). Read the effective name with `cookie_name`.
pub opaque type Options {
  Options(
    secret_key_base: BitArray,
    // Base cookie name without the `__Host-` prefix; the effective name is
    // produced by the `cookie_name` accessor from `cookie_security`.
    cookie_name: String,
    session_ttl_seconds: Int,
    cookie_security: CookieSecurity,
    same_site: CookieSameSite,
  )
}

/// Structured errors that can occur during the OAuth callback phase.
pub type CallbackError(e) {
  /// The requested provider is not registered.
  UnknownProvider(provider: String)
  /// The signed session cookie set during the request phase is missing or
  /// invalid; `reason` says which.
  MissingOrInvalidSessionCookie(reason: SessionCookieError)
  /// The session state was not found, expired, or already used.
  SessionUnavailable
  /// Callback parameters could not be extracted from the request; `reason`
  /// says why.
  InvalidCallbackParams(reason: CallbackParamsError)
  /// Provider authentication failed.
  AuthFailed(error.AuthError(e))
}

/// Why the signed session cookie could not be used.
///
/// The distinction matters operationally: `CookieAbsent` is ordinary user
/// behaviour (a bookmarked callback URL, a cleared cookie jar, an expired
/// cookie), while `CookieSignatureInvalid` means a cookie was presented that
/// this secret did not sign, which may indicate tampering or a secret
/// rotation that invalidated in-flight logins.
pub type SessionCookieError {
  /// No cookie with the configured name was present on the request.
  CookieAbsent
  /// A cookie was present but its HMAC signature did not verify: wrong
  /// secret, tampered payload, or a malformed token.
  CookieSignatureInvalid
}

/// Why callback parameters could not be extracted from a POST callback body.
pub type CallbackParamsError {
  /// The request body could not be read (e.g. larger than the 64 KiB limit,
  /// or a transport failure).
  BodyReadFailed
  /// The request body was not valid UTF-8.
  BodyNotUtf8
  /// The request body was not valid form/query encoding.
  BodyNotFormEncoded
}

/// Prefix that makes a cookie host-bound under the `__Host-` cookie name rule.
const host_cookie_prefix: String = "__Host-"

/// The default session cookie name, before the `__Host-` prefix is applied.
const default_cookie_base_name: String = "vestibule_session"

/// Build middleware options with the given HMAC `secret_key_base`, which must
/// be at least `min_secret_key_base_bytes` (32) bytes of unpredictable data.
///
/// Defaults: host-bound cookie name `__Host-vestibule_session`, session TTL
/// 600 seconds, `SecureOnly` cookies, `SameSite=Lax`. Customize with
/// `with_cookie_name`, `with_session_ttl_seconds`, `with_cookie_security`, and
/// `with_same_site`.
pub fn new_options(secret_key_base: BitArray) -> Result(Options, OptionsError) {
  let actual_bytes = bit_array.byte_size(secret_key_base)
  use <- bool.guard(
    when: actual_bytes < min_secret_key_base_bytes,
    return: Error(SecretKeyBaseTooShort(
      minimum_bytes: min_secret_key_base_bytes,
      actual_bytes: actual_bytes,
    )),
  )
  Ok(Options(
    secret_key_base: secret_key_base,
    cookie_name: default_cookie_base_name,
    session_ttl_seconds: 600,
    cookie_security: SecureOnly,
    same_site: Lax,
  ))
}

/// Set a custom session cookie name.
///
/// The name is stored without any `__Host-` prefix (one is stripped when
/// present); the prefix is applied automatically under `SecureOnly` cookie
/// security. See the `Options` docs.
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

/// Set whether the session cookie requires HTTPS. See `CookieSecurity`.
pub fn with_cookie_security(
  options: Options,
  security: CookieSecurity,
) -> Options {
  Options(..options, cookie_security: security)
}

/// Set the session cookie's `SameSite` attribute. See `CookieSameSite`.
pub fn with_same_site(options: Options, same_site: CookieSameSite) -> Options {
  Options(..options, same_site: same_site)
}

/// The session cookie's `SameSite` setting for these options.
pub fn same_site(options: Options) -> CookieSameSite {
  options.same_site
}

/// The effective session cookie name: host-bound (`__Host-` prefixed) under
/// `SecureOnly` cookie security, the unprefixed base name under
/// `AllowInsecure`.
pub fn cookie_name(options: Options) -> String {
  case options.cookie_security {
    SecureOnly -> host_cookie_prefix <> options.cookie_name
    AllowInsecure -> options.cookie_name
  }
}

/// The session TTL in seconds for these options.
pub fn session_ttl_seconds(options: Options) -> Int {
  options.session_ttl_seconds
}

/// The cookie security for these options.
pub fn cookie_security(options: Options) -> CookieSecurity {
  options.cookie_security
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
/// The request is not inspected at all — everything the response needs comes
/// from `options` and the registry. It is still taken as an argument so this
/// function has the same shape as `callback_phase` and its `vestibule_wisp`
/// counterpart, and so a future change can read request metadata without
/// breaking callers. Hence it is generic over the body type.
pub fn request_phase(
  _http_request: Request(body),
  registry registry: Registry(e),
  provider provider: String,
  store store: StateStore,
  authorize_options authorize_options: AuthorizeOptions,
  options options: Options,
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
        logger.bool_field(
          "secure_cookie",
          secure_attribute(options.cookie_security),
        ),
      ],
    ),
  )
  case
    transport_flow.start_authorization(
      registry,
      provider: provider,
      store: store,
      ttl_seconds: options.session_ttl_seconds,
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
            logger.field("transport", "mist"),
            logger.field("error_category", "unknown_provider"),
          ],
        ),
      )
      not_found_response()
    }
    Error(transport_flow.AuthFailed(authentication_error)) -> {
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.adapter.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("transport", "mist"),
            logger.field(
              "error_category",
              logger.auth_error_category(authentication_error),
            ),
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
      let attributes =
        cookie.Attributes(
          max_age: option.Some(options.session_ttl_seconds),
          domain: option.None,
          path: option.Some("/"),
          secure: secure_attribute(options.cookie_security)
            || options.same_site == CrossSite,
          http_only: True,
          same_site: option.Some(same_site_policy(options.same_site)),
        )
      redirect(url)
      |> response.set_cookie(cookie_name(options), token, attributes)
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
  http_request: Request(Connection),
  registry registry: Registry(e),
  provider provider: String,
  store store: StateStore,
  options options: Options,
  on_success on_success: fn(Auth) -> Response(ResponseData),
) -> Response(ResponseData) {
  case
    callback_phase_auth_result(
      http_request,
      registry: registry,
      provider: provider,
      store: store,
      options: options,
    )
  {
    Ok(auth) -> on_success(auth)
    Error(callback_error) -> callback_error_response(callback_error)
  }
}

/// Phase 2 (Result variant): Handle the OAuth callback and return either the
/// `Auth` result or an error `Response`.
///
/// Use this instead of `callback_phase` when you want to decide how to use the
/// success value or generated error response yourself.
pub fn callback_phase_result(
  http_request: Request(Connection),
  registry registry: Registry(e),
  provider provider: String,
  store store: StateStore,
  options options: Options,
) -> Result(Auth, Response(ResponseData)) {
  case
    callback_phase_auth_result(
      http_request,
      registry: registry,
      provider: provider,
      store: store,
      options: options,
    )
  {
    Ok(auth) -> Ok(auth)
    Error(callback_error) -> Error(callback_error_response(callback_error))
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
  http_request: Request(Connection),
  registry registry: Registry(e),
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
  case get_callback_params(http_request) {
    Error(callback_error) -> {
      log_callback_error(provider, callback_error)
      Error(callback_error)
    }
    Ok(callback_params) ->
      do_callback_phase_auth_result_with_parameters(
        http_request,
        params: callback_params,
        registry: registry,
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
  http_request: Request(body),
  params callback_params: dict.Dict(String, String),
  registry registry: Registry(e),
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
  do_callback_phase_auth_result_with_parameters(
    http_request,
    params: callback_params,
    registry: registry,
    provider: provider,
    store: store,
    options: options,
  )
}

fn do_callback_phase_auth_result_with_parameters(
  http_request: Request(body),
  params callback_params: dict.Dict(String, String),
  registry registry: Registry(e),
  provider provider: String,
  store store: StateStore,
  options options: Options,
) -> Result(Auth, CallbackError(e)) {
  let outcome = {
    use strategy_config <- result.try(
      transport_flow.ensure_callback_provider(registry, provider)
      |> result.map_error(to_callback_error),
    )

    use session_id <- result.try(get_signed_cookie(
      http_request,
      cookie_name(options),
      options.secret_key_base,
    ))

    transport_flow.finish_callback(
      strategy_config,
      store: store,
      parameters: callback_params,
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
          fields: [logger.field("transport", "mist")],
        ),
      )
    Error(callback_error) -> log_callback_error(provider, callback_error)
  }
  outcome
}

fn get_signed_cookie(
  http_request: Request(body),
  cookie_name: String,
  secret_key_base: BitArray,
) -> Result(String, CallbackError(e)) {
  let cookies = request.get_cookies(http_request)
  case list.key_find(cookies, cookie_name) {
    Error(Nil) -> Error(MissingOrInvalidSessionCookie(CookieAbsent))
    Ok(token) ->
      signed_cookie.verify(token: token, secret_key_base: secret_key_base)
      |> result.map_error(fn(_) {
        MissingOrInvalidSessionCookie(CookieSignatureInvalid)
      })
  }
}

/// Extract callback parameters from either query string (GET) or
/// form-encoded body (POST). For POST requests, body parameters are merged
/// over query parameters so body values take precedence.
fn get_callback_params(
  http_request: Request(Connection),
) -> Result(dict.Dict(String, String), CallbackError(e)) {
  let query_parameters = case http_request.query {
    option.Some(query) -> uri.parse_query(query) |> result.unwrap([])
    option.None -> []
  }
  case http_request.method {
    http.Post -> {
      use request_with_body <- result.try(
        mist.read_body(http_request, max_callback_body_bytes)
        |> result.replace_error(InvalidCallbackParams(BodyReadFailed)),
      )
      use body_string <- result.try(
        bit_array.to_string(request_with_body.body)
        |> result.replace_error(InvalidCallbackParams(BodyNotUtf8)),
      )
      use body_parameters <- result.try(
        uri.parse_query(body_string)
        |> result.replace_error(InvalidCallbackParams(BodyNotFormEncoded)),
      )
      Ok(dict.merge(
        dict.from_list(query_parameters),
        dict.from_list(body_parameters),
      ))
    }
    http.Get
    | http.Head
    | http.Put
    | http.Delete
    | http.Trace
    | http.Connect
    | http.Options
    | http.Patch
    | http.Other(_) -> Ok(dict.from_list(query_parameters))
  }
}

fn same_site_policy(same_site: CookieSameSite) -> cookie.SameSitePolicy {
  case same_site {
    Lax -> cookie.Lax
    CrossSite -> cookie.None
  }
}

fn secure_attribute(security: CookieSecurity) -> Bool {
  case security {
    SecureOnly -> True
    AllowInsecure -> False
  }
}

fn to_callback_error(
  flow_error: transport_flow.CallbackFlowError(e),
) -> CallbackError(e) {
  case flow_error {
    transport_flow.CallbackUnknownProvider(provider) ->
      UnknownProvider(provider)
    transport_flow.CallbackSessionUnavailable -> SessionUnavailable
    transport_flow.CallbackAuthFailed(authentication_error) ->
      AuthFailed(authentication_error)
  }
}

fn log_callback_error(
  provider: String,
  callback_error: CallbackError(e),
) -> Nil {
  let category = case callback_error {
    UnknownProvider(_) -> "unknown_provider"
    MissingOrInvalidSessionCookie(CookieAbsent) -> "session_cookie_absent"
    MissingOrInvalidSessionCookie(CookieSignatureInvalid) ->
      "session_cookie_signature_invalid"
    SessionUnavailable -> "session_unavailable"
    InvalidCallbackParams(_) -> "invalid_callback_params"
    AuthFailed(authentication_error) ->
      logger.auth_error_category(authentication_error)
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

fn callback_error_response(
  callback_error: CallbackError(e),
) -> Response(ResponseData) {
  case callback_error {
    UnknownProvider(_) -> not_found_response()
    MissingOrInvalidSessionCookie(_) -> generic_error_response()
    SessionUnavailable -> generic_error_response()
    InvalidCallbackParams(_) -> generic_error_response()
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
