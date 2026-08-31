//// Provider-strategy interface. A `Strategy(e)` is an opaque record
//// bundling the provider-specific functions an OAuth/OIDC provider
//// implements: build authorize URL, exchange code, fetch user, and an
//// optional refresh token.
////
//// Provider packages (`vestibule_google`, `vestibule_apple`, ...) build
//// these with `strategy.new`, which takes the three required capabilities
//// directly, plus the optional `with_refresh` and `with_nonce` builders;
//// the core library invokes them through the exposed accessors.

import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/http/request
import gleam/option.{type Option}
import gleam/string
import gleam/uri

import vestibule/config.{type AuthorizeOptions, type ClientConfig}
import vestibule/credential
import vestibule/error.{type AuthError}
import vestibule/user_info.{type UserInfo}

/// Normalized user details returned by a strategy.
///
/// Opaque so that new fields can be added without breaking strategy
/// implementations. Construct with `user_result` and read with the
/// `user_result_uid`, `user_result_info`, and `user_result_extra` accessors.
pub opaque type UserResult {
  UserResult(uid: String, info: UserInfo, extra: Dict(String, Dynamic))
}

/// Build a `UserResult`.
pub fn user_result(
  uid uid: String,
  info info: UserInfo,
  extra extra: Dict(String, Dynamic),
) -> UserResult {
  UserResult(uid: uid, info: info, extra: extra)
}

/// Return the provider's unique user id.
pub fn user_result_uid(user: UserResult) -> String {
  user.uid
}

/// Return the normalized user info.
pub fn user_result_info(user: UserResult) -> UserInfo {
  user.info
}

/// Return provider-specific extra fields associated with the user.
pub fn user_result_extra(user: UserResult) -> Dict(String, Dynamic) {
  user.extra
}

/// The result of exchanging an authorization code.
///
/// `credentials` contains the standard OAuth credentials. `artifacts` contains
/// provider-specific token response data that may be needed while resolving the
/// user, such as an OpenID Connect `id_token`.
///
/// Opaque to keep provider-specific artifacts evolution-safe.
pub opaque type ExchangeResult {
  ExchangeResult(
    credentials: credential.Credentials,
    artifacts: Dict(String, Dynamic),
  )
}

/// Build an exchange result for providers with no provider-specific artifacts.
pub fn exchange_result(credentials: credential.Credentials) -> ExchangeResult {
  ExchangeResult(credentials: credentials, artifacts: dict.new())
}

/// Build an exchange result with provider-specific artifacts.
pub fn exchange_result_with_artifacts(
  credentials: credential.Credentials,
  artifacts: Dict(String, Dynamic),
) -> ExchangeResult {
  ExchangeResult(credentials: credentials, artifacts: artifacts)
}

/// Return the OAuth credentials produced by the exchange.
pub fn exchange_credentials(
  exchange: ExchangeResult,
) -> credential.Credentials {
  exchange.credentials
}

/// Return provider-specific artifacts produced by the exchange
/// (e.g., an OpenID Connect `id_token`).
pub fn exchange_artifacts(exchange: ExchangeResult) -> Dict(String, Dynamic) {
  exchange.artifacts
}

/// A strategy is the bundle of provider-specific functions needed to
/// authenticate with a single OAuth/OIDC provider.
///
/// The type parameter `e` corresponds to the custom error type in
/// `AuthError(e)`. Built-in strategies are polymorphic in `e`.
///
/// Opaque so that vestibule can add optional capabilities without breaking
/// provider packages. Construct with `new`, which requires the three core
/// capabilities (`authorize_url`, `exchange_code`, `fetch_user`) so that a
/// strategy unable to complete an authentication flow cannot be built.
/// Attach optional capabilities with the `with_refresh` and `with_nonce`
/// builders. Invoke through the `build_authorize_url`, `exchange_code`,
/// `refresh_token`, and `fetch_user` helpers.
///
/// `refresh_token` is optional: a strategy built without `with_refresh` fails
/// `refresh_token` with an AuthError of kind `RefreshUnsupportedKind`.
pub opaque type Strategy(e) {
  Strategy(
    provider: String,
    default_scopes: List(String),
    uses_nonce: Bool,
    authorize_url: fn(ClientConfig, AuthorizeOptions, List(String), String) ->
      Result(String, AuthError(e)),
    exchange_code: fn(ClientConfig, String, Option(String)) ->
      Result(ExchangeResult, AuthError(e)),
    refresh_token: Option(
      fn(ClientConfig, String) -> Result(credential.Credentials, AuthError(e)),
    ),
    fetch_user: fn(ClientConfig, ExchangeResult) ->
      Result(UserResult, AuthError(e)),
  )
}

/// Build a `Strategy` for `provider`.
///
/// `default_scopes` is used when the caller's `AuthorizeOptions` does not
/// specify any scopes. The three core capabilities are required:
///
/// - `authorize_url` builds the provider-specific authorization URL from the
///   config, options, scopes, and state.
/// - `exchange_code` exchanges an authorization code for credentials and
///   optional provider-specific artifacts; the third parameter is the PKCE
///   `code_verifier` if one was generated.
/// - `fetch_user` resolves the authenticated user from the exchange result.
///
/// Attach optional capabilities with the `with_*` builders:
///
/// ```gleam
/// strategy.new(
///   provider: "github",
///   default_scopes: ["user:email"],
///   authorize_url: do_authorize_url,
///   exchange_code: do_exchange_code,
///   fetch_user: do_fetch_user,
/// )
/// |> strategy.with_refresh(do_refresh_token)
/// ```
pub fn new(
  provider provider: String,
  default_scopes default_scopes: List(String),
  authorize_url authorize_url: fn(
    ClientConfig,
    AuthorizeOptions,
    List(String),
    String,
  ) -> Result(String, AuthError(e)),
  exchange_code exchange_code: fn(ClientConfig, String, Option(String)) ->
    Result(ExchangeResult, AuthError(e)),
  fetch_user fetch_user: fn(ClientConfig, ExchangeResult) ->
    Result(UserResult, AuthError(e)),
) -> Strategy(e) {
  Strategy(
    provider: provider,
    default_scopes: default_scopes,
    uses_nonce: False,
    authorize_url: authorize_url,
    exchange_code: exchange_code,
    refresh_token: option.None,
    fetch_user: fetch_user,
  )
}

/// Attach an optional token-refresh capability. `refresh_token` swaps a
/// refresh token for fresh credentials. Strategies built without this fail
/// `refresh_token` with an AuthError of kind `RefreshUnsupportedKind`.
pub fn with_refresh(
  strategy: Strategy(e),
  refresh_token: fn(ClientConfig, String) ->
    Result(credential.Credentials, AuthError(e)),
) -> Strategy(e) {
  Strategy(..strategy, refresh_token: option.Some(refresh_token))
}

/// Mark this strategy as using the OIDC `nonce`. The core will then generate
/// an OIDC `nonce`, emit it on the authorize URL, and validate it against the
/// `id_token` on callback. Plain OAuth2 strategies should omit this.
pub fn with_nonce(strategy: Strategy(e)) -> Strategy(e) {
  Strategy(..strategy, uses_nonce: True)
}

/// Return the human-readable provider name (e.g., `"github"`, `"google"`).
pub fn provider(strategy: Strategy(e)) -> String {
  strategy.provider
}

/// Whether this strategy uses the OIDC `nonce` (generate + validate).
pub fn uses_nonce(strategy: Strategy(e)) -> Bool {
  strategy.uses_nonce
}

/// Return the strategy's default scopes, used when the caller's
/// `AuthorizeOptions` does not specify any.
pub fn default_scopes(strategy: Strategy(e)) -> List(String) {
  strategy.default_scopes
}

/// Build the provider's authorization URL.
pub fn build_authorize_url(
  strategy: Strategy(e),
  config config: ClientConfig,
  options options: AuthorizeOptions,
  scopes scopes: List(String),
  state state: String,
) -> Result(String, AuthError(e)) {
  strategy.authorize_url(config, options, scopes, state)
}

/// Exchange an authorization code for credentials and any provider-specific
/// artifacts. Pass the PKCE `code_verifier` if one was generated for the
/// authorization request.
pub fn exchange_code(
  strategy: Strategy(e),
  config config: ClientConfig,
  code code: String,
  code_verifier code_verifier: Option(String),
) -> Result(ExchangeResult, AuthError(e)) {
  strategy.exchange_code(config, code, code_verifier)
}

/// Refresh credentials using a refresh token.
///
/// Returns an AuthError of kind `RefreshUnsupportedKind` if the strategy was
/// built without `with_refresh`.
pub fn refresh_token(
  strategy: Strategy(e),
  config config: ClientConfig,
  refresh_token refresh_token: String,
) -> Result(credential.Credentials, AuthError(e)) {
  case strategy.refresh_token {
    option.Some(refresh) -> refresh(config, refresh_token)
    option.None -> Error(error.refresh_unsupported())
  }
}

/// Fetch user info using the obtained exchange result.
pub fn fetch_user(
  strategy: Strategy(e),
  config config: ClientConfig,
  exchange exchange: ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  strategy.fetch_user(config, exchange)
}

/// Build the Authorization header value from credentials.
///
/// Uses the `token_type` from the credentials (e.g., "Bearer", "bearer").
/// Strategy implementations should use this instead of hardcoding `"Bearer "`.
///
/// Returns `Error` if the token type is not "bearer" (case-insensitive),
/// as vestibule only supports Bearer token authentication.
pub fn authorization_header(
  credentials credentials: credential.Credentials,
) -> Result(String, AuthError(e)) {
  case string.lowercase(credential.token_type(credentials)) {
    "bearer" -> {
      let token = credential.token(credentials)
      case
        string.contains(token, "\r")
        || string.contains(token, "\n")
        || string.contains(token, "\u{0000}")
      {
        True ->
          Error(error.config(
            reason: "Access token contains invalid HTTP header characters",
          ))
        False -> Ok("Bearer " <> token)
      }
    }
    other ->
      Error(error.config(
        reason: "Unsupported token type: "
        <> other
        <> ". Only Bearer tokens are supported.",
      ))
  }
}

/// Append a PKCE code_verifier to a form-encoded request body when present.
///
/// Strategy implementations should call this after building the token
/// exchange request to include the PKCE verifier parameter.
pub fn append_code_verifier(
  http_request: request.Request(String),
  code_verifier: Option(String),
) -> request.Request(String) {
  case code_verifier {
    option.Some(verifier) -> {
      let verifier_parameter =
        uri.query_to_string([#("code_verifier", verifier)])
      let body = case http_request.body {
        "" -> verifier_parameter
        existing -> existing <> "&" <> verifier_parameter
      }
      request.set_body(http_request, body)
    }
    option.None -> http_request
  }
}
