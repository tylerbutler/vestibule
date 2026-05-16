//// Provider-strategy interface. A `Strategy(e)` is an opaque record
//// bundling the four functions every OAuth/OIDC provider must implement:
//// build authorize URL, exchange code, refresh token, and fetch user.
////
//// Provider packages (`vestibule_google`, `vestibule_apple`, ...) build
//// these with `strategy.new`; the core library invokes them through the
//// exposed accessors.

import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/http/request
import gleam/option.{type Option}
import gleam/string
import gleam/uri

import vestibule/config.{type Config}
import vestibule/credentials
import vestibule/error.{type AuthError}
import vestibule/user_info.{type UserInfo}

/// Normalized user details returned by a strategy.
///
/// Opaque so that new fields can be added without breaking strategy
/// implementations. Construct with `user_result` and read with the
/// `uid` / `info` / `extra` accessors.
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
    credentials: credentials.Credentials,
    artifacts: Dict(String, Dynamic),
  )
}

/// Build an exchange result for providers with no provider-specific artifacts.
pub fn exchange_result(credentials: credentials.Credentials) -> ExchangeResult {
  ExchangeResult(credentials: credentials, artifacts: dict.new())
}

/// Build an exchange result with provider-specific artifacts.
pub fn exchange_result_with_artifacts(
  credentials: credentials.Credentials,
  artifacts: Dict(String, Dynamic),
) -> ExchangeResult {
  ExchangeResult(credentials: credentials, artifacts: artifacts)
}

/// Return the OAuth credentials produced by the exchange.
pub fn exchange_credentials(
  exchange: ExchangeResult,
) -> credentials.Credentials {
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
/// Opaque so that vestibule can add fields (or swap the internal
/// representation, e.g., to an injectable HTTP client) without breaking
/// provider packages. Construct with `new` and invoke with the
/// `build_authorize_url`, `exchange_code`, `refresh_token`, and
/// `fetch_user` helpers.
pub opaque type Strategy(e) {
  Strategy(
    provider: String,
    default_scopes: List(String),
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError(e)),
    exchange_code: fn(Config, String, Option(String)) ->
      Result(ExchangeResult, AuthError(e)),
    refresh_token: fn(Config, String) ->
      Result(credentials.Credentials, AuthError(e)),
    fetch_user: fn(Config, ExchangeResult) -> Result(UserResult, AuthError(e)),
  )
}

/// Build a `Strategy`.
///
/// `authorize_url` builds the provider-specific authorization URL.
/// `exchange_code` exchanges an authorization code for credentials and
/// optional provider-specific artifacts; the third parameter is the PKCE
/// `code_verifier` if one was generated. `refresh_token` swaps a refresh
/// token for fresh credentials. `fetch_user` resolves the authenticated
/// user from the exchange result.
pub fn new(
  provider provider: String,
  default_scopes default_scopes: List(String),
  authorize_url authorize_url: fn(Config, List(String), String) ->
    Result(String, AuthError(e)),
  exchange_code exchange_code: fn(Config, String, Option(String)) ->
    Result(ExchangeResult, AuthError(e)),
  refresh_token refresh_token: fn(Config, String) ->
    Result(credentials.Credentials, AuthError(e)),
  fetch_user fetch_user: fn(Config, ExchangeResult) ->
    Result(UserResult, AuthError(e)),
) -> Strategy(e) {
  Strategy(
    provider: provider,
    default_scopes: default_scopes,
    authorize_url: authorize_url,
    exchange_code: exchange_code,
    refresh_token: refresh_token,
    fetch_user: fetch_user,
  )
}

/// Return the human-readable provider name (e.g., `"github"`, `"google"`).
pub fn provider(strat: Strategy(e)) -> String {
  strat.provider
}

/// Return the strategy's default scopes, used when the caller's
/// `Config` does not specify any.
pub fn default_scopes(strat: Strategy(e)) -> List(String) {
  strat.default_scopes
}

/// Build the provider's authorization URL.
pub fn build_authorize_url(
  strat: Strategy(e),
  cfg: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  strat.authorize_url(cfg, scopes, state)
}

/// Exchange an authorization code for credentials and any provider-specific
/// artifacts. Pass the PKCE `code_verifier` if one was generated for the
/// authorization request.
pub fn exchange_code(
  strat: Strategy(e),
  cfg: Config,
  code: String,
  code_verifier: Option(String),
) -> Result(ExchangeResult, AuthError(e)) {
  strat.exchange_code(cfg, code, code_verifier)
}

/// Refresh credentials using a refresh token.
pub fn refresh_token(
  strat: Strategy(e),
  cfg: Config,
  refresh_tok: String,
) -> Result(credentials.Credentials, AuthError(e)) {
  strat.refresh_token(cfg, refresh_tok)
}

/// Fetch user info using the obtained exchange result.
pub fn fetch_user(
  strat: Strategy(e),
  cfg: Config,
  exchange: ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  strat.fetch_user(cfg, exchange)
}

/// Build the Authorization header value from credentials.
///
/// Uses the `token_type` from the credentials (e.g., "Bearer", "bearer").
/// Strategy implementations should use this instead of hardcoding `"Bearer "`.
///
/// Returns `Error` if the token type is not "bearer" (case-insensitive),
/// as vestibule only supports Bearer token authentication.
pub fn authorization_header(
  credentials creds: credentials.Credentials,
) -> Result(String, AuthError(e)) {
  case string.lowercase(credentials.token_type(creds)) {
    "bearer" -> Ok("Bearer " <> credentials.token(creds))
    other ->
      Error(error.ConfigError(
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
  req: request.Request(String),
  code_verifier: Option(String),
) -> request.Request(String) {
  case code_verifier {
    option.Some(verifier) -> {
      let verifier_param = uri.query_to_string([#("code_verifier", verifier)])
      let body = case req.body {
        "" -> verifier_param
        existing -> existing <> "&" <> verifier_param
      }
      request.set_body(req, body)
    }
    option.None -> req
  }
}
