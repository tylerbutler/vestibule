//// Provider-strategy interface. A `Strategy(e)` is an opaque record
//// bundling the provider-specific functions an OAuth/OIDC provider
//// implements: build authorize URL, exchange code, fetch user, and an
//// optional refresh token.
////
//// Provider packages (`vestibule_google`, `vestibule_apple`, ...) build
//// these with `strategy.new` plus the `with_*` capability builders; the
//// core library invokes them through the exposed accessors.

import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/http/request
import gleam/option.{type Option}
import gleam/string
import gleam/uri

import vestibule/config.{type AuthorizeOptions, type ClientConfig}
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
/// Opaque so that vestibule can add optional capabilities without breaking
/// provider packages. Construct with `new` and attach capabilities with the
/// `with_authorize_url`, `with_exchange_code`, `with_fetch_user`,
/// `with_refresh`, and `with_nonce` builders. Invoke through the
/// `build_authorize_url`, `exchange_code`, `refresh_token`, and `fetch_user`
/// helpers.
///
/// The core capabilities (`authorize_url`, `exchange_code`, `fetch_user`) are
/// stored as `Option`; invoking one that was never configured fails with a
/// an AuthError of kind `ConfigKind`. `refresh_token` is optional: a strategy
/// built without `with_refresh` fails with an AuthError of kind
/// `RefreshUnsupportedKind`.
pub opaque type Strategy(e) {
  Strategy(
    provider: String,
    default_scopes: List(String),
    uses_nonce: Bool,
    authorize_url: Option(
      fn(ClientConfig, AuthorizeOptions, List(String), String) ->
        Result(String, AuthError(e)),
    ),
    exchange_code: Option(
      fn(ClientConfig, String, Option(String)) ->
        Result(ExchangeResult, AuthError(e)),
    ),
    refresh_token: Option(
      fn(ClientConfig, String) -> Result(credentials.Credentials, AuthError(e)),
    ),
    fetch_user: Option(
      fn(ClientConfig, ExchangeResult) -> Result(UserResult, AuthError(e)),
    ),
  )
}

/// Begin building a `Strategy` for `provider` with the given `default_scopes`
/// (used when the caller's `AuthorizeOptions` does not specify any).
///
/// The returned strategy has no capabilities attached yet. Use the `with_*`
/// builders to add them:
///
/// ```gleam
/// strategy.new(provider: "github", default_scopes: ["user:email"])
/// |> strategy.with_authorize_url(do_authorize_url)
/// |> strategy.with_exchange_code(do_exchange_code)
/// |> strategy.with_fetch_user(do_fetch_user)
/// |> strategy.with_refresh(do_refresh_token)
/// ```
pub fn new(
  provider provider: String,
  default_scopes default_scopes: List(String),
) -> Strategy(e) {
  Strategy(
    provider: provider,
    default_scopes: default_scopes,
    uses_nonce: False,
    authorize_url: option.None,
    exchange_code: option.None,
    refresh_token: option.None,
    fetch_user: option.None,
  )
}

/// Attach the authorize-URL builder. `authorize_url` builds the
/// provider-specific authorization URL from the config, scopes, and state.
pub fn with_authorize_url(
  strat: Strategy(e),
  authorize_url: fn(ClientConfig, AuthorizeOptions, List(String), String) ->
    Result(String, AuthError(e)),
) -> Strategy(e) {
  Strategy(..strat, authorize_url: option.Some(authorize_url))
}

/// Attach the code-exchange capability. `exchange_code` exchanges an
/// authorization code for credentials and optional provider-specific
/// artifacts; the third parameter is the PKCE `code_verifier` if one was
/// generated.
pub fn with_exchange_code(
  strat: Strategy(e),
  exchange_code: fn(ClientConfig, String, Option(String)) ->
    Result(ExchangeResult, AuthError(e)),
) -> Strategy(e) {
  Strategy(..strat, exchange_code: option.Some(exchange_code))
}

/// Attach the user-resolution capability. `fetch_user` resolves the
/// authenticated user from the exchange result.
pub fn with_fetch_user(
  strat: Strategy(e),
  fetch_user: fn(ClientConfig, ExchangeResult) ->
    Result(UserResult, AuthError(e)),
) -> Strategy(e) {
  Strategy(..strat, fetch_user: option.Some(fetch_user))
}

/// Attach an optional token-refresh capability. `refresh_token` swaps a
/// refresh token for fresh credentials. Strategies built without this fail
/// `refresh_token` with an AuthError of kind `RefreshUnsupportedKind`.
pub fn with_refresh(
  strat: Strategy(e),
  refresh_token: fn(ClientConfig, String) ->
    Result(credentials.Credentials, AuthError(e)),
) -> Strategy(e) {
  Strategy(..strat, refresh_token: option.Some(refresh_token))
}

/// Mark this strategy as using the OIDC `nonce`. The core will then generate
/// an OIDC `nonce`, emit it on the authorize URL, and validate it against the
/// `id_token` on callback. Plain OAuth2 strategies should omit this.
pub fn with_nonce(strat: Strategy(e)) -> Strategy(e) {
  Strategy(..strat, uses_nonce: True)
}

/// Return the human-readable provider name (e.g., `"github"`, `"google"`).
pub fn provider(strat: Strategy(e)) -> String {
  strat.provider
}

/// Whether this strategy uses the OIDC `nonce` (generate + validate).
pub fn uses_nonce(strat: Strategy(e)) -> Bool {
  strat.uses_nonce
}

/// Return the strategy's default scopes, used when the caller's
/// `AuthorizeOptions` does not specify any.
pub fn default_scopes(strat: Strategy(e)) -> List(String) {
  strat.default_scopes
}

/// Build the provider's authorization URL.
///
/// Returns an AuthError of kind `ConfigKind` if the strategy was built without
/// `with_authorize_url`.
pub fn build_authorize_url(
  strat: Strategy(e),
  cfg cfg: ClientConfig,
  options options: AuthorizeOptions,
  scopes scopes: List(String),
  state state: String,
) -> Result(String, AuthError(e)) {
  case strat.authorize_url {
    option.Some(authorize_url) -> authorize_url(cfg, options, scopes, state)
    option.None ->
      Error(error.config(
        reason: "Strategy \""
        <> strat.provider
        <> "\" has no authorize_url capability (missing with_authorize_url).",
      ))
  }
}

/// Exchange an authorization code for credentials and any provider-specific
/// artifacts. Pass the PKCE `code_verifier` if one was generated for the
/// authorization request.
///
/// Returns an AuthError of kind `ConfigKind` if the strategy was built without
/// `with_exchange_code`.
pub fn exchange_code(
  strat: Strategy(e),
  cfg cfg: ClientConfig,
  code code: String,
  code_verifier code_verifier: Option(String),
) -> Result(ExchangeResult, AuthError(e)) {
  case strat.exchange_code {
    option.Some(exchange_code) -> exchange_code(cfg, code, code_verifier)
    option.None ->
      Error(error.config(
        reason: "Strategy \""
        <> strat.provider
        <> "\" has no exchange_code capability (missing with_exchange_code).",
      ))
  }
}

/// Refresh credentials using a refresh token.
///
/// Returns an AuthError of kind `RefreshUnsupportedKind` if the strategy was built without
/// `with_refresh`.
pub fn refresh_token(
  strat: Strategy(e),
  cfg cfg: ClientConfig,
  refresh_tok refresh_tok: String,
) -> Result(credentials.Credentials, AuthError(e)) {
  case strat.refresh_token {
    option.Some(refresh_token) -> refresh_token(cfg, refresh_tok)
    option.None -> Error(error.refresh_unsupported())
  }
}

/// Fetch user info using the obtained exchange result.
///
/// Returns an AuthError of kind `ConfigKind` if the strategy was built without
/// `with_fetch_user`.
pub fn fetch_user(
  strat: Strategy(e),
  cfg cfg: ClientConfig,
  exchange exchange: ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  case strat.fetch_user {
    option.Some(fetch_user) -> fetch_user(cfg, exchange)
    option.None ->
      Error(error.config(
        reason: "Strategy \""
        <> strat.provider
        <> "\" has no fetch_user capability (missing with_fetch_user).",
      ))
  }
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
