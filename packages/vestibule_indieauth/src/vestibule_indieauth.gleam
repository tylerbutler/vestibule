/// IndieAuth strategy for vestibule — decentralized identity via OAuth 2.0.
///
/// IndieAuth is an identity layer on top of OAuth 2.0 where users are identified
/// by a URL they control. Endpoints are discovered dynamically from the user's
/// homepage rather than being statically configured.
///
/// ## Usage
///
/// ```gleam
/// // Discover the user's IndieAuth endpoints
/// let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")
///
/// // Use with vestibule's standard two-phase flow
/// let options = config.authorize_options()
/// let assert Ok(auth_request) =
///   vestibule.create_authorization_request(strategy, config: client_config, options: options)
/// ```
///
/// ## Discovery
///
/// The `discover` function fetches the user's homepage and finds their
/// authorization and token endpoints using a three-tier fallback:
///
/// 1. IndieAuth server metadata (`rel="indieauth-metadata"` → JSON document)
/// 2. Direct link relations (`rel="authorization_endpoint"`, `rel="token_endpoint"`)
/// 3. Falls back from HTTP `Link` headers to HTML `<link>` tags at each tier
import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

import vestibule/config.{type AuthorizeOptions, type ClientConfig}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, type UserResult}
import vestibule/user_info

import vestibule_indieauth/discovery.{
  type DiscoveredEndpoints, DiscoveredEndpoints,
}
import vestibule_indieauth/token
import vestibule_indieauth/url

/// Discover IndieAuth endpoints from a user's profile URL and return
/// a configured Strategy.
///
/// This performs the full discovery flow:
/// 1. Validates and canonicalizes the user URL
/// 2. Fetches the URL and follows redirects
/// 3. Discovers authorization and token endpoints
/// 4. Returns a `Strategy(e)` ready for use with `vestibule.create_authorization_request`
///
/// ## Example
///
/// ```gleam
/// let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")
/// let client_config =
///   config.new(
///     client_id: "https://myapp.com/",
///     redirect_uri: "https://myapp.com/callback",
///     auth: config.PublicClient,
///   )
/// let options = config.authorize_options()
/// let assert Ok(auth_request) =
///   vestibule.create_authorization_request(strategy, config: client_config, options: options)
/// ```
pub fn discover(user_url: String) -> Result(Strategy(e), AuthError(e)) {
  use canonical_url <- result.try(url.validate_profile_url(user_url))
  use endpoints <- result.try(discovery.discover_endpoints(canonical_url))
  Ok(strategy(endpoints, canonical_url))
}

/// Discover IndieAuth endpoints without creating a strategy.
///
/// Useful when you want to inspect the discovered endpoints before
/// creating a strategy, or need to store them for later use.
pub fn discover_endpoints(
  user_url: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  use canonical_url <- result.try(url.validate_profile_url(user_url))
  discovery.discover_endpoints(canonical_url)
}

/// Discover IndieAuth endpoints and return them together with the canonical
/// `me` URL.
///
/// IndieAuth's two-phase flow needs both the discovered endpoints and the
/// canonical profile URL again at callback time, but `discover` returns only a
/// `Strategy` and `discover_endpoints` returns only the endpoints. This helper
/// performs validation + discovery once and hands back both, so callers don't
/// have to reach into the `url` and `discovery` submodules themselves.
///
/// Pair it with `serialize_endpoints` / `parse_endpoints` to carry the result
/// across the request→callback boundary (e.g. in a signed cookie), then rebuild
/// the strategy with `strategy(endpoints, me)`.
///
/// ## Example
///
/// ```gleam
/// let assert Ok(#(endpoints, me)) =
///   vestibule_indieauth.discover_endpoints_with_me("https://user.example.com")
/// let strategy = vestibule_indieauth.strategy(endpoints, me)
/// ```
pub fn discover_endpoints_with_me(
  user_url: String,
) -> Result(#(DiscoveredEndpoints, String), AuthError(e)) {
  use me <- result.try(url.validate_profile_url(user_url))
  use endpoints <- result.try(discovery.discover_endpoints(me))
  Ok(#(endpoints, me))
}

/// Serialize discovered endpoints + the canonical `me` URL to a compact JSON
/// string.
///
/// IndieAuth strategies are discovered per-user at request time, but the
/// transport-independent flow needs the same endpoints again in the callback
/// phase. Persist this string (for example in a signed cookie or server-side
/// session) during the request phase and restore it with `parse_endpoints` in
/// the callback phase to rebuild the strategy via `strategy(endpoints, me)` —
/// no second discovery round-trip required.
pub fn serialize_endpoints(
  endpoints: DiscoveredEndpoints,
  me: String,
) -> String {
  json.object([
    #("me", json.string(me)),
    #("authorization_endpoint", json.string(endpoints.authorization_endpoint)),
    #("token_endpoint", json.string(endpoints.token_endpoint)),
    #("issuer", json.nullable(endpoints.issuer, json.string)),
    #(
      "userinfo_endpoint",
      json.nullable(endpoints.userinfo_endpoint, json.string),
    ),
  ])
  |> json.to_string
}

/// Parse a string produced by `serialize_endpoints` back into the discovered
/// endpoints and the canonical `me` URL.
///
/// Returns `Error(error.config(..))` if the value is missing fields or is
/// not the JSON produced by `serialize_endpoints`.
pub fn parse_endpoints(
  value: String,
) -> Result(#(DiscoveredEndpoints, String), AuthError(e)) {
  let decoder = {
    use me <- decode.field("me", decode.string)
    use authorization_endpoint <- decode.field(
      "authorization_endpoint",
      decode.string,
    )
    use token_endpoint <- decode.field("token_endpoint", decode.string)
    use issuer <- decode.field("issuer", decode.optional(decode.string))
    use userinfo_endpoint <- decode.field(
      "userinfo_endpoint",
      decode.optional(decode.string),
    )
    decode.success(#(
      DiscoveredEndpoints(
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        issuer: issuer,
        userinfo_endpoint: userinfo_endpoint,
      ),
      me,
    ))
  }
  json.parse(value, decoder)
  |> result.replace_error(error.config(
    reason: "Failed to parse serialized IndieAuth endpoints",
  ))
}

/// Create a strategy from previously discovered endpoints.
///
/// Use this with `discover_endpoints` when you want to separate
/// discovery from strategy creation.
pub fn strategy(endpoints: DiscoveredEndpoints, me: String) -> Strategy(e) {
  strategy.new(
    provider: "indieauth",
    default_scopes: ["profile"],
    authorize_url: fn(cfg, options, scopes, state) {
      do_authorize_url(endpoints, me, cfg, options, scopes, state)
    },
    exchange_code: fn(cfg, code, code_verifier) {
      do_exchange_code(endpoints, cfg, code, code_verifier)
    },
    fetch_user: fn(_cfg, exchange) { do_fetch_user(endpoints, me, exchange) },
  )
  |> strategy.with_refresh(fn(cfg, refresh_tok) {
    do_refresh_token(endpoints, cfg, refresh_tok)
  })
}

fn do_authorize_url(
  endpoints: DiscoveredEndpoints,
  me: String,
  cfg: ClientConfig,
  options: AuthorizeOptions,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  let scope = string.join(scopes, " ")
  let extra_params = config.extra_params(options)
  case dict.get(extra_params, "me") {
    Ok(_) ->
      Error(error.config(
        reason: "Reserved authorization parameter not allowed: me",
      ))
    Error(Nil) ->
      build_authorize_url(endpoints, me, cfg, scope, state, extra_params)
  }
}

fn build_authorize_url(
  endpoints: DiscoveredEndpoints,
  me: String,
  cfg: ClientConfig,
  scope: String,
  state: String,
  extra_params: dict.Dict(String, String),
) -> Result(String, AuthError(e)) {
  let params = [
    #("response_type", "code"),
    #("client_id", config.client_id(cfg)),
    #("redirect_uri", config.redirect_uri(cfg)),
    #("state", state),
    #("scope", scope),
    #("me", me),
    ..dict.to_list(extra_params)
  ]
  let query =
    params
    |> uri.query_to_string()
  let separator = case string.contains(endpoints.authorization_endpoint, "?") {
    True -> "&"
    False -> "?"
  }
  Ok(endpoints.authorization_endpoint <> separator <> query)
}

fn do_exchange_code(
  endpoints: DiscoveredEndpoints,
  cfg: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  token.exchange_code(
    endpoints.token_endpoint,
    config.client_id(cfg),
    config.redirect_uri(cfg),
    code,
    code_verifier,
  )
  |> result.map(strategy.exchange_result)
}

fn do_refresh_token(
  endpoints: DiscoveredEndpoints,
  cfg: ClientConfig,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  token.refresh(endpoints.token_endpoint, config.client_id(cfg), refresh_tok)
}

fn do_fetch_user(
  endpoints: DiscoveredEndpoints,
  me: String,
  exchange: strategy.ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  let creds = strategy.exchange_credentials(exchange)
  // IndieAuth returns profile info in the token response, so we
  // store it on the credentials. If the token endpoint returned
  // profile info, we already have it. For IndieAuth, the uid is
  // the canonical "me" URL.
  //
  // If a userinfo_endpoint was discovered, fetch from it.
  // Otherwise, return minimal info with the me URL as identity.
  case endpoints.userinfo_endpoint {
    Some(userinfo_url) -> {
      use #(uid, info) <- result.try(token.fetch_userinfo(userinfo_url, creds))
      Ok(strategy.user_result(uid: uid, info: info, extra: dict.new()))
    }
    None ->
      // Return minimal user info — the me URL is the identity
      Ok(strategy.user_result(
        uid: me,
        info: user_info.new()
          |> user_info.with_urls(dict.from_list([#("url", me)])),
        extra: dict.new(),
      ))
  }
}
