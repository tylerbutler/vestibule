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
/// let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
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
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info

import vestibule_indieauth/discovery.{type DiscoveredEndpoints}
import vestibule_indieauth/token
import vestibule_indieauth/url

/// Discover IndieAuth endpoints from a user's profile URL and return
/// a configured Strategy.
///
/// This performs the full discovery flow:
/// 1. Validates and canonicalizes the user URL
/// 2. Fetches the URL and follows redirects
/// 3. Discovers authorization and token endpoints
/// 4. Returns a `Strategy(e)` ready for use with `vestibule.authorize_url`
///
/// ## Example
///
/// ```gleam
/// let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")
/// let cfg = config.new("https://myapp.com/", "", "https://myapp.com/callback")
/// let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
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

/// Create a strategy from previously discovered endpoints.
///
/// Use this with `discover_endpoints` when you want to separate
/// discovery from strategy creation.
pub fn strategy(endpoints: DiscoveredEndpoints, me: String) -> Strategy(e) {
  Strategy(
    provider: "indieauth",
    default_scopes: ["profile"],
    token_url: endpoints.token_endpoint,
    authorize_url: fn(cfg, scopes, state) {
      do_authorize_url(endpoints, me, cfg, scopes, state)
    },
    exchange_code: fn(cfg, code, code_verifier) {
      do_exchange_code(endpoints, cfg, code, code_verifier)
    },
    fetch_user: fn(creds) { do_fetch_user(endpoints, me, creds) },
  )
}

fn do_authorize_url(
  endpoints: DiscoveredEndpoints,
  me: String,
  cfg: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  let scope = string.join(scopes, " ")
  let params = [
    #("response_type", "code"),
    #("client_id", config.client_id(cfg)),
    #("redirect_uri", config.redirect_uri(cfg)),
    #("state", state),
    #("scope", scope),
    #("me", me),
  ]
  let query =
    params
    |> url.encode_query_params()
  let separator = case string.contains(endpoints.authorization_endpoint, "?") {
    True -> "&"
    False -> "?"
  }
  Ok(endpoints.authorization_endpoint <> separator <> query)
}

fn do_exchange_code(
  endpoints: DiscoveredEndpoints,
  cfg: Config,
  code: String,
  code_verifier: Option(String),
) -> Result(Credentials, AuthError(e)) {
  token.exchange_code(
    endpoints.token_endpoint,
    config.client_id(cfg),
    config.redirect_uri(cfg),
    code,
    code_verifier,
  )
}

fn do_fetch_user(
  endpoints: DiscoveredEndpoints,
  me: String,
  creds: Credentials,
) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
  // IndieAuth returns profile info in the token response, so we
  // store it on the credentials. If the token endpoint returned
  // profile info, we already have it. For IndieAuth, the uid is
  // the canonical "me" URL.
  //
  // If a userinfo_endpoint was discovered, fetch from it.
  // Otherwise, return minimal info with the me URL as identity.
  case endpoints.userinfo_endpoint {
    Some(userinfo_url) -> token.fetch_userinfo(userinfo_url, creds)
    None -> {
      // Return minimal user info — the me URL is the identity
      Ok(#(
        me,
        user_info.UserInfo(
          name: None,
          email: None,
          nickname: None,
          image: None,
          description: None,
          urls: dict.from_list([#("url", me)]),
        ),
      ))
    }
  }
}
