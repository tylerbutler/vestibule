//// OpenID Connect Discovery support for auto-configuring strategies.
////
//// This module implements [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
//// to automatically fetch provider configuration from a well-known endpoint
//// and build a `Strategy` from the discovered endpoints.
////
//// ## Usage
////
//// ```gleam
//// // Auto-discover and create a strategy in one step:
//// let assert Ok(strategy) = oidc.discover("https://accounts.google.com")
////
//// // Or fetch configuration separately for inspection:
//// let assert Ok(config) = oidc.fetch_configuration("https://accounts.google.com")
//// let strategy = oidc.strategy_from_config(config, "my-provider")
//// ```

import gleam/dict
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri

import vestibule/config
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/provider_support
import vestibule/strategy.{type Strategy, type UserResult, Strategy, UserResult}
import vestibule/user_info

/// Configuration discovered from an OpenID Connect provider's
/// `/.well-known/openid-configuration` endpoint.
pub opaque type OidcConfig {
  OidcConfig(
    /// The issuer identifier (must match the URL used for discovery).
    issuer: String,
    /// The authorization endpoint URL.
    authorization_endpoint: String,
    /// The token endpoint URL.
    token_endpoint: String,
    /// The userinfo endpoint URL.
    userinfo_endpoint: String,
    /// Scopes supported by this provider.
    scopes_supported: List(String),
  )
}

/// Construct a validated OIDC configuration.
///
/// The issuer and endpoint URLs must use HTTPS, except for localhost URLs
/// which are allowed for local development.
pub fn new_config(
  issuer issuer: String,
  authorization_endpoint authorization_endpoint: String,
  token_endpoint token_endpoint: String,
  userinfo_endpoint userinfo_endpoint: String,
  scopes_supported scopes_supported: List(String),
) -> Result(OidcConfig, AuthError(e)) {
  use _ <- result.try(provider_support.require_https(issuer))
  use _ <- result.try(provider_support.require_https(authorization_endpoint))
  use _ <- result.try(provider_support.require_https(token_endpoint))
  use _ <- result.try(provider_support.require_https(userinfo_endpoint))

  Ok(OidcConfig(
    issuer: issuer,
    authorization_endpoint: authorization_endpoint,
    token_endpoint: token_endpoint,
    userinfo_endpoint: userinfo_endpoint,
    scopes_supported: scopes_supported,
  ))
}

/// Get the issuer identifier for an OIDC configuration.
pub fn issuer(config: OidcConfig) -> String {
  config.issuer
}

/// Get the authorization endpoint URL for an OIDC configuration.
pub fn authorization_endpoint(config: OidcConfig) -> String {
  config.authorization_endpoint
}

/// Get the token endpoint URL for an OIDC configuration.
pub fn token_endpoint(config: OidcConfig) -> String {
  config.token_endpoint
}

/// Get the userinfo endpoint URL for an OIDC configuration.
pub fn userinfo_endpoint(config: OidcConfig) -> String {
  config.userinfo_endpoint
}

/// Get the scopes supported by an OIDC configuration.
pub fn scopes_supported(config: OidcConfig) -> List(String) {
  config.scopes_supported
}

/// Fetch the OpenID Connect configuration from a provider's discovery endpoint.
///
/// Constructs the well-known URL from the issuer, makes a GET request, parses
/// the JSON response, and validates that the `issuer` field in the response
/// matches the provided `issuer_url` (a security requirement per the OIDC spec).
///
/// **Security warning:** If `issuer_url` is provided dynamically by end-users
/// (e.g., for custom SSO in a multi-tenant application), you must sanitize
/// the URL before passing it here to prevent Server-Side Request Forgery (SSRF).
pub fn fetch_configuration(
  issuer_url: String,
) -> Result(OidcConfig, AuthError(e)) {
  use discovery_url <- result.try(discovery_url(issuer_url))

  use r <- result.try(
    request.to(discovery_url)
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Invalid discovery URL: " <> discovery_url)
    }),
  )
  let r =
    r
    |> request.set_header("accept", "application/json")

  case httpc.send(r) {
    Ok(response) -> {
      use body <- result.try(provider_support.check_response_status(response))
      use config <- result.try(parse_discovery_document(body))
      // Security: validate issuer matches per OIDC Discovery spec
      let normalized_issuer = strip_trailing_slash(issuer_url)
      let response_issuer = strip_trailing_slash(config.issuer)
      case normalized_issuer == response_issuer {
        True -> Ok(config)
        False ->
          Error(error.ConfigError(
            reason: "Issuer mismatch: expected "
            <> issuer_url
            <> " but got "
            <> config.issuer,
          ))
      }
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to fetch OIDC discovery document from " <> discovery_url,
      ))
  }
}

/// Build the OpenID Connect discovery URL for an issuer URL.
///
/// Per OIDC Discovery, path-based issuers insert
/// `/.well-known/openid-configuration` between the host and issuer path.
pub fn discovery_url(issuer_url: String) -> Result(String, AuthError(e)) {
  // Security: preserve issuer validation before constructing the fetch URL.
  use _ <- result.try(provider_support.require_https(issuer_url))

  use issuer <- result.try(
    uri.parse(issuer_url)
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Invalid issuer URL: " <> issuer_url)
    }),
  )

  let path = strip_trailing_slash(issuer.path)
  let issuer_path = case path {
    "" | "/" -> ""
    _ -> path
  }

  uri.Uri(
    ..issuer,
    path: "/.well-known/openid-configuration" <> issuer_path,
    query: None,
    fragment: None,
  )
  |> uri.to_string()
  |> Ok()
}

/// Parse an OIDC discovery JSON document into an `OidcConfig`.
///
/// Supported parsing helper for custom OIDC strategy authors. Extracts the
/// required fields from the standard OpenID Connect discovery response.
pub fn parse_discovery_document(
  body: String,
) -> Result(OidcConfig, AuthError(e)) {
  let decoder = {
    use issuer <- decode.field("issuer", decode.string)
    use authorization_endpoint <- decode.field(
      "authorization_endpoint",
      decode.string,
    )
    use token_endpoint <- decode.field("token_endpoint", decode.string)
    use userinfo_endpoint <- decode.field("userinfo_endpoint", decode.string)
    use scopes_supported <- decode.optional_field(
      "scopes_supported",
      [],
      decode.list(decode.string),
    )
    decode.success(#(
      issuer,
      authorization_endpoint,
      token_endpoint,
      userinfo_endpoint,
      scopes_supported,
    ))
  }
  case json.parse(body, decoder) {
    Ok(#(
      issuer,
      authorization_endpoint,
      token_endpoint,
      userinfo_endpoint,
      scopes_supported,
    )) ->
      new_config(
        issuer: issuer,
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        userinfo_endpoint: userinfo_endpoint,
        scopes_supported: scopes_supported,
      )
    Error(err) ->
      Error(error.ConfigError(
        reason: "Failed to parse OIDC discovery document: "
        <> string.inspect(err),
      ))
  }
}

/// Build a `Strategy` from a discovered `OidcConfig`.
///
/// The resulting strategy uses standard OIDC/OAuth2 flows:
/// - Authorization code flow for authentication
/// - Standard token exchange
/// - Userinfo endpoint for user claims
///
/// The `provider_name` is used as the strategy's provider identifier.
pub fn strategy_from_config(
  oidc_config: OidcConfig,
  provider_name: String,
) -> Strategy(e) {
  let scopes = filter_default_scopes(oidc_config.scopes_supported)
  Strategy(
    provider: provider_name,
    default_scopes: scopes,
    authorize_url: build_authorize_url_fn(oidc_config.authorization_endpoint),
    exchange_code: build_exchange_code_fn(oidc_config.token_endpoint),
    refresh_token: build_refresh_token_fn(oidc_config.token_endpoint),
    fetch_user: build_fetch_user_fn(oidc_config.userinfo_endpoint),
  )
}

/// Discover an OIDC provider and build a strategy in one step.
///
/// Fetches the discovery document from the issuer's well-known endpoint,
/// then constructs a strategy using the discovered configuration.
/// The issuer's hostname is used as the provider name.
pub fn discover(issuer_url: String) -> Result(Strategy(e), AuthError(e)) {
  use oidc_config <- result.try(fetch_configuration(issuer_url))
  let provider_name = extract_hostname(issuer_url)
  Ok(strategy_from_config(oidc_config, provider_name))
}

/// Filter scopes to only include the standard OIDC scopes that the provider supports.
///
/// Supported helper for custom OIDC strategy authors.
pub fn filter_default_scopes(scopes_supported: List(String)) -> List(String) {
  let desired = ["openid", "profile", "email"]
  case
    list.filter(desired, fn(scope) { list.contains(scopes_supported, scope) })
  {
    [] -> ["openid"]
    scopes -> scopes
  }
}

/// Parse a standard OAuth2/OIDC token response.
///
/// Supported parsing helper for custom OIDC strategy authors. Handles both
/// success and error responses.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(separator: " "),
  )
}

/// Parse a standard OIDC userinfo response into a uid and UserInfo.
///
/// Supported parsing helper for custom OIDC strategy authors. Maps standard
/// OIDC claims to UserInfo fields:
/// - `sub` -> uid
/// - `name` -> name
/// - `email` -> email
/// - `preferred_username` -> nickname
/// - `picture` -> image
pub fn parse_userinfo_response(
  body: String,
) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    use email <- decode.optional_field(
      "email",
      None,
      decode.optional(decode.string),
    )
    use email_verified <- decode.optional_field(
      "email_verified",
      None,
      decode.optional(decode.bool),
    )
    use preferred_username <- decode.optional_field(
      "preferred_username",
      None,
      decode.optional(decode.string),
    )
    use picture <- decode.optional_field(
      "picture",
      None,
      decode.optional(decode.string),
    )
    let verified_email = case email, email_verified {
      Some(addr), Some(True) -> Some(addr)
      _, _ -> None
    }
    decode.success(#(
      sub,
      user_info.UserInfo(
        name: name,
        email: verified_email,
        nickname: preferred_username,
        image: picture,
        description: None,
        urls: dict.new(),
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(err) ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse OIDC userinfo response: "
        <> string.inspect(err),
      ))
  }
}

// --- Internal helpers ---

fn strip_trailing_slash(url: String) -> String {
  case string.ends_with(url, "/") {
    True -> string.drop_end(url, 1)
    False -> url
  }
}

fn extract_hostname(url: String) -> String {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.host {
        Some(host) -> host
        None -> "oidc"
      }
    Error(_) -> "oidc"
  }
}

fn build_authorize_url_fn(
  authorization_endpoint: String,
) -> fn(config.Config, List(String), String) -> Result(String, AuthError(e)) {
  fn(cfg: config.Config, scopes: List(String), state: String) -> Result(
    String,
    AuthError(e),
  ) {
    use redirect <- result.try(
      provider_support.parse_redirect_uri(config.redirect_uri(cfg)),
    )
    case uri.parse(authorization_endpoint) {
      Ok(base_uri) -> {
        let params = [
          #("response_type", "code"),
          #("client_id", config.client_id(cfg)),
          #("redirect_uri", uri.to_string(redirect)),
          #("scope", string.join(scopes, " ")),
          #("state", state),
        ]
        // Merge any extra params from config
        let all_params =
          list.append(params, dict.to_list(config.extra_params(cfg)))
        let query = uri.query_to_string(all_params)
        let full_uri = uri.Uri(..base_uri, query: Some(query))
        Ok(uri.to_string(full_uri))
      }
      Error(_) ->
        Error(error.ConfigError(
          reason: "Invalid authorization endpoint URL: "
          <> authorization_endpoint,
        ))
    }
  }
}

fn build_exchange_code_fn(
  token_endpoint: String,
) -> fn(config.Config, String, option.Option(String)) ->
  Result(Credentials, AuthError(e)) {
  fn(cfg: config.Config, code: String, code_verifier: option.Option(String)) -> Result(
    Credentials,
    AuthError(e),
  ) {
    use redirect <- result.try(
      provider_support.parse_redirect_uri(config.redirect_uri(cfg)),
    )
    let base_params = [
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", uri.to_string(redirect)),
      #("client_id", config.client_id(cfg)),
      #("client_secret", config.client_secret(cfg)),
    ]
    let params = case code_verifier {
      option.Some(verifier) ->
        list.append(base_params, [#("code_verifier", verifier)])
      option.None -> base_params
    }
    let body = uri.query_to_string(params)

    use r <- result.try(
      request.to(token_endpoint)
      |> result.map_error(fn(_) {
        error.ConfigError(
          reason: "Invalid token endpoint URL: " <> token_endpoint,
        )
      }),
    )
    let r =
      r
      |> request.set_method(http.Post)
      |> request.set_header("content-type", "application/x-www-form-urlencoded")
      |> request.set_header("accept", "application/json")
      |> request.set_body(body)

    case httpc.send(r) {
      Ok(response) -> {
        use body <- result.try(provider_support.check_response_status(response))
        parse_token_response(body)
      }
      Error(_) ->
        Error(error.NetworkError(
          reason: "Failed to connect to OIDC token endpoint: " <> token_endpoint,
        ))
    }
  }
}

fn build_fetch_user_fn(
  userinfo_endpoint: String,
) -> fn(config.Config, Credentials) -> Result(UserResult, AuthError(e)) {
  fn(_cfg: config.Config, creds: Credentials) -> Result(
    UserResult,
    AuthError(e),
  ) {
    use auth_header <- result.try(strategy.authorization_header(creds))
    use #(uid, info) <- result.try(provider_support.fetch_json_with_auth(
      userinfo_endpoint,
      auth_header,
      parse_userinfo_response,
      "OIDC userinfo",
    ))
    Ok(UserResult(uid: uid, info: info, extra: dict.new()))
  }
}

fn build_refresh_token_fn(
  token_endpoint: String,
) -> fn(config.Config, String) -> Result(Credentials, AuthError(e)) {
  fn(cfg: config.Config, refresh_tok: String) -> Result(
    Credentials,
    AuthError(e),
  ) {
    let body =
      uri.query_to_string([
        #("grant_type", "refresh_token"),
        #("refresh_token", refresh_tok),
        #("client_id", config.client_id(cfg)),
        #("client_secret", config.client_secret(cfg)),
      ])

    use r <- result.try(
      request.to(token_endpoint)
      |> result.map_error(fn(_) {
        error.ConfigError(
          reason: "Invalid token endpoint URL: " <> token_endpoint,
        )
      }),
    )
    let r =
      r
      |> request.set_method(http.Post)
      |> request.set_header("content-type", "application/x-www-form-urlencoded")
      |> request.set_header("accept", "application/json")
      |> request.set_body(body)

    case httpc.send(r) {
      Ok(response) -> {
        use body <- result.try(provider_support.check_response_status(response))
        parse_token_response(body)
      }
      Error(_) ->
        Error(error.NetworkError(
          reason: "Failed to connect to OIDC token endpoint: " <> token_endpoint,
        ))
    }
  }
}
