/// OpenID Connect Discovery support for auto-configuring strategies.
///
/// This module implements [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
/// to automatically fetch provider configuration from a well-known endpoint
/// and build a `Strategy` from the discovered endpoints.
///
/// ## Usage
///
/// ```gleam
/// // Auto-discover and create a strategy in one step:
/// let assert Ok(strategy) = oidc.discover("https://accounts.google.com")
///
/// // Or fetch configuration separately for inspection:
/// let assert Ok(config) = oidc.fetch_configuration("https://accounts.google.com")
/// let strategy = oidc.strategy_from_config(config, "my-provider")
/// ```
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

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info

/// Configuration discovered from an OpenID Connect provider's
/// `/.well-known/openid-configuration` endpoint.
pub type OidcConfig {
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

/// Fetch the OpenID Connect configuration from a provider's discovery endpoint.
///
/// Constructs the well-known URL from the issuer, makes a GET request, parses
/// the JSON response, and validates that the `issuer` field in the response
/// matches the provided `issuer_url` (a security requirement per the OIDC spec).
pub fn fetch_configuration(
  issuer_url: String,
) -> Result(OidcConfig, AuthError(e)) {
  let discovery_url =
    strip_trailing_slash(issuer_url) <> "/.well-known/openid-configuration"

  let req = case request.to(discovery_url) {
    Ok(r) -> Ok(r)
    Error(_) ->
      Error(error.ConfigError(
        reason: "Invalid discovery URL: " <> discovery_url,
      ))
  }

  use r <- result.try(req)
  let r =
    r
    |> request.set_header("accept", "application/json")

  case httpc.send(r) {
    Ok(response) -> {
      use config <- result.try(parse_discovery_document(response.body))
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

/// Parse an OIDC discovery JSON document into an `OidcConfig`.
///
/// Exported for testing. Extracts the required fields from the standard
/// OpenID Connect discovery response.
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
    decode.success(OidcConfig(
      issuer: issuer,
      authorization_endpoint: authorization_endpoint,
      token_endpoint: token_endpoint,
      userinfo_endpoint: userinfo_endpoint,
      scopes_supported: scopes_supported,
    ))
  }
  case json.parse(body, decoder) {
    Ok(config) -> Ok(config)
    _ ->
      Error(error.ConfigError(reason: "Failed to parse OIDC discovery document"))
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
/// Exported for testing.
pub fn filter_default_scopes(scopes_supported: List(String)) -> List(String) {
  let desired = ["openid", "profile", "email"]
  list.filter(desired, fn(scope) { list.contains(scopes_supported, scope) })
}

/// Parse a standard OAuth2/OIDC token response.
///
/// Exported for testing. Handles both success and error responses.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  // Check for error response first
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.field("error_description", decode.string)
    decode.success(#(error_code, description))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description)) ->
      Error(error.ProviderError(code: code, description: description))
    _ -> parse_success_token(body)
  }
}

/// Parse a standard OIDC userinfo response into a uid and UserInfo.
///
/// Exported for testing. Maps standard OIDC claims to UserInfo fields:
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
    decode.success(#(
      sub,
      user_info.UserInfo(
        name: name,
        email: email,
        nickname: preferred_username,
        image: picture,
        description: None,
        urls: dict.new(),
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    _ ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse OIDC userinfo response",
      ))
  }
}

// --- Internal helpers ---

fn parse_success_token(body: String) -> Result(Credentials, AuthError(e)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use scope <- decode.optional_field("scope", "", decode.string)
    use expires_in <- decode.optional_field(
      "expires_in",
      None,
      decode.optional(decode.int),
    )
    use refresh_token <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    let scopes = case scope {
      "" -> []
      s -> string.split(s, " ")
    }
    decode.success(Credentials(
      token: access_token,
      refresh_token: refresh_token,
      token_type: token_type,
      expires_at: expires_in,
      scopes: scopes,
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse OIDC token response",
      ))
  }
}

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
) -> fn(Config, List(String), String) -> Result(String, AuthError(e)) {
  fn(config: Config, scopes: List(String), state: String) -> Result(
    String,
    AuthError(e),
  ) {
    case uri.parse(authorization_endpoint) {
      Ok(base_uri) -> {
        let params = [
          #("response_type", "code"),
          #("client_id", config.client_id),
          #("redirect_uri", config.redirect_uri),
          #("scope", string.join(scopes, " ")),
          #("state", state),
        ]
        // Merge any extra params from config
        let all_params = list.append(params, dict.to_list(config.extra_params))
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
) -> fn(Config, String) -> Result(Credentials, AuthError(e)) {
  fn(config: Config, code: String) -> Result(Credentials, AuthError(e)) {
    let body =
      uri.query_to_string([
        #("grant_type", "authorization_code"),
        #("code", code),
        #("redirect_uri", config.redirect_uri),
        #("client_id", config.client_id),
        #("client_secret", config.client_secret),
      ])

    let req = case request.to(token_endpoint) {
      Ok(r) -> Ok(r)
      Error(_) ->
        Error(error.ConfigError(
          reason: "Invalid token endpoint URL: " <> token_endpoint,
        ))
    }

    use r <- result.try(req)
    let r =
      r
      |> request.set_method(http.Post)
      |> request.set_header("content-type", "application/x-www-form-urlencoded")
      |> request.set_header("accept", "application/json")
      |> request.set_body(body)

    case httpc.send(r) {
      Ok(response) -> parse_token_response(response.body)
      Error(_) ->
        Error(error.NetworkError(
          reason: "Failed to connect to OIDC token endpoint: " <> token_endpoint,
        ))
    }
  }
}

fn build_fetch_user_fn(
  userinfo_endpoint: String,
) -> fn(Credentials) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
  fn(creds: Credentials) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
    let req = case request.to(userinfo_endpoint) {
      Ok(r) -> Ok(r)
      Error(_) ->
        Error(error.ConfigError(
          reason: "Invalid userinfo endpoint URL: " <> userinfo_endpoint,
        ))
    }

    use r <- result.try(req)
    let r =
      r
      |> request.set_header("authorization", "Bearer " <> creds.token)
      |> request.set_header("accept", "application/json")

    case httpc.send(r) {
      Ok(response) -> parse_userinfo_response(response.body)
      Error(_) ->
        Error(error.NetworkError(
          reason: "Failed to connect to OIDC userinfo endpoint: "
          <> userinfo_endpoint,
        ))
    }
  }
}
