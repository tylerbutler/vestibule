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
//// import vestibule_oidc
//// let assert Ok(strategy) = vestibule_oidc.discover("https://accounts.google.com")
////
//// // Or fetch configuration separately for inspection:
//// let assert Ok(config) = vestibule_oidc.fetch_configuration("https://accounts.google.com")
//// let strategy = vestibule_oidc.strategy_from_config(config, "my-provider")
//// ```

import gleam/bool
import gleam/dict
import gleam/dynamic
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri

import vestibule/config
import vestibule/credential.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/provider_support
import vestibule/strategy.{type Strategy, type UserResult}
import vestibule/user_info
import vestibule_oidc/internal/token_request

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
/// The issuer and endpoint URLs must use HTTPS and target a publicly-routable
/// host. Loopback (`localhost`, `127.0.0.1`, `[::1]`), private, and link-local
/// addresses are rejected: these endpoints come from a provider-controlled
/// discovery document and are called server-side with an `Authorization`
/// header, so permitting internal hosts would enable SSRF.
pub fn new_config(
  issuer issuer: String,
  authorization_endpoint authorization_endpoint: String,
  token_endpoint token_endpoint: String,
  userinfo_endpoint userinfo_endpoint: String,
  scopes_supported scopes_supported: List(String),
) -> Result(OidcConfig, AuthError(e)) {
  use _ <- result.try(provider_support.require_public_https_format(issuer))
  use _ <- result.try(provider_support.require_public_https_format(
    authorization_endpoint,
  ))
  use _ <- result.try(provider_support.require_public_https_format(
    token_endpoint,
  ))
  use _ <- result.try(provider_support.require_public_https_format(
    userinfo_endpoint,
  ))

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
/// Dynamic issuer URLs are sent through Vestibule's secure transport, which
/// requires public HTTPS, validates every DNS answer, pins the connection, and
/// disables redirects.
pub fn fetch_configuration(
  issuer_url: String,
) -> Result(OidcConfig, AuthError(e)) {
  use http_request <- result.try(build_discovery_request(issuer_url))

  case provider_support.send_public(http_request) {
    Ok(response) -> parse_discovery_response(issuer_url, response)
    Error(send_error) -> Error(send_error)
  }
}

/// Build an OIDC discovery request without sending it.
///
/// The returned request is opaque and can only be sent with
/// `provider_support.send_public`, which performs DNS validation and address
/// pinning immediately before connecting.
pub fn build_discovery_request(
  issuer_url: String,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use url <- result.try(discovery_url(issuer_url))
  use http_request <- result.try(
    request.to(url)
    |> result.map_error(fn(_parse_error) {
      error.config(reason: "Invalid discovery URL: " <> url)
    }),
  )
  http_request
  |> request.set_header("accept", "application/json")
  |> provider_support.secure_request_with_limit(
    provider_support.DiscoveryResponse,
  )
}

/// Parse and validate an OIDC discovery HTTP response without performing I/O.
///
/// In addition to parsing the document and validating all discovered endpoints,
/// this enforces the OIDC requirement that the returned issuer matches the
/// issuer used to construct the request.
pub fn parse_discovery_response(
  issuer_url: String,
  http_response: response.Response(String),
) -> Result(OidcConfig, AuthError(e)) {
  use body <- result.try(provider_support.check_response_status(http_response))
  use oidc_config <- result.try(parse_discovery_document(body))
  let normalized_issuer = strip_trailing_slash(issuer_url)
  let response_issuer = strip_trailing_slash(oidc_config.issuer)
  case normalized_issuer == response_issuer {
    True -> Ok(oidc_config)
    False ->
      Error(error.config(
        reason: "Issuer mismatch: expected "
        <> issuer_url
        <> " but got "
        <> oidc_config.issuer,
      ))
  }
}

/// Build the OpenID Connect discovery URL for an issuer URL.
///
/// Per OIDC Discovery, path-based issuers insert
/// `/.well-known/openid-configuration` between the host and issuer path.
pub fn discovery_url(issuer_url: String) -> Result(String, AuthError(e)) {
  // Security: preserve issuer validation before constructing the fetch URL.
  // The issuer is provider-controlled, so reject loopback/internal hosts.
  use _ <- result.try(provider_support.require_public_https_format(issuer_url))

  use issuer <- result.try(
    uri.parse(issuer_url)
    |> result.map_error(fn(_parse_error) {
      error.config(reason: "Invalid issuer URL: " <> issuer_url)
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
    Error(parse_error) ->
      Error(error.config(
        reason: "Failed to parse OIDC discovery document: "
        <> string.inspect(parse_error),
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
  strategy.new(
    provider: provider_name,
    default_scopes: scopes,
    authorize_url: build_authorize_url_fn(oidc_config.authorization_endpoint),
    exchange_code: build_exchange_code_fn(oidc_config),
    fetch_user: build_fetch_user_fn(oidc_config),
  )
  |> strategy.with_nonce()
  |> strategy.with_refresh(build_refresh_token_fn(oidc_config))
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

/// Build an OIDC authorization-code token request without sending it.
pub fn build_authorization_code_request(
  oidc_config: OidcConfig,
  client_config: config.ClientConfig,
  code: String,
  code_verifier: option.Option(String),
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(client_config)),
  )
  let body =
    token_request.authorization_code(
      client_config,
      code: code,
      redirect_uri: uri.to_string(redirect),
      code_verifier: code_verifier,
    )
    |> uri.query_to_string
  build_token_request(oidc_config.token_endpoint, body)
}

/// Parse an OIDC authorization-code HTTP response without performing I/O.
pub fn parse_authorization_code_response(
  http_response: response.Response(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use body <- result.try(provider_support.check_response_status(http_response))
  use oauth_credentials <- result.try(parse_token_response(body))
  Ok(strategy.exchange_result_with_artifacts(
    oauth_credentials,
    id_token_artifacts(body),
  ))
}

/// Build an OIDC refresh-token request without sending it.
pub fn build_refresh_token_request(
  oidc_config: OidcConfig,
  client_config: config.ClientConfig,
  refresh_token: String,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  let body =
    token_request.refresh(client_config, refresh_token: refresh_token)
    |> uri.query_to_string
  build_token_request(oidc_config.token_endpoint, body)
}

/// Parse an OIDC refresh-token HTTP response without performing I/O.
pub fn parse_refresh_token_response(
  http_response: response.Response(String),
) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_token_response)
}

/// Build an OIDC userinfo request without sending it.
pub fn build_user_info_request(
  oidc_config: OidcConfig,
  oauth_credentials: Credentials,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use authorization_header <- result.try(strategy.authorization_header(
    oauth_credentials,
  ))
  use http_request <- result.try(provider_support.build_json_request_with_auth(
    oidc_config.userinfo_endpoint,
    authorization_header,
    "OIDC userinfo",
  ))
  provider_support.secure_request_with_limit(
    http_request,
    provider_support.UserInfoResponse,
  )
}

/// Parse an OIDC userinfo HTTP response without performing I/O.
pub fn parse_user_info_response(
  http_response: response.Response(String),
) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_userinfo_response)
}

fn build_token_request(
  token_endpoint: String,
  body: String,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use http_request <- result.try(
    request.to(token_endpoint)
    |> result.map_error(fn(_parse_error) {
      error.config(reason: "Invalid token endpoint URL: " <> token_endpoint)
    }),
  )
  http_request
  |> request.set_method(http.Post)
  |> request.set_header("content-type", "application/x-www-form-urlencoded")
  |> request.set_header("accept", "application/json")
  |> request.set_body(body)
  |> provider_support.secure_request_with_limit(provider_support.TokenResponse)
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
      Some(address), Some(True) -> Some(address)
      Some(_address), Some(False) -> None
      Some(_address), None -> None
      None, Some(True) -> None
      None, Some(False) -> None
      None, None -> None
    }
    decode.success(#(
      sub,
      user_info.new()
        |> user_info.with_name(name)
        |> user_info.with_email(verified_email)
        |> user_info.with_nickname(preferred_username)
        |> user_info.with_image(picture),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(parse_error) ->
      Error(error.user_info(
        reason: "Failed to parse OIDC userinfo response: "
        <> string.inspect(parse_error),
      ))
  }
}

// --- Internal helpers ---

/// Build exchange artifacts carrying the OIDC `id_token` when present, so the
/// core can validate the `nonce` claim on callback.
fn id_token_artifacts(body: String) -> dict.Dict(String, dynamic.Dynamic) {
  case parse_id_token(body) {
    Some(token) -> dict.from_list([#("id_token", dynamic.string(token))])
    None -> dict.new()
  }
}

fn parse_id_token(body: String) -> option.Option(String) {
  let decoder = {
    use id_token <- decode.optional_field(
      "id_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(id_token)
  }
  case json.parse(body, decoder) {
    Ok(id_token) -> id_token
    Error(_parse_error) -> None
  }
}

fn strip_trailing_slash(url: String) -> String {
  use <- bool.guard(when: !string.ends_with(url, "/"), return: url)
  string.drop_end(url, 1)
}

fn extract_hostname(url: String) -> String {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.host {
        Some(host) -> host
        None -> "oidc"
      }
    Error(_parse_error) -> "oidc"
  }
}

fn build_authorize_url_fn(
  authorization_endpoint: String,
) -> fn(config.ClientConfig, config.AuthorizeOptions, List(String), String) ->
  Result(String, AuthError(e)) {
  fn(
    client_config: config.ClientConfig,
    options: config.AuthorizeOptions,
    scopes: List(String),
    state: String,
  ) -> Result(String, AuthError(e)) {
    use redirect <- result.try(
      provider_support.parse_redirect_uri(config.redirect_uri(client_config)),
    )
    case uri.parse(authorization_endpoint) {
      Ok(base_uri) -> {
        let parameters = [
          #("response_type", "code"),
          #("client_id", config.client_id(client_config)),
          #("redirect_uri", uri.to_string(redirect)),
          #("scope", string.join(scopes, " ")),
          #("state", state),
        ]
        // Merge any extra parameters from options
        let all_parameters =
          list.append(parameters, dict.to_list(config.extra_params(options)))
        let query = uri.query_to_string(all_parameters)
        let full_uri = uri.Uri(..base_uri, query: Some(query))
        Ok(uri.to_string(full_uri))
      }
      Error(_parse_error) ->
        Error(error.config(
          reason: "Invalid authorization endpoint URL: "
          <> authorization_endpoint,
        ))
    }
  }
}

fn build_exchange_code_fn(
  oidc_config: OidcConfig,
) -> fn(config.ClientConfig, String, option.Option(String)) ->
  Result(strategy.ExchangeResult, AuthError(e)) {
  fn(
    client_config: config.ClientConfig,
    code: String,
    code_verifier: option.Option(String),
  ) -> Result(strategy.ExchangeResult, AuthError(e)) {
    use http_request <- result.try(build_authorization_code_request(
      oidc_config,
      client_config,
      code,
      code_verifier,
    ))

    case provider_support.send_public(http_request) {
      Ok(response) -> parse_authorization_code_response(response)
      Error(send_error) -> Error(send_error)
    }
  }
}

fn build_fetch_user_fn(
  oidc_config: OidcConfig,
) -> fn(config.ClientConfig, strategy.ExchangeResult) ->
  Result(UserResult, AuthError(e)) {
  fn(_client_config: config.ClientConfig, exchange: strategy.ExchangeResult) -> Result(
    UserResult,
    AuthError(e),
  ) {
    use http_request <- result.try(build_user_info_request(
      oidc_config,
      strategy.exchange_credentials(exchange),
    ))
    use http_response <- result.try(provider_support.send_public(http_request))
    use #(uid, info) <- result.try(parse_user_info_response(http_response))
    Ok(strategy.user_result(uid: uid, info: info, extra: dict.new()))
  }
}

fn build_refresh_token_fn(
  oidc_config: OidcConfig,
) -> fn(config.ClientConfig, String) -> Result(Credentials, AuthError(e)) {
  fn(client_config: config.ClientConfig, refresh_token: String) -> Result(
    Credentials,
    AuthError(e),
  ) {
    use http_request <- result.try(build_refresh_token_request(
      oidc_config,
      client_config,
      refresh_token,
    ))

    case provider_support.send_public(http_request) {
      Ok(response) -> parse_refresh_token_response(response)
      Error(send_error) -> Error(send_error)
    }
  }
}
