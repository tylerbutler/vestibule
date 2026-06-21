//// Stable helpers for OAuth provider implementations.

import gleam/bool
import gleam/dynamic/decode
import gleam/http/request
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import vestibule/error.{type AuthError}
import vestibule/internal/logger

import vestibule/credentials

/// Check that an HTTP response has a 2xx status code.
/// Returns the response body on success, or an HttpError on failure.
pub fn check_response_status(
  response: Response(String),
) -> Result(String, AuthError(e)) {
  check_response_status_for_endpoint(response, provider_name: "", endpoint: "")
}

/// Check that an HTTP response has a 2xx status code, emitting structured log
/// events with the given provider name and endpoint label.
/// Returns the response body on success, or an HttpError on failure.
pub fn check_response_status_for_endpoint(
  response: Response(String),
  provider_name provider_name: String,
  endpoint endpoint: String,
) -> Result(String, AuthError(e)) {
  case response.status < 200 || response.status >= 300 {
    True -> {
      logger.new(
        level: logger.Error,
        event: "vestibule.provider.response.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: option.Some(provider_name),
        fields: [
          logger.field("endpoint", endpoint),
          logger.int_field("status", response.status),
          logger.field("error_category", "http_error"),
        ],
      )
      |> logger.emit()
      Error(error.HttpError(
        status: response.status,
        body: safe_error_body(response.body),
      ))
    }
    False -> {
      logger.new(
        level: logger.Debug,
        event: "vestibule.provider.response.success",
        phase: "provider_request",
        outcome: "success",
        provider: option.Some(provider_name),
        fields: [
          logger.field("endpoint", endpoint),
          logger.int_field("status", response.status),
        ],
      )
      |> logger.emit()
      Ok(response.body)
    }
  }
}

fn safe_error_body(body: String) -> String {
  use <- bool.guard(when: string.length(body) <= 120, return: body)
  string.slice(body, 0, 120)
}

/// Validate that a URL uses HTTPS.
/// HTTP is allowed for localhost and 127.0.0.1 (development use).
/// Returns Ok(Nil) if valid, or a ConfigError describing the issue.
pub fn require_https(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        option.Some("https") ->
          case parsed.host {
            option.Some("") | option.None ->
              Error(error.ConfigError(
                reason: "URL must include a host: " <> url,
              ))
            option.Some(_) -> Ok(Nil)
          }
        option.Some("http") ->
          case parsed.host {
            option.Some("localhost") | option.Some("127.0.0.1") -> Ok(Nil)
            _ ->
              Error(error.ConfigError(
                reason: "HTTPS required for endpoint URL: " <> url,
              ))
          }
        _ ->
          Error(error.ConfigError(
            reason: "HTTPS required for endpoint URL: " <> url,
          ))
      }
    Error(_) -> Error(error.ConfigError(reason: "Invalid URL: " <> url))
  }
}

/// Validate that a URL uses HTTPS *and* targets a publicly-routable host.
///
/// Unlike `require_https`, this rejects `http` entirely (no localhost
/// exception) and also rejects loopback, private, link-local, and other
/// non-publicly-routable hosts. Use it for values supplied by a provider's
/// discovery document — such as the OIDC issuer and discovered
/// token/userinfo endpoints — where an attacker-controlled issuer could
/// otherwise publish an internal URL and trigger Server-Side Request
/// Forgery (SSRF) against loopback or internal services.
///
/// Returns Ok(Nil) if valid, or a ConfigError describing the issue.
pub fn require_public_https(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        option.Some("https") ->
          case parsed.host {
            option.Some("") | option.None ->
              Error(error.ConfigError(
                reason: "URL must include a host: " <> url,
              ))
            option.Some(host) ->
              case is_non_public_host(host) {
                True ->
                  Error(error.ConfigError(
                    reason: "Endpoint host is not publicly routable (loopback, private, or link-local addresses are not allowed for discovered endpoints): "
                    <> url,
                  ))
                False -> Ok(Nil)
              }
          }
        _ ->
          Error(error.ConfigError(
            reason: "HTTPS required for endpoint URL: " <> url,
          ))
      }
    Error(_) -> Error(error.ConfigError(reason: "Invalid URL: " <> url))
  }
}

/// Determine whether a URL host refers to a non-publicly-routable target.
///
/// Catches the `localhost`/`.local` hostnames plus IPv4 and IPv6 literals in
/// loopback, private, link-local, shared (CGNAT), and unspecified ranges.
/// Hostnames that resolve via DNS cannot be classified here and are treated
/// as public; callers that accept fully untrusted issuers should additionally
/// restrict resolution at the network layer.
fn is_non_public_host(host: String) -> Bool {
  let normalized =
    host
    |> string.lowercase
    |> strip_ipv6_brackets

  case is_blocked_hostname(normalized) {
    True -> True
    False ->
      case parse_ipv4(normalized) {
        Ok(octets) -> is_non_public_ipv4(octets)
        Error(_) -> is_non_public_ipv6(normalized)
      }
  }
}

fn strip_ipv6_brackets(host: String) -> String {
  use <- bool.guard(
    when: !{ string.starts_with(host, "[") && string.ends_with(host, "]") },
    return: host,
  )
  string.slice(host, 1, string.length(host) - 2)
}

fn is_blocked_hostname(host: String) -> Bool {
  host == "localhost"
  || string.ends_with(host, ".localhost")
  || string.ends_with(host, ".local")
}

fn parse_ipv4(host: String) -> Result(#(Int, Int, Int, Int), Nil) {
  case string.split(host, ".") {
    [a, b, c, d] -> {
      use a <- result.try(parse_octet(a))
      use b <- result.try(parse_octet(b))
      use c <- result.try(parse_octet(c))
      use d <- result.try(parse_octet(d))
      Ok(#(a, b, c, d))
    }
    _ -> Error(Nil)
  }
}

fn parse_octet(segment: String) -> Result(Int, Nil) {
  case int.parse(segment) {
    Ok(value) if value >= 0 && value <= 255 -> Ok(value)
    _ -> Error(Nil)
  }
}

fn is_non_public_ipv4(octets: #(Int, Int, Int, Int)) -> Bool {
  let #(a, b, _c, _d) = octets
  // 0.0.0.0/8 "this network" / unspecified
  a == 0
  // 10.0.0.0/8 private
  || a == 10
  // 127.0.0.0/8 loopback
  || a == 127
  // 169.254.0.0/16 link-local (incl. cloud metadata 169.254.169.254)
  || { a == 169 && b == 254 }
  // 172.16.0.0/12 private
  || { a == 172 && b >= 16 && b <= 31 }
  // 192.168.0.0/16 private
  || { a == 192 && b == 168 }
  // 100.64.0.0/10 shared address space (CGNAT)
  || { a == 100 && b >= 64 && b <= 127 }
  // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved
  || a >= 224
}

fn is_non_public_ipv6(host: String) -> Bool {
  // Not an IPv6 literal; an ordinary DNS hostname we cannot classify here.
  use <- bool.guard(when: !string.contains(host, ":"), return: False)
  // Loopback and unspecified
  host == "::1"
  || host == "::"
  // Unique local addresses fc00::/7 (fc.. / fd..)
  || string.starts_with(host, "fc")
  || string.starts_with(host, "fd")
  // Link-local fe80::/10 (fe8.. / fe9.. / fea.. / feb..)
  || string.starts_with(host, "fe8")
  || string.starts_with(host, "fe9")
  || string.starts_with(host, "fea")
  || string.starts_with(host, "feb")
  // IPv4-mapped / IPv4-compatible addresses embedding a non-public IPv4
  || embeds_non_public_ipv4(host)
}

fn embeds_non_public_ipv4(host: String) -> Bool {
  case list.last(string.split(host, ":")) {
    Ok(last) ->
      case string.contains(last, ".") {
        True ->
          case parse_ipv4(last) {
            Ok(octets) -> is_non_public_ipv4(octets)
            Error(_) -> False
          }
        False -> False
      }
    Error(_) -> False
  }
}

/// Fetch JSON from a URL with Bearer token authentication.
///
/// Builds a GET request with Authorization and Accept headers,
/// checks the response status, and passes the body to the provided
/// parser function. Used by provider strategies that need to call
/// a userinfo or similar API endpoint.
pub fn fetch_json_with_auth(
  url: String,
  auth_header: String,
  parse: fn(String) -> Result(a, AuthError(e)),
  provider_name: String,
) -> Result(a, AuthError(e)) {
  use _ <- result.try(require_https(url))
  use req <- result.try(
    request.to(url)
    |> result.map_error(fn(_) {
      error.ConfigError(
        reason: "Invalid " <> provider_name <> " endpoint URL: " <> url,
      )
    }),
  )
  let req =
    req
    |> request.set_header("authorization", auth_header)
    |> request.set_header("accept", "application/json")
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some(provider_name),
    fields: [logger.field("endpoint", "user_info")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(check_response_status_for_endpoint(
        response,
        provider_name: provider_name,
        endpoint: "user_info",
      ))
      parse(body)
    }
    Error(_) -> {
      logger.new(
        level: logger.Error,
        event: "vestibule.provider.request.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: option.Some(provider_name),
        fields: [
          logger.field("endpoint", "user_info"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.NetworkError(
        reason: "Failed to connect to " <> provider_name <> " API: " <> url,
      ))
    }
  }
}

/// Check a JSON response body for an OAuth2 error response.
///
/// If the body contains `{"error": "...", "error_description": "..."}`,
/// returns `Error(ProviderError(...))`. Otherwise returns `Ok(body)`
/// so the caller can proceed with success parsing.
///
/// This pattern is used by every token endpoint response parser
/// (GitHub, Google, Microsoft, Apple, OIDC, refresh).
pub fn check_token_error(body: String) -> Result(String, AuthError(e)) {
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.optional_field(
      "error_description",
      "",
      decode.string,
    )
    use error_uri <- decode.optional_field(
      "error_uri",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(#(error_code, description, error_uri))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description, uri)) ->
      Error(error.ProviderError(code: code, description: description, uri: uri))
    _ -> Ok(body)
  }
}

/// Parse and validate a redirect URI.
///
/// Redirect URIs must be valid URLs and use HTTPS, except localhost/127.0.0.1
/// which are allowed for local development.
pub fn parse_redirect_uri(
  redirect_uri: String,
) -> Result(uri.Uri, AuthError(e)) {
  use parsed <- result.try(
    uri.parse(redirect_uri)
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Invalid redirect URI: " <> redirect_uri)
    }),
  )
  let https_error =
    Error(error.ConfigError(
      reason: "Redirect URI must use HTTPS (except localhost): " <> redirect_uri,
    ))
  case parsed.scheme {
    option.Some("https") ->
      case parsed.host {
        option.Some("") | option.None ->
          Error(error.ConfigError(
            reason: "Redirect URI must include a host: " <> redirect_uri,
          ))
        option.Some(_) -> Ok(parsed)
      }
    option.Some("http") ->
      case parsed.host {
        option.Some("localhost") | option.Some("127.0.0.1") -> Ok(parsed)
        _ -> https_error
      }
    _ -> https_error
  }
}

/// Append additional query params to a URL.
pub fn append_query_params(
  url: String,
  params: List(#(String, String)),
) -> String {
  case params {
    [] -> url
    _ -> {
      let separator = case string.contains(url, "?") {
        True -> "&"
        False -> "?"
      }
      url <> separator <> uri.query_to_string(params)
    }
  }
}

/// Scope parsing behavior for OAuth token responses.
pub type ScopeParsing {
  RequiredScope(separator: String)
  OptionalScope(separator: String)
  NoScope
}

/// Parse a standard OAuth token response JSON into credentials.
///
/// Checks for OAuth error responses before parsing success responses.
pub fn parse_oauth_token_response(
  body: String,
  scope_parsing: ScopeParsing,
) -> Result(credentials.Credentials, AuthError(e)) {
  use body <- result.try(check_token_error(body))
  parse_oauth_token_success(body, scope_parsing)
}

fn parse_oauth_token_success(
  body: String,
  scope_parsing: ScopeParsing,
) -> Result(credentials.Credentials, AuthError(e)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use refresh_token <- decode.optional_field(
      "refresh_token",
      option.None,
      decode.optional(decode.string),
    )
    use expires_in <- decode.optional_field(
      "expires_in",
      option.None,
      decode.optional(decode.int),
    )
    decode_token_credentials(
      access_token,
      refresh_token,
      token_type,
      expires_in,
      scope_parsing,
    )
  }

  case json.parse(body, decoder) {
    Ok(credentials) -> Ok(credentials)
    Error(err) ->
      Error(error.DecodeError(
        context: "token response",
        reason: string.inspect(err),
      ))
  }
}

fn decode_token_credentials(
  access_token: String,
  refresh_token: option.Option(String),
  token_type: String,
  expires_in: option.Option(Int),
  scope_parsing: ScopeParsing,
) -> decode.Decoder(credentials.Credentials) {
  case scope_parsing {
    RequiredScope(separator) -> {
      use scope <- decode.field("scope", decode.string)
      decode.success(token_credentials(
        access_token,
        refresh_token,
        token_type,
        expires_in,
        split_scope(scope, separator),
      ))
    }
    OptionalScope(separator) -> {
      use scope <- decode.optional_field("scope", "", decode.string)
      decode.success(token_credentials(
        access_token,
        refresh_token,
        token_type,
        expires_in,
        split_scope(scope, separator),
      ))
    }
    NoScope ->
      decode.success(
        token_credentials(
          access_token,
          refresh_token,
          token_type,
          expires_in,
          [],
        ),
      )
  }
}

fn token_credentials(
  access_token: String,
  refresh_token: option.Option(String),
  token_type: String,
  expires_in: option.Option(Int),
  scopes: List(String),
) -> credentials.Credentials {
  credentials.new(
    token: access_token,
    refresh_token: refresh_token,
    token_type: token_type,
    expires_in: expires_in,
    scopes: scopes,
  )
}

fn split_scope(scope: String, separator: String) -> List(String) {
  case scope {
    "" -> []
    scope -> string.split(scope, separator)
  }
}
