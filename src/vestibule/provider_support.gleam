//// Stable helpers for OAuth provider implementations.

import gleam/bool
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response.{type Response}
import gleam/json
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import vestibule/error.{type AuthError}
import vestibule/internal/public_http
import vestibule/logger

import vestibule/credential

/// An opaque HTTP request for an untrusted, dynamically selected destination.
///
/// The wrapped `gleam_http` request cannot be extracted or sent with an
/// arbitrary HTTP client. It can only be passed to `send_public`, which
/// validates every DNS answer, pins the selected address, preserves the
/// original HTTPS hostname for SNI and `Host`, and disables redirects.
pub opaque type SecureRequest {
  SecureRequest(
    http_request: request.Request(String),
    response_limit: SecureResponseLimit,
  )
}

/// A bounded response class for a request sent through the secure transport.
///
/// Each class maps to a fixed conservative cap. Callers cannot provide an
/// arbitrary byte count:
/// - `ProfileHtmlResponse`: 1 MiB
/// - `DiscoveryResponse`: 256 KiB (including JWKS documents)
/// - `TokenResponse`: 64 KiB
/// - `UserInfoResponse`: 256 KiB
pub type SecureResponseLimit {
  ProfileHtmlResponse
  DiscoveryResponse
  TokenResponse
  UserInfoResponse
}

/// Check that an HTTP response has a 2xx status code.
/// Returns the response body on success, or an AuthError of kind `HttpKind` on
/// failure. The error's summary carries the first 120 characters of the
/// response body, so it may contain provider response content.
pub fn check_response_status(
  response: Response(String),
) -> Result(String, AuthError(e)) {
  use <- bool.guard(
    when: response.status < 200 || response.status >= 300,
    return: Error(error.http(
      status: response.status,
      summary: safe_error_body(response.body),
    )),
  )
  Ok(response.body)
}

/// Check that an HTTP response has a 2xx status code, emitting structured log
/// events with the given provider name and endpoint label.
/// Returns the response body on success, or an AuthError of kind `HttpKind` on
/// failure.
pub fn check_response_status_for_endpoint(
  response: Response(String),
  provider_name provider_name: String,
  endpoint endpoint: String,
) -> Result(String, AuthError(e)) {
  let checked = check_response_status(response)
  case checked {
    Error(authentication_error) -> {
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
      Error(authentication_error)
    }
    Ok(body) -> {
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
      Ok(body)
    }
  }
}

fn safe_error_body(body: String) -> String {
  use <- bool.guard(when: string.length(body) <= 120, return: body)
  string.slice(body, 0, 120)
}

/// Validate that a URL uses HTTPS.
/// HTTP is allowed for localhost and 127.0.0.1 (development use).
/// Returns Ok(Nil) if valid, or an AuthError of kind `ConfigKind` describing
/// the issue.
pub fn require_https(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        option.Some("https") ->
          case parsed.host {
            option.Some("") | option.None ->
              Error(error.config(reason: "URL must include a host: " <> url))
            option.Some(_) -> Ok(Nil)
          }
        option.Some("http") ->
          case parsed.host {
            option.Some("localhost") | option.Some("127.0.0.1") -> Ok(Nil)
            option.Some(_) | option.None ->
              Error(error.config(
                reason: "HTTPS required for endpoint URL: " <> url,
              ))
          }
        option.Some(_) | option.None ->
          Error(error.config(reason: "HTTPS required for endpoint URL: " <> url))
      }
    Error(_) -> Error(error.config(reason: "Invalid URL: " <> url))
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
/// Returns Ok(Nil) if valid, or an AuthError of kind `ConfigKind` describing
/// the issue.
pub fn require_public_https(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        option.Some("https") -> require_public_host(url)
        option.Some(_) | option.None ->
          Error(error.config(reason: "HTTPS required for endpoint URL: " <> url))
      }
    Error(_) -> Error(error.config(reason: "Invalid URL: " <> url))
  }
}

/// Validate the scheme and literal host of a server-side HTTPS URL without
/// performing DNS resolution.
///
/// This exists for sans-I/O request builders and parsers. Any request accepted
/// here must be sent with `send_public`, which performs the authoritative DNS
/// validation and address pinning immediately before connecting.
pub fn require_public_https_format(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        option.Some("https") -> require_public_host_format(url)
        option.Some(_) | option.None ->
          Error(error.config(reason: "HTTPS required for endpoint URL: " <> url))
      }
    Error(_) -> Error(error.config(reason: "Invalid URL: " <> url))
  }
}

/// Validate a server-side URL's literal host without performing DNS
/// resolution. See `require_public_https_format`.
pub fn require_public_host_format(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.host {
        option.Some("") | option.None ->
          Error(error.config(reason: "URL must include a host: " <> url))
        option.Some(host) -> {
          use _ <- result.try(
            public_http.validate_host_format(host)
            |> result.map_error(fn(reason) {
              error.config(reason: reason <> " (URL: " <> url <> ")")
            }),
          )
          Ok(Nil)
        }
      }
    Error(_) -> Error(error.config(reason: "Invalid URL: " <> url))
  }
}

/// Validate that a URL targets a publicly-routable host, whatever its scheme.
///
/// This is the host half of `require_public_https`, for URLs that are fetched
/// server-side but where plain `http` is legitimately allowed — for example
/// an IndieAuth profile URL supplied by the person logging in. Loopback,
/// private, link-local, shared (CGNAT), multicast, and reserved IPv4/IPv6
/// literals are rejected, as are `localhost`, `*.localhost`, and `*.local`
/// names. DNS names are resolved and rejected if any returned IPv4 or IPv6
/// address is not globally routable. Alternate numeric spellings accepted by
/// Erlang's resolver (`127.1`, `2130706433`, `0177.0.0.1`) and IPv4 embedded
/// in IPv6 are classified after parsing, rather than by textual prefix.
///
/// Returns Ok(Nil) if valid, or an AuthError of kind `ConfigKind` describing
/// the issue.
pub fn require_public_host(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.host {
        option.Some("") | option.None ->
          Error(error.config(reason: "URL must include a host: " <> url))
        option.Some(host) -> {
          use _ <- result.try(
            public_http.validate_host(host)
            |> result.map_error(fn(reason) {
              error.config(reason: reason <> " (URL: " <> url <> ")")
            }),
          )
          Ok(Nil)
        }
      }
    Error(_) -> Error(error.config(reason: "Invalid URL: " <> url))
  }
}

/// Wrap an HTTPS request to an untrusted dynamic destination.
///
/// This performs the format-only checks that are safe in a sans-I/O builder.
/// DNS validation is deliberately deferred until `send_public`, immediately
/// before the connection is made. The default 256 KiB discovery cap is
/// conservative; endpoint builders should use `secure_request_with_limit`.
pub fn secure_request(
  http_request: request.Request(String),
) -> Result(SecureRequest, AuthError(e)) {
  secure_request_with_limit(http_request, DiscoveryResponse)
}

/// Wrap an HTTPS request with an endpoint-appropriate response body cap.
///
/// The cap is enforced while bytes are read, for both fixed-length and chunked
/// responses. Oversized responses are aborted before their bodies can be
/// buffered in full.
pub fn secure_request_with_limit(
  http_request: request.Request(String),
  response_limit: SecureResponseLimit,
) -> Result(SecureRequest, AuthError(e)) {
  let url =
    http_request
    |> request.to_uri
    |> uri.to_string
  use _ <- result.try(require_public_https_format(url))
  Ok(SecureRequest(http_request, response_limit))
}

/// Return the method of an opaque secure request for deterministic testing.
pub fn secure_request_method(secure_request: SecureRequest) -> http.Method {
  let SecureRequest(http_request, _) = secure_request
  http_request.method
}

/// Return the URI of an opaque secure request for deterministic testing.
///
/// This does not expose the underlying sendable `gleam_http` request.
pub fn secure_request_uri(secure_request: SecureRequest) -> uri.Uri {
  let SecureRequest(http_request, _) = secure_request
  request.to_uri(http_request)
}

/// Return the body of an opaque secure request for deterministic testing.
pub fn secure_request_body(secure_request: SecureRequest) -> String {
  let SecureRequest(http_request, _) = secure_request
  http_request.body
}

/// Return the response limit class of an opaque request for testing.
pub fn secure_request_response_limit(
  secure_request: SecureRequest,
) -> SecureResponseLimit {
  let SecureRequest(_, response_limit) = secure_request
  response_limit
}

/// Read a header from an opaque secure request for deterministic testing.
pub fn secure_request_header(
  secure_request: SecureRequest,
  name: String,
) -> Result(String, Nil) {
  let SecureRequest(http_request, _) = secure_request
  request.get_header(http_request, name)
}

/// Send an opaque request only to a globally-routable destination.
///
/// The hostname is resolved once, every returned address is checked, and the
/// selected validated address is placed directly in the connection URL. HTTPS
/// requests retain the original hostname in both SNI/certificate verification
/// and the Host header. Redirects are disabled so every subsequent URL must be
/// independently validated and pinned. The response body is counted while it
/// is read and the connection is closed immediately if the request's fixed
/// endpoint cap is exceeded.
pub fn send_public(
  secure_request: SecureRequest,
) -> Result(Response(String), AuthError(e)) {
  let SecureRequest(http_request, response_limit) = secure_request
  let url =
    http_request
    |> request.to_uri
    |> uri.to_string
  case public_http.send(http_request, response_limit_bytes(response_limit)) {
    Ok(http_response) -> Ok(http_response)
    Error(public_http.UnsafeTarget(reason)) ->
      Error(error.config(reason: reason))
    Error(public_http.NetworkFailure(reason)) ->
      Error(error.network(
        reason: "Failed to connect to " <> url <> ": " <> reason,
      ))
  }
}

fn response_limit_bytes(response_limit: SecureResponseLimit) -> Int {
  case response_limit {
    ProfileHtmlResponse -> 1_048_576
    DiscoveryResponse -> 262_144
    TokenResponse -> 65_536
    UserInfoResponse -> 262_144
  }
}

/// Build a JSON GET request with an Authorization header.
///
/// The URL is validated before the request is returned. This function performs
/// no network I/O; send the request with any HTTP client and pass its response
/// to `parse_json_response`.
pub fn build_json_request_with_auth(
  url: String,
  auth_header: String,
  provider_name: String,
) -> Result(request.Request(String), AuthError(e)) {
  use _ <- result.try(require_https(url))
  use http_request <- result.try(
    request.to(url)
    |> result.map_error(fn(_) {
      error.config(
        reason: "Invalid " <> provider_name <> " endpoint URL: " <> url,
      )
    }),
  )
  let http_request =
    http_request
    |> request.set_header("authorization", auth_header)
    |> request.set_header("accept", "application/json")
  Ok(http_request)
}

/// Parse a JSON HTTP response after it has been sent by the caller.
///
/// Checks the HTTP status and passes the successful response body to `parse`.
/// This function performs no network I/O.
pub fn parse_json_response(
  response: Response(String),
  parse: fn(String) -> Result(a, AuthError(e)),
) -> Result(a, AuthError(e)) {
  use body <- result.try(check_response_status(response))
  parse(body)
}

/// Fetch JSON from a URL with Authorization authentication.
///
/// This convenience wrapper uses Vestibule’s public-destination transport. To
/// supply a different HTTP client, build the request with
/// `build_json_request_with_auth`, send it, and parse the response with
/// `parse_json_response`.
pub fn fetch_json_with_auth(
  url: String,
  auth_header: String,
  parse: fn(String) -> Result(a, AuthError(e)),
  provider_name: String,
) -> Result(a, AuthError(e)) {
  use http_request <- result.try(build_json_request_with_auth(
    url,
    auth_header,
    provider_name,
  ))
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some(provider_name),
    fields: [logger.field("endpoint", "user_info")],
  )
  |> logger.emit()
  use public_request <- result.try(secure_request_with_limit(
    http_request,
    UserInfoResponse,
  ))
  case send_public(public_request) {
    Ok(response) -> {
      use body <- result.try(check_response_status_for_endpoint(
        response,
        provider_name: provider_name,
        endpoint: "user_info",
      ))
      parse(body)
    }
    Error(send_error) -> {
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
      Error(send_error)
    }
  }
}

/// Check a JSON response body for an OAuth2 error response.
///
/// If the body contains `{"error": "...", "error_description": "..."}`,
/// returns an AuthError of kind `ProviderKind`. Otherwise returns `Ok(body)` so
/// the caller can proceed with success parsing.
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
      Error(error.provider(code: code, description: description, uri: uri))
    Error(_) -> Ok(body)
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
      error.config(reason: "Invalid redirect URI: " <> redirect_uri)
    }),
  )
  let https_error =
    Error(error.config(
      reason: "Redirect URI must use HTTPS (except localhost): " <> redirect_uri,
    ))
  case parsed.scheme {
    option.Some("https") ->
      case parsed.host {
        option.Some("") | option.None ->
          Error(error.config(
            reason: "Redirect URI must include a host: " <> redirect_uri,
          ))
        option.Some(_) -> Ok(parsed)
      }
    option.Some("http") ->
      case parsed.host {
        option.Some("localhost") | option.Some("127.0.0.1") -> Ok(parsed)
        option.Some(_) | option.None -> https_error
      }
    option.Some(_) | option.None -> https_error
  }
}

/// Append additional query parameters to a URL.
pub fn append_query_params(
  url: String,
  parameters: List(#(String, String)),
) -> String {
  case parameters {
    [] -> url
    _ -> {
      let separator = case string.contains(url, "?") {
        True -> "&"
        False -> "?"
      }
      url <> separator <> uri.query_to_string(parameters)
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
) -> Result(credential.Credentials, AuthError(e)) {
  use body <- result.try(check_token_error(body))
  parse_oauth_token_success(body, scope_parsing)
}

fn parse_oauth_token_success(
  body: String,
  scope_parsing: ScopeParsing,
) -> Result(credential.Credentials, AuthError(e)) {
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
    Error(decode_error) ->
      Error(error.decode(
        context: "token response",
        reason: string.inspect(decode_error),
      ))
  }
}

fn decode_token_credentials(
  access_token: String,
  refresh_token: option.Option(String),
  token_type: String,
  expires_in: option.Option(Int),
  scope_parsing: ScopeParsing,
) -> decode.Decoder(credential.Credentials) {
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
) -> credential.Credentials {
  credential.new(
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
