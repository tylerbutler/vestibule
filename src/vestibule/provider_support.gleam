/// Stable helpers for OAuth provider implementations.
import gleam/dynamic/decode
import gleam/http/request
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/int
import gleam/json
import gleam/option
import gleam/result
import gleam/string
import gleam/uri
import vestibule/error.{type AuthError}

import vestibule/credentials.{type Credentials, Credentials}

/// Check that an HTTP response has a 2xx status code.
/// Returns the response body on success, or a NetworkError on failure.
pub fn check_response_status(
  response: Response(String),
) -> Result(String, AuthError(e)) {
  case response.status >= 200 && response.status < 300 {
    True -> Ok(response.body)
    False ->
      Error(error.NetworkError(
        reason: "HTTP "
        <> int.to_string(response.status)
        <> ": "
        <> response.body,
      ))
  }
}

/// Validate that a URL uses HTTPS.
/// HTTP is allowed for localhost and 127.0.0.1 (development use).
/// Returns Ok(Nil) if valid, or a ConfigError describing the issue.
pub fn require_https(url: String) -> Result(Nil, AuthError(e)) {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        option.Some("https") -> Ok(Nil)
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
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(check_response_status(response))
      parse(body)
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to " <> provider_name <> " API: " <> url,
      ))
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
    decode.success(#(error_code, description))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description)) ->
      Error(error.ProviderError(code: code, description: description))
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
    option.Some("https") -> Ok(parsed)
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
) -> Result(Credentials, AuthError(e)) {
  use body <- result.try(check_token_error(body))
  parse_oauth_token_success(body, scope_parsing)
}

fn parse_oauth_token_success(
  body: String,
  scope_parsing: ScopeParsing,
) -> Result(Credentials, AuthError(e)) {
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
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse token response: " <> string.inspect(err),
      ))
  }
}

fn decode_token_credentials(
  access_token: String,
  refresh_token: option.Option(String),
  token_type: String,
  expires_in: option.Option(Int),
  scope_parsing: ScopeParsing,
) -> decode.Decoder(Credentials) {
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
) -> Credentials {
  Credentials(
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
