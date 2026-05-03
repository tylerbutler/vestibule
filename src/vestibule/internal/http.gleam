/// Internal HTTP helpers shared across vestibule modules.
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
