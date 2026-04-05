/// Internal HTTP helpers shared across vestibule modules.
import gleam/http/response.{type Response}
import gleam/int
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

/// Parse and validate a redirect URI.
///
/// Redirect URIs must be valid URLs and use HTTPS, except localhost/127.0.0.1
/// which are allowed for local development.
pub fn parse_redirect_uri(redirect_uri: String) -> Result(uri.Uri, AuthError(e)) {
  use parsed <- result.try(
    uri.parse(redirect_uri)
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Invalid redirect URI: " <> redirect_uri)
    }),
  )
  use _ <- result.try(
    require_https(redirect_uri)
    |> result.map_error(fn(_) {
      error.ConfigError(
        reason: "Redirect URI must use HTTPS (except localhost): "
        <> redirect_uri,
      )
    }),
  )
  Ok(parsed)
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
