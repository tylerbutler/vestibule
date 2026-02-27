/// Internal HTTP helpers shared across vestibule modules.
import gleam/http/response.{type Response}
import gleam/int
import gleam/option
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
