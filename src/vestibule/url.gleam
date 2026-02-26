/// URL validation utilities for OAuth2 security.
///
/// Provides HTTPS enforcement for OAuth endpoint URLs to prevent
/// tokens from being transmitted in cleartext. Development-friendly
/// exceptions are made for localhost addresses.
import gleam/option.{Some}
import gleam/string
import gleam/uri

/// Validate that a URL uses the HTTPS scheme.
///
/// Returns `Ok(url)` if the URL uses HTTPS, or if it uses HTTP with a
/// localhost address (for development). Returns `Error(reason)` otherwise.
///
/// Allowed development URLs (HTTP):
/// - `http://localhost`
/// - `http://127.0.0.1`
/// - `http://[::1]`
///
/// ## Examples
///
/// ```gleam
/// validate_https_url("https://example.com/callback")
/// // -> Ok("https://example.com/callback")
///
/// validate_https_url("http://localhost:8080/callback")
/// // -> Ok("http://localhost:8080/callback")
///
/// validate_https_url("http://example.com/callback")
/// // -> Error("URL must use HTTPS scheme: http://example.com/callback")
/// ```
pub fn validate_https_url(url: String) -> Result(String, String) {
  case uri.parse(url) {
    Ok(parsed) -> validate_parsed_url(url, parsed)
    Error(_) -> Error("Invalid URL: " <> url)
  }
}

fn validate_parsed_url(url: String, parsed: uri.Uri) -> Result(String, String) {
  case parsed.scheme {
    Some("https") -> Ok(url)
    Some("http") -> validate_http_localhost(url, parsed)
    Some(scheme) ->
      Error("URL must use HTTPS scheme, got " <> scheme <> ": " <> url)
    _ -> Error("URL is missing a scheme: " <> url)
  }
}

fn validate_http_localhost(
  url: String,
  parsed: uri.Uri,
) -> Result(String, String) {
  case parsed.host {
    Some(host) -> {
      let is_localhost = case string.lowercase(host) {
        "localhost" -> True
        "127.0.0.1" -> True
        "::1" -> True
        "[::1]" -> True
        _ -> False
      }
      case is_localhost {
        True -> Ok(url)
        False ->
          Error(
            "URL must use HTTPS scheme (HTTP is only allowed for localhost): "
            <> url,
          )
      }
    }
    _ ->
      Error(
        "URL must use HTTPS scheme (HTTP is only allowed for localhost): "
        <> url,
      )
  }
}
