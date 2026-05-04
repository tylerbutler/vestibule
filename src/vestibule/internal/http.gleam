/// Internal compatibility wrappers for provider support helpers.
import gleam/http/response.{type Response}
import gleam/uri
import vestibule/error.{type AuthError}
import vestibule/provider_support

/// Check that an HTTP response has a 2xx status code.
pub fn check_response_status(
  response: Response(String),
) -> Result(String, AuthError(e)) {
  provider_support.check_response_status(response)
}

/// Validate that a URL uses HTTPS.
pub fn require_https(url: String) -> Result(Nil, AuthError(e)) {
  provider_support.require_https(url)
}

/// Fetch JSON from a URL with authentication.
pub fn fetch_json_with_auth(
  url: String,
  auth_header: String,
  parse: fn(String) -> Result(a, AuthError(e)),
  provider_name: String,
) -> Result(a, AuthError(e)) {
  provider_support.fetch_json_with_auth(url, auth_header, parse, provider_name)
}

/// Check a JSON response body for an OAuth2 error response.
pub fn check_token_error(body: String) -> Result(String, AuthError(e)) {
  provider_support.check_token_error(body)
}

/// Parse and validate a redirect URI.
pub fn parse_redirect_uri(
  redirect_uri: String,
) -> Result(uri.Uri, AuthError(e)) {
  provider_support.parse_redirect_uri(redirect_uri)
}

/// Append additional query params to a URL.
pub fn append_query_params(
  url: String,
  params: List(#(String, String)),
) -> String {
  provider_support.append_query_params(url, params)
}
