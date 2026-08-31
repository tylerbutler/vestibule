//// IndieAuth endpoint discovery.
////
//// Implements the discovery algorithm from IndieAuth spec Section 4.1:
//// 1. Fetch the user's profile URL
//// 2. Look for `rel="indieauth-metadata"` — if found, fetch metadata JSON
//// 3. Fall back to `rel="authorization_endpoint"` and `rel="token_endpoint"`
//// 4. Check HTTP `Link` headers first, then HTML `<link>` tags

import gleam/bool
import gleam/dynamic/decode
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

import presentable_soup as soup

import vestibule/error.{type AuthError}
import vestibule/provider_support
import vestibule_indieauth/url

/// Endpoints discovered from a user's IndieAuth server.
pub type DiscoveredEndpoints {
  DiscoveredEndpoints(
    /// The authorization endpoint URL.
    authorization_endpoint: String,
    /// The token endpoint URL.
    token_endpoint: String,
    /// The server's issuer identifier (from metadata, if available).
    issuer: Option(String),
    /// The userinfo endpoint URL (from metadata, if available).
    userinfo_endpoint: Option(String),
  )
}

/// Result of parsing a profile-page discovery response.
///
/// A profile can either contain the authorization and token endpoint links
/// directly, or point to a metadata document that requires one more request.
pub type ProfileDiscovery {
  EndpointsDiscovered(DiscoveredEndpoints)
  MetadataRequired(url: String)
}

/// Discover IndieAuth endpoints from a user's profile URL.
///
/// Fetches the URL and discovers endpoints using the three-tier fallback:
/// 1. IndieAuth server metadata (`rel="indieauth-metadata"`)
/// 2. Direct link relations (`rel="authorization_endpoint"`, `rel="token_endpoint"`)
/// 3. HTTP `Link` headers take precedence over HTML `<link>` tags
pub fn discover_endpoints(
  profile_url: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  use http_request <- result.try(build_profile_request(profile_url))

  use response <- result.try(provider_support.send_public(http_request))

  use discovery <- result.try(parse_profile_response(profile_url, response))
  case discovery {
    EndpointsDiscovered(endpoints) -> Ok(endpoints)
    MetadataRequired(metadata_url) -> fetch_metadata(metadata_url)
  }
}

/// Build the request used to discover endpoints from a profile page.
///
/// The profile URL must be public HTTPS. The returned request is opaque and
/// can only be sent with `provider_support.send_public`, so DNS validation and
/// address pinning cannot be accidentally bypassed.
pub fn build_profile_request(
  profile_url: String,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use profile_url <- result.try(url.validate_profile_url(profile_url))
  use http_request <- result.try(
    request.to(profile_url)
    |> result.replace_error(error.config(
      reason: "Invalid profile URL: " <> profile_url,
    )),
  )
  http_request
  |> request.set_header("accept", "text/html, application/xhtml+xml")
  |> provider_support.secure_request_with_limit(
    provider_support.ProfileHtmlResponse,
  )
}

/// Parse a profile-page discovery HTTP response without performing I/O.
pub fn parse_profile_response(
  profile_url: String,
  http_response: response.Response(String),
) -> Result(ProfileDiscovery, AuthError(e)) {
  case http_response.status {
    status if status >= 200 && status < 300 ->
      case
        find_metadata_url(
          http_response.headers,
          http_response.body,
          profile_url,
        )
      {
        Some(metadata_url) -> {
          use _ <- result.try(provider_support.require_public_https_format(
            metadata_url,
          ))
          Ok(MetadataRequired(metadata_url))
        }
        None ->
          discover_from_link_relations(
            http_response.headers,
            http_response.body,
            profile_url,
          )
          |> result.map(EndpointsDiscovered)
      }
    status ->
      Error(error.network(
        reason: "Profile URL returned HTTP "
        <> int.to_string(status)
        <> ": "
        <> profile_url,
      ))
  }
}

/// Look for `rel="indieauth-metadata"` in HTTP Link headers then HTML.
fn find_metadata_url(
  headers: List(#(String, String)),
  body: String,
  base_url: String,
) -> Option(String) {
  find_link_header_relation(headers, "indieauth-metadata")
  |> option.lazy_or(fn() { find_html_link_relation(body, "indieauth-metadata") })
  |> option.map(resolve_url(_, base_url))
}

/// Fetch and parse IndieAuth server metadata JSON.
fn fetch_metadata(
  metadata_url: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  use http_request <- result.try(build_metadata_request(metadata_url))

  use response <- result.try(provider_support.send_public(http_request))

  parse_metadata_response(metadata_url, response)
}

/// Build an IndieAuth metadata request without sending it.
///
/// The returned request is opaque and must be sent with
/// `provider_support.send_public`.
pub fn build_metadata_request(
  metadata_url: String,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use _ <- result.try(provider_support.require_public_https_format(metadata_url))
  use http_request <- result.try(
    request.to(metadata_url)
    |> result.replace_error(error.config(
      reason: "Invalid metadata URL: " <> metadata_url,
    )),
  )
  http_request
  |> request.set_header("accept", "application/json")
  |> provider_support.secure_request_with_limit(
    provider_support.DiscoveryResponse,
  )
}

/// Parse an IndieAuth metadata HTTP response without performing I/O.
pub fn parse_metadata_response(
  metadata_url: String,
  http_response: response.Response(String),
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  case http_response.status {
    status if status >= 200 && status < 300 -> parse_metadata(http_response.body)
    status ->
      Error(error.network(
        reason: "Metadata endpoint returned HTTP "
        <> int.to_string(status)
        <> ": "
        <> metadata_url,
      ))
  }
}

/// Parse IndieAuth server metadata JSON.
/// Exported for testing.
pub fn parse_metadata(
  body: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  let decoder = {
    use authorization_endpoint <- decode.field(
      "authorization_endpoint",
      decode.string,
    )
    use token_endpoint <- decode.field("token_endpoint", decode.string)
    use issuer <- decode.optional_field(
      "issuer",
      None,
      decode.optional(decode.string),
    )
    use userinfo_endpoint <- decode.optional_field(
      "userinfo_endpoint",
      None,
      decode.optional(decode.string),
    )
    decode.success(DiscoveredEndpoints(
      authorization_endpoint: authorization_endpoint,
      token_endpoint: token_endpoint,
      issuer: issuer,
      userinfo_endpoint: userinfo_endpoint,
    ))
  }

  case json.parse(body, decoder) {
    Ok(endpoints) -> validate_endpoints(endpoints)
    Error(parse_error) ->
      Error(error.config(
        reason: "Failed to parse IndieAuth metadata: "
        <> string.inspect(parse_error),
      ))
  }
}

/// Require every discovered endpoint to be a structurally safe HTTPS URL.
///
/// Discovered endpoints are chosen by whoever controls the profile URL, so
/// without this check a login attempt could point the server's token or
/// userinfo requests at loopback, private, or cloud-metadata addresses
/// (SSRF). Literal non-public addresses are rejected here. Immediately before
/// each server-side request, `provider_support.send_public` additionally
/// resolves every DNS answer, rejects mixed/non-public results, and pins the
/// validated address to the connection.
pub fn validate_endpoints(
  endpoints: DiscoveredEndpoints,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  use _ <- result.try(provider_support.require_public_https_format(
    endpoints.authorization_endpoint,
  ))
  use _ <- result.try(provider_support.require_public_https_format(
    endpoints.token_endpoint,
  ))
  use _ <- result.try(require_public_https_option(endpoints.issuer))
  use _ <- result.try(require_public_https_option(endpoints.userinfo_endpoint))
  Ok(endpoints)
}

fn require_public_https_option(
  url: Option(String),
) -> Result(Nil, AuthError(e)) {
  case url {
    Some(value) -> provider_support.require_public_https_format(value)
    None -> Ok(Nil)
  }
}

/// Discover endpoints from direct link relations (legacy fallback).
fn discover_from_link_relations(
  headers: List(#(String, String)),
  body: String,
  base_url: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  // Try HTTP Link headers first, fall back to HTML for each endpoint
  let authorization_endpoint =
    find_link_header_relation(headers, "authorization_endpoint")
    |> option.lazy_or(fn() {
      find_html_link_relation(body, "authorization_endpoint")
    })
    |> option.map(resolve_url(_, base_url))

  let token_endpoint =
    find_link_header_relation(headers, "token_endpoint")
    |> option.lazy_or(fn() { find_html_link_relation(body, "token_endpoint") })
    |> option.map(resolve_url(_, base_url))

  case authorization_endpoint, token_endpoint {
    Some(authorization_endpoint), Some(token_endpoint) ->
      validate_endpoints(DiscoveredEndpoints(
        authorization_endpoint: authorization_endpoint,
        token_endpoint: token_endpoint,
        issuer: None,
        userinfo_endpoint: None,
      ))
    Some(_), None ->
      Error(error.config(
        reason: "Found authorization_endpoint but no token_endpoint at "
        <> base_url,
      ))
    None, Some(_) ->
      Error(error.config(
        reason: "Could not discover IndieAuth endpoints at "
        <> base_url
        <> ". No indieauth-metadata or authorization_endpoint found.",
      ))
    None, None ->
      Error(error.config(
        reason: "Could not discover IndieAuth endpoints at "
        <> base_url
        <> ". No indieauth-metadata or authorization_endpoint found.",
      ))
  }
}

/// Parse HTTP Link headers to find a URL with the given rel value.
///
/// Handles the format: `<URL>; rel="value"` or `<URL>; rel=value`
/// Exported for testing.
pub fn find_link_header_relation(
  headers: List(#(String, String)),
  relation: String,
) -> Option(String) {
  headers
  |> list.filter_map(fn(header) {
    let #(name, value) = header
    case string.lowercase(name) == "link" {
      True -> parse_link_header_value(value, relation)
      False -> Error(Nil)
    }
  })
  |> list.first()
  |> option.from_result()
}

/// Parse a single Link header value to extract URL for a given rel.
fn parse_link_header_value(
  value: String,
  target_relation: String,
) -> Result(String, Nil) {
  // Link headers can contain multiple comma-separated entries
  let entries = string.split(value, ",")
  entries
  |> list.filter_map(fn(entry) {
    let entry = string.trim(entry)
    // Extract URL between < and >
    use #(_, rest) <- result.try(string.split_once(entry, "<"))
    use #(url, parameters) <- result.try(string.split_once(rest, ">"))
    use <- bool.guard(
      when: !has_relation_parameter(parameters, target_relation),
      return: Error(Nil),
    )
    Ok(string.trim(url))
  })
  |> list.first()
}

/// Check if Link header parameters contain the target relation value.
fn has_relation_parameter(parameters: String, target_relation: String) -> Bool {
  let lowercase_parameters = string.lowercase(parameters)
  let lowercase_target = string.lowercase(target_relation)

  // Look for rel="value" or rel=value
  string.contains(lowercase_parameters, "rel=\"" <> lowercase_target <> "\"")
  || string.contains(lowercase_parameters, "rel=" <> lowercase_target)
}

/// Find an HTML `<link>` element with the given rel attribute.
///
/// Uses presentable_soup for robust HTML parsing.
/// Exported for testing.
pub fn find_html_link_relation(
  html: String,
  relation: String,
) -> Option(String) {
  let query =
    soup.elements([
      soup.with_tag("link"),
      soup.with_attribute("rel", relation),
    ])
    |> soup.return(soup.attributes())
    |> soup.scrape(html)

  case query {
    Ok([attributes, ..]) -> find_href(attributes)
    Ok([]) -> None
    Error(_) -> None
  }
}

/// Extract the href from a list of element attributes.
fn find_href(attributes: List(#(String, String))) -> Option(String) {
  list.key_find(attributes, "href")
  |> option.from_result()
}

/// Resolve a potentially relative URL against a base URL.
fn resolve_url(url: String, base_url: String) -> String {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        Some(_) -> url
        None ->
          case uri.parse(base_url) {
            Ok(base) -> {
              uri.to_string(uri.Uri(
                scheme: base.scheme,
                userinfo: None,
                host: base.host,
                port: base.port,
                path: resolve_path(base.path, parsed.path),
                query: parsed.query,
                fragment: None,
              ))
            }
            Error(_) -> url
          }
      }
    Error(_) -> url
  }
}

/// Resolve a relative path against a base path.
fn resolve_path(base_path: String, relative_path: String) -> String {
  use <- bool.guard(
    when: string.starts_with(relative_path, "/"),
    return: relative_path,
  )
  // Remove the last segment from base path and append relative
  let base_directory = case string.split(base_path, "/") {
    [] -> "/"
    segments -> {
      let directory_segments = list.take(segments, list.length(segments) - 1)
      string.join(directory_segments, "/")
    }
  }
  base_directory <> "/" <> relative_path
}
