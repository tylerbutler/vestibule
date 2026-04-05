/// IndieAuth endpoint discovery.
///
/// Implements the discovery algorithm from IndieAuth spec Section 4.1:
/// 1. Fetch the user's profile URL
/// 2. Look for `rel="indieauth-metadata"` — if found, fetch metadata JSON
/// 3. Fall back to `rel="authorization_endpoint"` and `rel="token_endpoint"`
/// 4. Check HTTP `Link` headers first, then HTML `<link>` tags
import gleam/dict
import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

import presentable_soup as soup

import vestibule/error.{type AuthError}

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

/// Discover IndieAuth endpoints from a user's profile URL.
///
/// Fetches the URL and discovers endpoints using the three-tier fallback:
/// 1. IndieAuth server metadata (`rel="indieauth-metadata"`)
/// 2. Direct link relations (`rel="authorization_endpoint"`, `rel="token_endpoint"`)
/// 3. HTTP `Link` headers take precedence over HTML `<link>` tags
pub fn discover_endpoints(
  profile_url: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  use req <- result.try(
    request.to(profile_url)
    |> result.replace_error(error.ConfigError(
      reason: "Invalid profile URL: " <> profile_url,
    )),
  )

  let req =
    request.set_header(req, "accept", "text/html, application/xhtml+xml")

  use response <- result.try(
    httpc.send(req)
    |> result.replace_error(error.NetworkError(
      reason: "Failed to fetch profile URL: " <> profile_url,
    )),
  )

  case response.status {
    status if status >= 200 && status < 300 -> {
      let headers = response.headers
      let body = response.body

      // Try metadata discovery first
      case find_metadata_url(headers, body, profile_url) {
        Some(metadata_url) -> fetch_metadata(metadata_url)
        None -> discover_from_link_rels(headers, body, profile_url)
      }
    }
    status ->
      Error(error.NetworkError(
        reason: "Profile URL returned HTTP "
        <> string.inspect(status)
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
  // Check HTTP Link headers first
  case find_link_header_rel(headers, "indieauth-metadata") {
    Some(url) -> Some(resolve_url(url, base_url))
    None -> {
      // Check HTML <link> tags
      case find_html_link_rel(body, "indieauth-metadata") {
        Some(url) -> Some(resolve_url(url, base_url))
        None -> None
      }
    }
  }
}

/// Fetch and parse IndieAuth server metadata JSON.
fn fetch_metadata(
  metadata_url: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  use req <- result.try(
    request.to(metadata_url)
    |> result.replace_error(error.ConfigError(
      reason: "Invalid metadata URL: " <> metadata_url,
    )),
  )

  let req = request.set_header(req, "accept", "application/json")

  use response <- result.try(
    httpc.send(req)
    |> result.replace_error(error.NetworkError(
      reason: "Failed to fetch IndieAuth metadata: " <> metadata_url,
    )),
  )

  case response.status {
    status if status >= 200 && status < 300 -> parse_metadata(response.body)
    status ->
      Error(error.NetworkError(
        reason: "Metadata endpoint returned HTTP "
        <> string.inspect(status)
        <> ": "
        <> metadata_url,
      ))
  }
}

/// Parse IndieAuth server metadata JSON.
/// Exported for testing.
pub fn parse_metadata(body: String) -> Result(DiscoveredEndpoints, AuthError(e)) {
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
    Ok(endpoints) -> Ok(endpoints)
    Error(err) ->
      Error(error.ConfigError(
        reason: "Failed to parse IndieAuth metadata: " <> string.inspect(err),
      ))
  }
}

/// Discover endpoints from direct link relations (legacy fallback).
fn discover_from_link_rels(
  headers: List(#(String, String)),
  body: String,
  base_url: String,
) -> Result(DiscoveredEndpoints, AuthError(e)) {
  // Try HTTP Link headers first, fall back to HTML for each endpoint
  let auth_endpoint =
    find_link_header_rel(headers, "authorization_endpoint")
    |> option.lazy_or(fn() {
      find_html_link_rel(body, "authorization_endpoint")
    })
    |> option.map(resolve_url(_, base_url))

  let token_endpoint =
    find_link_header_rel(headers, "token_endpoint")
    |> option.lazy_or(fn() { find_html_link_rel(body, "token_endpoint") })
    |> option.map(resolve_url(_, base_url))

  case auth_endpoint, token_endpoint {
    Some(auth), Some(token) ->
      Ok(DiscoveredEndpoints(
        authorization_endpoint: auth,
        token_endpoint: token,
        issuer: None,
        userinfo_endpoint: None,
      ))
    Some(_), None ->
      Error(error.ConfigError(
        reason: "Found authorization_endpoint but no token_endpoint at "
        <> base_url,
      ))
    None, _ ->
      Error(error.ConfigError(
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
pub fn find_link_header_rel(
  headers: List(#(String, String)),
  rel: String,
) -> Option(String) {
  headers
  |> list.filter_map(fn(header) {
    let #(name, value) = header
    case string.lowercase(name) == "link" {
      True -> parse_link_header_value(value, rel)
      False -> Error(Nil)
    }
  })
  |> list.first()
  |> option.from_result()
}

/// Parse a single Link header value to extract URL for a given rel.
fn parse_link_header_value(
  value: String,
  target_rel: String,
) -> Result(String, Nil) {
  // Link headers can contain multiple comma-separated entries
  let entries = string.split(value, ",")
  entries
  |> list.filter_map(fn(entry) {
    let entry = string.trim(entry)
    // Extract URL between < and >
    case string.split_once(entry, "<") {
      Ok(#(_, rest)) ->
        case string.split_once(rest, ">") {
          Ok(#(url, params)) -> {
            // Check if rel matches
            case has_rel_param(params, target_rel) {
              True -> Ok(string.trim(url))
              False -> Error(Nil)
            }
          }
          Error(_) -> Error(Nil)
        }
      Error(_) -> Error(Nil)
    }
  })
  |> list.first()
}

/// Check if a Link header params string contains the target rel value.
fn has_rel_param(params: String, target_rel: String) -> Bool {
  let params_lower = string.lowercase(params)
  let target_lower = string.lowercase(target_rel)

  // Look for rel="value" or rel=value
  string.contains(params_lower, "rel=\"" <> target_lower <> "\"")
  || string.contains(params_lower, "rel=" <> target_lower)
}

/// Find an HTML `<link>` element with the given rel attribute.
///
/// Uses presentable_soup for robust HTML parsing.
/// Exported for testing.
pub fn find_html_link_rel(html: String, rel: String) -> Option(String) {
  let query =
    soup.elements([soup.with_tag("link"), soup.with_attribute("rel", rel)])
    |> soup.return(soup.attributes())
    |> soup.scrape(html)

  case query {
    Ok([attrs, ..]) -> find_href(attrs)
    _ -> None
  }
}

/// Extract the href from a list of element attributes.
fn find_href(attrs: List(#(String, String))) -> Option(String) {
  attrs
  |> dict.from_list()
  |> dict.get("href")
  |> option.from_result()
}

/// Resolve a potentially relative URL against a base URL.
fn resolve_url(url: String, base_url: String) -> String {
  case uri.parse(url) {
    Ok(parsed) ->
      case parsed.scheme {
        // Already absolute
        Some(_) -> url
        // Relative — resolve against base
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
  case string.starts_with(relative_path, "/") {
    True -> relative_path
    False -> {
      // Remove the last segment from base path and append relative
      let base_dir = case string.split(base_path, "/") {
        [] -> "/"
        segments -> {
          let dir_segments = list.take(segments, list.length(segments) - 1)
          string.join(dir_segments, "/")
        }
      }
      base_dir <> "/" <> relative_path
    }
  }
}
