/// URL validation and canonicalization for IndieAuth.
///
/// Implements the URL requirements from the IndieAuth specification:
/// - Section 3.2: User Profile URL
/// - Section 3.3: Client Identifier
/// - Section 3.4: URL Canonicalization
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/uri.{type Uri}

import vestibule/error.{type AuthError}

/// Validate a user profile URL per IndieAuth spec Section 3.2.
///
/// Profile URLs MUST:
/// - Have `https` or `http` scheme
/// - Contain a path component (`/` is valid)
/// - Not contain single-dot or double-dot path segments
/// - Not contain a fragment
/// - Not contain a username or password
/// - Not contain a port
/// - Have a domain name host (not an IP address)
pub fn validate_profile_url(raw_url: String) -> Result(String, AuthError(e)) {
  let url = canonicalize(raw_url)
  case uri.parse(url) {
    Ok(parsed) -> validate_profile_uri(parsed, url)
    Error(_) ->
      Error(error.ConfigError(
        reason: "Invalid URL: could not parse \"" <> raw_url <> "\"",
      ))
  }
}

fn validate_profile_uri(
  parsed: Uri,
  url: String,
) -> Result(String, AuthError(e)) {
  use _ <- result.try(case parsed.scheme {
    Some("https") | Some("http") -> Ok(Nil)
    Some(scheme) ->
      Error(error.ConfigError(
        reason: "Profile URL must use https or http scheme, got: " <> scheme,
      ))
    None -> Error(error.ConfigError(reason: "Profile URL is missing a scheme"))
  })
  use _ <- result.try(case parsed.host {
    Some(host) if host != "" ->
      case is_ip_address(host) {
        True ->
          Error(error.ConfigError(
            reason: "Profile URL host must be a domain name, not an IP address: "
            <> host,
          ))
        False -> Ok(Nil)
      }
    _ -> Error(error.ConfigError(reason: "Profile URL is missing a host"))
  })
  use _ <- result.try(case parsed.port {
    Some(_) ->
      Error(error.ConfigError(reason: "Profile URL must not contain a port"))
    None -> Ok(Nil)
  })
  use _ <- result.try(case parsed.fragment {
    Some(_) ->
      Error(error.ConfigError(reason: "Profile URL must not contain a fragment"))
    None -> Ok(Nil)
  })
  use _ <- result.try(case parsed.userinfo {
    Some(_) ->
      Error(error.ConfigError(
        reason: "Profile URL must not contain username or password",
      ))
    None -> Ok(Nil)
  })
  case has_dot_segments(parsed.path) {
    True ->
      Error(error.ConfigError(
        reason: "Profile URL must not contain . or .. path segments",
      ))
    False -> Ok(url)
  }
}

/// Canonicalize a URL per IndieAuth spec Section 3.4.
///
/// - If no scheme, prepend `https://`
/// - If no path, append `/`
/// - Lowercase the host
pub fn canonicalize(raw_url: String) -> String {
  let url = case
    string.starts_with(raw_url, "http://")
    || string.starts_with(raw_url, "https://")
  {
    True -> raw_url
    False -> "https://" <> raw_url
  }

  case uri.parse(url) {
    Ok(parsed) -> {
      let host = case parsed.host {
        Some(h) -> Some(string.lowercase(h))
        None -> None
      }
      let path = case parsed.path {
        "" -> "/"
        p -> p
      }
      uri.to_string(uri.Uri(
        scheme: parsed.scheme,
        userinfo: parsed.userinfo,
        host: host,
        port: parsed.port,
        path: path,
        query: parsed.query,
        fragment: parsed.fragment,
      ))
    }
    Error(_) -> url
  }
}

/// Check if a string looks like an IP address (v4 or v6).
fn is_ip_address(host: String) -> Bool {
  case string.starts_with(host, "[") {
    True -> True
    False ->
      string.to_graphemes(host)
      |> list.all(fn(c) {
        c == "."
        || c == "0"
        || c == "1"
        || c == "2"
        || c == "3"
        || c == "4"
        || c == "5"
        || c == "6"
        || c == "7"
        || c == "8"
        || c == "9"
      })
  }
}

/// Check if a path contains . or .. segments.
fn has_dot_segments(path: String) -> Bool {
  string.split(path, "/")
  |> list.any(fn(seg) { seg == "." || seg == ".." })
}
