/// URL validation and canonicalization for IndieAuth.
///
/// Implements the URL requirements from the IndieAuth specification:
/// - Section 3.2: User Profile URL
/// - Section 3.3: Client Identifier
/// - Section 3.4: URL Canonicalization
import gleam/option.{None, Some}
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
  // Must have https or http scheme
  case parsed.scheme {
    Some("https") | Some("http") -> Ok(Nil)
    Some(scheme) ->
      Error(error.ConfigError(
        reason: "Profile URL must use https or http scheme, got: " <> scheme,
      ))
    None -> Error(error.ConfigError(reason: "Profile URL is missing a scheme"))
  }
  |> then(fn() {
    // Must have a host
    case parsed.host {
      Some(host) if host != "" -> {
        // Must be a domain name, not an IP address
        case is_ip_address(host) {
          True ->
            Error(error.ConfigError(
              reason: "Profile URL host must be a domain name, not an IP address: "
              <> host,
            ))
          False -> Ok(Nil)
        }
      }
      _ -> Error(error.ConfigError(reason: "Profile URL is missing a host"))
    }
  })
  |> then(fn() {
    // Must not contain a port
    case parsed.port {
      Some(_) ->
        Error(error.ConfigError(reason: "Profile URL must not contain a port"))
      None -> Ok(Nil)
    }
  })
  |> then(fn() {
    // Must not contain a fragment
    case parsed.fragment {
      Some(_) ->
        Error(error.ConfigError(
          reason: "Profile URL must not contain a fragment",
        ))
      None -> Ok(Nil)
    }
  })
  |> then(fn() {
    // Must not contain userinfo (username/password)
    case parsed.userinfo {
      Some(_) ->
        Error(error.ConfigError(
          reason: "Profile URL must not contain username or password",
        ))
      None -> Ok(Nil)
    }
  })
  |> then(fn() {
    // Must have a path (canonicalize ensures "/" is present)
    // Must not contain single-dot or double-dot path segments
    let path = case parsed.path {
      "" -> "/"
      p -> p
    }
    case has_dot_segments(path) {
      True ->
        Error(error.ConfigError(
          reason: "Profile URL must not contain . or .. path segments",
        ))
      False -> Ok(Nil)
    }
  })
  |> result_map(fn() { url })
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

/// Encode a list of key-value pairs as a URL query string.
pub fn encode_query_params(params: List(#(String, String))) -> String {
  uri.query_to_string(params)
}

/// Check if a string looks like an IP address (v4 or v6).
fn is_ip_address(host: String) -> Bool {
  // IPv6 in brackets
  case string.starts_with(host, "[") {
    True -> True
    False -> {
      // IPv4: all characters are digits or dots
      let chars = string.to_graphemes(host)
      case chars {
        [] -> False
        _ ->
          chars
          |> list_all(fn(c) {
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
  }
}

/// Check if a path contains . or .. segments.
fn has_dot_segments(path: String) -> Bool {
  let segments = string.split(path, "/")
  segments
  |> list_any(fn(seg) { seg == "." || seg == ".." })
}

// Helpers to avoid importing gleam/list at module level
// (keeping imports minimal for a utility module)

fn list_all(items: List(a), predicate: fn(a) -> Bool) -> Bool {
  case items {
    [] -> True
    [first, ..rest] ->
      case predicate(first) {
        True -> list_all(rest, predicate)
        False -> False
      }
  }
}

fn list_any(items: List(a), predicate: fn(a) -> Bool) -> Bool {
  case items {
    [] -> False
    [first, ..rest] ->
      case predicate(first) {
        True -> True
        False -> list_any(rest, predicate)
      }
  }
}

/// Chain Result checks — if the first is Ok, run the next check.
fn then(
  result: Result(Nil, AuthError(e)),
  next: fn() -> Result(Nil, AuthError(e)),
) -> Result(Nil, AuthError(e)) {
  case result {
    Ok(_) -> next()
    Error(err) -> Error(err)
  }
}

/// Map a Result(Nil, err) to Result(a, err) on success.
fn result_map(
  result: Result(Nil, AuthError(e)),
  value: fn() -> String,
) -> Result(String, AuthError(e)) {
  case result {
    Ok(_) -> Ok(value())
    Error(err) -> Error(err)
  }
}
