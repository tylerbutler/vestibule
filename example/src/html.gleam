//// Small HTML rendering helpers for the example app.
////
//// Provider-controlled profile fields (name, email, image URL, etc.) must
//// never be concatenated into an HTML response unescaped — doing so allows
//// a malicious or compromised provider to inject markup/scripts and run an
//// XSS attack on the application origin. Always route provider data through
//// these helpers before rendering.

import gleam/option.{type Option, None, Some}
import gleam/string

/// HTML-escape a text node so it is rendered as literal text rather than
/// markup. Also safe for use inside double-quoted attribute values.
pub fn escape(text: String) -> String {
  text
  |> string.replace("&", "&amp;")
  |> string.replace("<", "&lt;")
  |> string.replace(">", "&gt;")
  |> string.replace("\"", "&quot;")
  |> string.replace("'", "&#39;")
}

/// Validate and escape a provider-supplied image URL for use in an `src`
/// attribute. Only `https://` URLs are allowed; anything else (including
/// `http://`, `javascript:`, `data:`, and protocol-relative URLs) is
/// rejected to avoid mixed-content and script-injection vectors.
///
/// Returns the attribute-escaped URL when safe, or `None` when the scheme is
/// not allowlisted.
pub fn safe_image_url(url: String) -> Option(String) {
  case string.starts_with(string.lowercase(url), "https://") {
    True -> Some(escape(url))
    False -> None
  }
}
