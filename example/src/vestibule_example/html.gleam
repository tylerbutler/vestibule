//// Small HTML rendering helpers for the example app.
////
//// Provider-controlled profile fields (name, email, image URL, etc.) must
//// never be concatenated into an HTML response unescaped — doing so allows
//// a malicious or compromised provider to inject markup/scripts and run an
//// XSS attack on the application origin. Text nodes and attribute values are
//// escaped with the `houdini` library (the same escaper `wisp` uses); the
//// image-URL scheme allowlist below is custom because no escaping library
//// validates URL schemes.

import gleam/bool
import gleam/string
import houdini

/// Validate and escape a provider-supplied image URL for use in an `src`
/// attribute. Only `https://` URLs are allowed; anything else (including
/// `http://`, `javascript:`, `data:`, and protocol-relative URLs) is
/// rejected to avoid mixed-content and script-injection vectors.
///
/// Returns the attribute-escaped URL when safe, or `Error(Nil)` when the
/// scheme is not allowlisted.
pub fn safe_image_url(url: String) -> Result(String, Nil) {
  use <- bool.guard(
    when: !string.starts_with(string.lowercase(url), "https://"),
    return: Error(Nil),
  )
  Ok(houdini.escape(url))
}
