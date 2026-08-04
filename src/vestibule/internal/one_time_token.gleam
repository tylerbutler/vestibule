//// Shared implementation for single-use anti-forgery tokens — the CSRF
//// `state` parameter and the OIDC `nonce`. Provides 256-bit random token
//// generation and constant-time validation; the public `vestibule/state`
//// and `vestibule/nonce` modules wrap this with their domain-specific
//// errors.

import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/string

import vestibule/error.{type AuthError}

/// Generate a cryptographically random token.
/// Returns 32 bytes of random data, base64url-encoded (no padding).
pub fn generate() -> String {
  crypto.strong_random_bytes(32)
  |> bit_array.base64_url_encode(False)
}

/// Validate a received token against the expected value using constant-time
/// comparison to prevent timing attacks. Blank values and mismatches both
/// fail with `mismatch_error`.
pub fn validate(
  received received: String,
  expected expected: String,
  mismatch_error mismatch_error: AuthError(e),
) -> Result(Nil, AuthError(e)) {
  use <- bool.guard(
    when: is_blank(received) || is_blank(expected),
    return: Error(mismatch_error),
  )
  case crypto.secure_compare(<<received:utf8>>, <<expected:utf8>>) {
    True -> Ok(Nil)
    False -> Error(mismatch_error)
  }
}

fn is_blank(value: String) -> Bool {
  string.trim(value) == ""
}
