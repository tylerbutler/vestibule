//// OIDC `nonce` generation and constant-time validation. A fresh 256-bit
//// base64url nonce is minted for every OIDC authorization request, sent as
//// the `nonce` authorize-request parameter, and echoed back by the provider
//// in the signed `id_token`. On callback the value read from the id_token is
//// compared against the stored value to bind the token to this browser
//// session, preventing id_token replay/injection.

import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/string

import vestibule/error.{type AuthError, InvalidNonce}

/// Generate a cryptographically random nonce.
/// Returns 32 bytes of random data, base64url-encoded (no padding).
pub fn generate() -> String {
  crypto.strong_random_bytes(32)
  |> bit_array.base64_url_encode(False)
}

/// Validate a received nonce against the expected value.
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate(
  received received: String,
  expected expected: String,
) -> Result(Nil, AuthError(e)) {
  use <- bool.guard(
    when: is_blank(received) || is_blank(expected),
    return: Error(InvalidNonce),
  )
  let received_bits = <<received:utf8>>
  let expected_bits = <<expected:utf8>>
  case crypto.secure_compare(received_bits, expected_bits) {
    True -> Ok(Nil)
    False -> Error(InvalidNonce)
  }
}

fn is_blank(value: String) -> Bool {
  string.trim(value) == ""
}
