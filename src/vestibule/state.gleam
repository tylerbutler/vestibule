import gleam/bit_array
import gleam/crypto

import vestibule/error.{type AuthError, StateMismatch}

/// Generate a cryptographically random state parameter.
/// Returns 32 bytes of random data, base64url-encoded (no padding).
pub fn generate() -> String {
  crypto.strong_random_bytes(32)
  |> bit_array.base64_url_encode(False)
}

/// Validate a received state parameter against the expected value.
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate(
  received: String,
  expected: String,
) -> Result(Nil, AuthError) {
  let received_bits = <<received:utf8>>
  let expected_bits = <<expected:utf8>>
  case crypto.secure_compare(received_bits, expected_bits) {
    True -> Ok(Nil)
    False -> Error(StateMismatch)
  }
}
