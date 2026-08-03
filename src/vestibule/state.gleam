//// CSRF state token generation and constant-time validation. A fresh
//// 256-bit base64url token is minted for every authorization request and
//// must be echoed back unchanged on the callback.

import vestibule/error.{type AuthError}
import vestibule/internal/one_time_token

/// Generate a cryptographically random state parameter.
/// Returns 32 bytes of random data, base64url-encoded (no padding).
pub fn generate() -> String {
  one_time_token.generate()
}

/// Validate a received state parameter against the expected value.
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate(
  received received: String,
  expected expected: String,
) -> Result(Nil, AuthError(e)) {
  one_time_token.validate(
    received: received,
    expected: expected,
    mismatch_error: error.state_mismatch(),
  )
}
