//// OIDC `nonce` generation and constant-time validation. A fresh 256-bit
//// base64url nonce is minted for every OIDC authorization request, sent as
//// the `nonce` authorize-request parameter, and echoed back by the provider
//// in the signed `id_token`. On callback the value read from the id_token is
//// compared against the stored value to bind the token to this browser
//// session, preventing id_token replay/injection.

import vestibule/error.{type AuthError}
import vestibule/internal/one_time_token

/// Generate a cryptographically random nonce.
/// Returns 32 bytes of random data, base64url-encoded (no padding).
pub fn generate() -> String {
  one_time_token.generate()
}

/// Validate a received nonce against the expected value.
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate(
  received received: String,
  expected expected: String,
) -> Result(Nil, AuthError(e)) {
  one_time_token.validate(
    received: received,
    expected: expected,
    mismatch_error: error.invalid_nonce(),
  )
}
