//// HMAC JWT signing helpers for tests.
////
//// The signing counterpart to `vestibule_apple/jwt`, kept in `test/` so the
//// published library ships verification only.

import gleam/crypto
import gleam/json
import ywt/claim.{type Claim}
import ywt/internal/core
import ywt/internal/jwt
import ywt/sign_key.{type SignKey}

/// Create a signed JWT (HMAC only).
pub fn encode(
  payload payload: List(#(String, json.Json)),
  claims claims: List(Claim),
  key key: SignKey,
) -> String {
  let sign = fn(message, key, next) { next(sign_bits(message, key)) }
  jwt.encode(payload:, claims:, key:, sign:)
}

/// Generate an HMAC-SHA256 signing key.
pub fn generate_test_key() -> SignKey {
  let assert Ok(key) = sign_key.hs256(crypto.strong_random_bytes(32))
  key
}

fn sign_bits(message: BitArray, key: SignKey) -> BitArray {
  sign_key.match(
    key,
    fn(_, _, _, _, _) { <<>> },
    fn(_, _, _, _, _, _) { <<>> },
    fn(_, _, _, _, _, _, _, _, _, _, _, _) { <<>> },
    fn(_, digest_type, secret) { do_sign_hmac(message, digest_type, secret) },
  )
}

@external(erlang, "vestibule_apple_jwt_ffi", "sign_hmac")
fn do_sign_hmac(
  message: BitArray,
  digest_type: core.DigestType,
  secret: BitArray,
) -> BitArray
