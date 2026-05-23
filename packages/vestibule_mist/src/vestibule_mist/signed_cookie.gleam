//// HMAC-SHA256 signed cookie payload helpers.
////
//// Thin wrapper over `gleam_crypto`'s `sign_message`/`verify_signed_message`
//// to standardize the signing algorithm and produce a String token suitable
//// for use as a cookie value.

import gleam/bit_array
import gleam/crypto

/// Sign `payload` with `secret_key_base` using HMAC-SHA256 and return a
/// URL-safe token (`protected.payload.signature`) suitable for use as a
/// cookie value.
pub fn sign(payload: String, secret_key_base: BitArray) -> String {
  crypto.sign_message(
    bit_array.from_string(payload),
    secret_key_base,
    crypto.Sha256,
  )
}

/// Verify a token previously produced by `sign/2`. Returns the original
/// payload string, or `Error(Nil)` if the token is malformed, the
/// signature does not match, or the payload is not valid UTF-8.
pub fn verify(token: String, secret_key_base: BitArray) -> Result(String, Nil) {
  case crypto.verify_signed_message(token, secret_key_base) {
    Ok(payload_bits) -> bit_array.to_string(payload_bits)
    Error(Nil) -> Error(Nil)
  }
}
