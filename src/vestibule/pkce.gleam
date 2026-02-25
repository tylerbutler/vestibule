/// PKCE (Proof Key for Code Exchange) utilities for OAuth2.
///
/// Implements RFC 7636 with S256 challenge method.
/// PKCE prevents authorization code interception attacks.
import gleam/bit_array
import gleam/crypto

/// Generate a cryptographically random code verifier.
///
/// Produces 32 bytes of random data, base64url-encoded without padding,
/// resulting in a 43-character string conforming to RFC 7636.
pub fn generate_verifier() -> String {
  crypto.strong_random_bytes(32)
  |> bit_array.base64_url_encode(False)
}

/// Compute the S256 code challenge from a code verifier.
///
/// Returns the SHA-256 hash of the verifier, base64url-encoded without padding,
/// as specified by RFC 7636 Section 4.2.
pub fn compute_challenge(verifier: String) -> String {
  <<verifier:utf8>>
  |> crypto.hash(crypto.Sha256, _)
  |> bit_array.base64_url_encode(False)
}
