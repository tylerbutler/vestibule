import gleam/string
import startest/expect
import vestibule/pkce

pub fn generate_verifier_produces_43_char_string_test() {
  let verifier = pkce.generate_verifier()
  // 32 bytes base64url-encoded without padding = 43 chars
  string.length(verifier) |> expect.to_equal(43)
}

pub fn generate_verifier_produces_unique_values_test() {
  let a = pkce.generate_verifier()
  let b = pkce.generate_verifier()
  { a != b } |> expect.to_be_true()
}

pub fn compute_challenge_produces_consistent_output_test() {
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge1 = pkce.compute_challenge(verifier)
  let challenge2 = pkce.compute_challenge(verifier)
  challenge1 |> expect.to_equal(challenge2)
}

pub fn compute_challenge_produces_base64url_string_test() {
  let verifier = pkce.generate_verifier()
  let challenge = pkce.compute_challenge(verifier)
  // SHA-256 hash = 32 bytes, base64url-encoded without padding = 43 chars
  string.length(challenge) |> expect.to_equal(43)
}

pub fn compute_challenge_differs_from_verifier_test() {
  let verifier = pkce.generate_verifier()
  let challenge = pkce.compute_challenge(verifier)
  { verifier != challenge } |> expect.to_be_true()
}

pub fn compute_challenge_matches_rfc7636_example_test() {
  // RFC 7636 Appendix B test vector
  let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let challenge = pkce.compute_challenge(verifier)
  challenge |> expect.to_equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
}
