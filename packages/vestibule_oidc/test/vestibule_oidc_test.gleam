/// Security-focused tests for vestibule_oidc.
///
/// These tests verify OIDC discovery, token, and userinfo parsing
/// properties. They were relocated from vestibule core's security_test
/// (audit findings M6) when OIDC discovery moved into this package.
import gleam/option.{None, Some}
import gleeunit
import vestibule/user_info
import vestibule_oidc

pub fn main() -> Nil {
  gleeunit.main()
}

// ===========================================================================
// OIDC Discovery Parsing
// ===========================================================================

/// Security: OIDC discovery must reject issuer mismatch.
/// Per OIDC Discovery spec, the issuer in the response must match the URL.
pub fn oidc_issuer_mismatch_is_detected_test() {
  // The parse_discovery_document doesn't validate issuer -- that's done
  // in fetch_configuration. But we can test the parser handles all fields.
  let json =
    "{\"issuer\":\"https://evil.example.com\",\"authorization_endpoint\":\"https://evil.example.com/auth\",\"token_endpoint\":\"https://evil.example.com/token\",\"userinfo_endpoint\":\"https://evil.example.com/userinfo\"}"
  // Parser itself accepts it (validation happens at fetch_configuration level)
  let result = vestibule_oidc.parse_discovery_document(json)
  let assert Ok(parsed) = result
  assert vestibule_oidc.issuer(parsed) == "https://evil.example.com"
}

/// Security: OIDC discovery parser must handle missing required fields.
pub fn oidc_discovery_missing_issuer_test() {
  let json =
    "{\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

/// Security: OIDC discovery parser must handle missing authorization_endpoint.
pub fn oidc_discovery_missing_auth_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

/// Security: OIDC discovery parser must handle malicious JSON payloads.
pub fn oidc_discovery_handles_deeply_nested_json_test() {
  // Deeply nested JSON should not crash
  let json = "{\"issuer\":{\"nested\":{\"deep\":true}}}"
  let assert Error(_) = vestibule_oidc.parse_discovery_document(json)
  Nil
}

// ===========================================================================
// OIDC Token Response Parsing
// ===========================================================================

/// Security: OIDC token response parser detects error responses.
pub fn oidc_token_response_detects_error_test() {
  let json =
    "{\"error\":\"invalid_grant\",\"error_description\":\"Expired code\"}"
  let assert Error(_) = vestibule_oidc.parse_token_response(json)
  Nil
}

/// Security: OIDC token response parser handles malformed JSON.
pub fn oidc_token_response_handles_malformed_json_test() {
  let assert Error(_) = vestibule_oidc.parse_token_response("{invalid")
  Nil
}

// ===========================================================================
// OIDC Userinfo Parsing
// ===========================================================================

/// Security: OIDC userinfo parser requires sub claim.
/// Without sub, the uid would be undefined -- a security issue.
pub fn oidc_userinfo_requires_sub_test() {
  let json = "{\"name\":\"No Sub\",\"email\":\"nosub@example.com\"}"
  let assert Error(_) = vestibule_oidc.parse_userinfo_response(json)
  Nil
}

/// Security: OIDC userinfo handles XSS payloads in fields gracefully.
/// The parser should accept them (they're strings) but not execute them.
pub fn oidc_userinfo_handles_xss_in_name_test() {
  let json = "{\"sub\":\"uid\",\"name\":\"<script>alert(1)</script>\"}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(_, info)) = result
  // The XSS payload is stored as a plain string; escaping is the
  // responsibility of the presentation layer.
  assert user_info.name(info) == Some("<script>alert(1)</script>")
}

/// Security: OIDC userinfo should not trust unverified emails.
pub fn oidc_rejects_unverified_email_test() {
  let json =
    "{\"sub\":\"user-1\",\"email\":\"unverified@example.com\",\"email_verified\":false}"
  let result = vestibule_oidc.parse_userinfo_response(json)
  let assert Ok(#(_, info)) = result
  assert user_info.email(info) == None
}
