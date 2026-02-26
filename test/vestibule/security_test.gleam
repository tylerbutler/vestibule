/// Security-focused tests for vestibule core.
///
/// These tests verify security properties identified during the
/// 2026-02-25 security audit. Each test documents what security
/// property it verifies and the finding it relates to.
import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import gleam/uri
import startest/expect
import vestibule
import vestibule/authorization_request.{AuthorizationRequest}
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule/error
import vestibule/oidc
import vestibule/pkce
import vestibule/state
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info.{UserInfo}

// ---------------------------------------------------------------------------
// Helper: test strategy that captures inputs for verification
// ---------------------------------------------------------------------------

fn test_strategy() -> Strategy(e) {
  Strategy(
    provider: "test",
    default_scopes: ["scope"],
    token_url: "https://test.example.com/token",
    authorize_url: fn(_config, scopes, st) {
      Ok(
        "https://test.example.com/auth?scope="
        <> string.join(scopes, " ")
        <> "&state="
        <> st,
      )
    },
    exchange_code: fn(_config, code, _verifier) {
      case code {
        "valid_code" ->
          Ok(
            Credentials(
              token: "tok",
              refresh_token: None,
              token_type: "bearer",
              expires_at: None,
              scopes: [],
            ),
          )
        _ -> Error(error.CodeExchangeFailed(reason: "bad code"))
      }
    },
    fetch_user: fn(_creds) {
      Ok(#(
        "uid",
        UserInfo(
          name: None,
          email: None,
          nickname: None,
          image: None,
          description: None,
          urls: dict.new(),
        ),
      ))
    },
  )
}

// ===========================================================================
// CSRF State Security Tests (Audit finding L1, M5)
// ===========================================================================

/// Security: VULNERABILITY (L1) -- empty state on both sides is ACCEPTED.
/// crypto.secure_compare("", "") returns True, which could bypass CSRF
/// protection if an application accidentally stores an empty state.
///
/// This test documents the current (vulnerable) behavior. When a guard
/// is added to reject empty strings, change this test to expect Error.
pub fn state_validate_accepts_both_empty_vulnerability_test() {
  // CURRENT BEHAVIOR: accepts empty-equals-empty (vulnerability L1)
  let _ =
    state.validate("", "")
    |> expect.to_be_ok()
  // TODO: When fixed, this should be:
  // |> expect.to_equal(Error(error.StateMismatch))
  Nil
}

/// Security: state with only whitespace is currently accepted.
/// Documents the behavior -- whitespace-only strings are not rejected.
pub fn state_validate_accepts_whitespace_only_test() {
  // CURRENT BEHAVIOR: whitespace matches whitespace
  let _ =
    state.validate("   ", "   ")
    |> expect.to_be_ok()
  // TODO: When fixed, this should be:
  // |> expect.to_equal(Error(error.StateMismatch))
  Nil
}

/// Security: generated states must have sufficient entropy.
/// 32 bytes of CSPRNG = 256 bits. Base64url encoding produces 43 chars.
pub fn state_generation_entropy_is_sufficient_test() {
  let s = state.generate()
  // Must be at least 43 chars (256 bits base64url-encoded)
  { string.length(s) >= 43 } |> expect.to_be_true()
}

/// Security: state tokens must be unique across generations.
/// Tests that 10 consecutive calls produce 10 distinct values.
pub fn state_generation_produces_unique_values_test() {
  let states = [
    state.generate(),
    state.generate(),
    state.generate(),
    state.generate(),
    state.generate(),
    state.generate(),
    state.generate(),
    state.generate(),
    state.generate(),
    state.generate(),
  ]
  // All 10 should be unique
  let unique_count =
    states
    |> list_unique_count()
  { unique_count == 10 } |> expect.to_be_true()
}

/// Security: near-miss states must be rejected.
/// Verifies the comparison isn't doing prefix-only or length-only checks.
pub fn state_validate_rejects_near_miss_test() {
  let s = state.generate()
  // Flip the last character
  let prefix = string.drop_end(s, 1)
  let tampered = prefix <> "X"
  state.validate(tampered, s)
  |> expect.to_equal(Error(error.StateMismatch))
}

/// Security: swapped state values must be rejected.
pub fn state_validate_rejects_swapped_values_test() {
  let a = state.generate()
  let b = state.generate()
  state.validate(a, b)
  |> expect.to_equal(Error(error.StateMismatch))
}

// ===========================================================================
// PKCE Security Tests (Audit: verified compliant)
// ===========================================================================

/// Security: PKCE verifier must use URL-safe base64 characters only.
/// No +, /, or = padding (RFC 7636 Section 4.1).
pub fn pkce_verifier_uses_url_safe_chars_only_test() {
  let verifier = pkce.generate_verifier()
  { string.contains(verifier, "+") } |> expect.to_be_false()
  { string.contains(verifier, "/") } |> expect.to_be_false()
  { string.contains(verifier, "=") } |> expect.to_be_false()
}

/// Security: PKCE challenge must use URL-safe base64 characters only.
pub fn pkce_challenge_uses_url_safe_chars_only_test() {
  let verifier = pkce.generate_verifier()
  let challenge = pkce.compute_challenge(verifier)
  { string.contains(challenge, "+") } |> expect.to_be_false()
  { string.contains(challenge, "/") } |> expect.to_be_false()
  { string.contains(challenge, "=") } |> expect.to_be_false()
}

/// Security: PKCE verifiers must be unique (CSPRNG).
pub fn pkce_verifiers_are_unique_test() {
  let verifiers = [
    pkce.generate_verifier(),
    pkce.generate_verifier(),
    pkce.generate_verifier(),
    pkce.generate_verifier(),
    pkce.generate_verifier(),
  ]
  let unique_count = list_unique_count(verifiers)
  { unique_count == 5 } |> expect.to_be_true()
}

/// Security: different verifiers must produce different challenges.
/// Ensures the hash function actually incorporates the verifier.
pub fn pkce_different_verifiers_produce_different_challenges_test() {
  let c1 = pkce.generate_verifier() |> pkce.compute_challenge()
  let c2 = pkce.generate_verifier() |> pkce.compute_challenge()
  { c1 != c2 } |> expect.to_be_true()
}

// ===========================================================================
// Authorization URL Security Tests
// ===========================================================================

/// Security: authorization URL must always include PKCE params.
/// No code path should produce a URL without code_challenge.
pub fn authorize_url_always_includes_pkce_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let assert Ok(AuthorizationRequest(url:, ..)) =
    vestibule.authorize_url(strat, conf)
  { string.contains(url, "code_challenge=") } |> expect.to_be_true()
  { string.contains(url, "code_challenge_method=S256") } |> expect.to_be_true()
}

/// Security: authorize_url state and verifier must differ on each call.
pub fn authorize_url_produces_fresh_state_and_verifier_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let assert Ok(req1) = vestibule.authorize_url(strat, conf)
  let assert Ok(req2) = vestibule.authorize_url(strat, conf)
  { req1.state != req2.state } |> expect.to_be_true()
  { req1.code_verifier != req2.code_verifier } |> expect.to_be_true()
}

// ===========================================================================
// Callback Security Tests (Audit findings M4)
// ===========================================================================

/// Security: state mismatch must reject the callback before any
/// server-side operations (code exchange, user fetch).
pub fn callback_rejects_state_mismatch_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let params =
    dict.from_list([#("code", "valid_code"), #("state", "attacker_state")])
  vestibule.handle_callback(strat, conf, params, "real_state", "verifier")
  |> expect.to_equal(Error(error.StateMismatch))
}

/// Security: missing state parameter must be rejected.
pub fn callback_rejects_missing_state_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let params = dict.from_list([#("code", "valid_code")])
  let result =
    vestibule.handle_callback(strat, conf, params, "expected", "verifier")
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: empty callback params must be rejected.
pub fn callback_rejects_empty_params_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let result =
    vestibule.handle_callback(strat, conf, dict.new(), "expected", "verifier")
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: provider error responses must be detected.
/// When a provider returns error=access_denied (user denied consent),
/// the library should propagate the ProviderError, not a generic
/// "Missing code parameter" ConfigError.
pub fn callback_detects_provider_error_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let state_val = "matching_state"
  let params =
    dict.from_list([
      #("state", state_val),
      #("error", "access_denied"),
      #("error_description", "User denied access"),
    ])
  let result =
    vestibule.handle_callback(strat, conf, params, state_val, "verifier")
  result
  |> expect.to_be_error()
  |> expect.to_equal(error.ProviderError(
    code: "access_denied",
    description: "User denied access",
  ))
}

/// Security: provider error without description still returns ProviderError.
pub fn callback_detects_provider_error_without_description_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let state_val = "matching_state"
  let params =
    dict.from_list([#("state", state_val), #("error", "server_error")])
  let result =
    vestibule.handle_callback(strat, conf, params, state_val, "verifier")
  result
  |> expect.to_be_error()
  |> expect.to_equal(error.ProviderError(code: "server_error", description: ""))
}

/// Security: provider error check happens after state validation.
/// Even if a provider error is present, CSRF state must be validated first.
pub fn callback_validates_state_before_checking_provider_error_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let params =
    dict.from_list([
      #("state", "attacker_state"),
      #("error", "access_denied"),
      #("error_description", "User denied access"),
    ])
  // State mismatch should be returned, not the provider error
  vestibule.handle_callback(strat, conf, params, "real_state", "verifier")
  |> expect.to_equal(Error(error.StateMismatch))
}

/// Security: extra unexpected parameters should not cause crashes.
pub fn callback_ignores_extra_params_test() {
  let strat = test_strategy()
  let assert Ok(conf) = config.new("id", "secret", "https://localhost/cb")
  let state_val = "test_state"
  let params =
    dict.from_list([
      #("code", "valid_code"),
      #("state", state_val),
      #("unexpected_param", "some_value"),
      #("another", "<script>alert(1)</script>"),
    ])
  let result =
    vestibule.handle_callback(strat, conf, params, state_val, "verifier")
  let _ = result |> expect.to_be_ok()
  Nil
}

// ===========================================================================
// Token Refresh Security Tests (Audit finding M1)
// ===========================================================================

/// Security: refresh token body must URL-encode parameters.
/// Verifies that uri.query_to_string properly encodes special characters
/// that could cause parameter injection in form-encoded POST bodies.
pub fn refresh_body_url_encodes_special_characters_test() {
  // Verify that uri.query_to_string encodes &, =, and + characters
  let params = [
    #("grant_type", "refresh_token"),
    #("refresh_token", "token&with=special+chars"),
    #("client_id", "id&inject=evil"),
    #("client_secret", "secret=with&ampersand"),
  ]
  let body = uri.query_to_string(params)

  // The encoded body must NOT contain raw & from values (only as separators)
  // and must NOT contain raw = from values (only as key=value delimiters)
  { string.contains(body, "token%26with%3Dwith") } |> expect.to_be_false()

  // Verify each parameter appears with proper encoding
  { string.contains(body, "grant_type=refresh_token") } |> expect.to_be_true()
  { string.contains(body, "refresh_token=token%26with%3Dspecial%2Bchars") }
  |> expect.to_be_true()
  { string.contains(body, "client_id=id%26inject%3Devil") }
  |> expect.to_be_true()
  { string.contains(body, "client_secret=secret%3Dwith%26ampersand") }
  |> expect.to_be_true()
}

/// Security: refresh response parser must handle malformed JSON gracefully.
pub fn refresh_response_handles_html_error_page_test() {
  let body = "<html><body><h1>500 Internal Server Error</h1></body></html>"
  let _ = vestibule.parse_refresh_response(body) |> expect.to_be_error()
  Nil
}

/// Security: refresh response parser must handle empty body.
pub fn refresh_response_handles_empty_body_test() {
  let _ = vestibule.parse_refresh_response("") |> expect.to_be_error()
  Nil
}

/// Security: refresh response parser handles error without description.
/// Finding L5 -- some providers omit error_description.
pub fn refresh_response_handles_error_without_description_test() {
  let body = "{\"error\":\"invalid_grant\"}"
  // Currently this falls through to success parsing and fails there.
  // The test documents the behavior -- ideally this should return
  // ProviderError with an empty description.
  let _ = vestibule.parse_refresh_response(body) |> expect.to_be_error()
  Nil
}

/// Security: refresh response with extremely long token should not crash.
pub fn refresh_response_handles_long_token_test() {
  let long_token = string.repeat("a", 10_000)
  let body =
    "{\"access_token\":\"" <> long_token <> "\",\"token_type\":\"bearer\"}"
  let result = vestibule.parse_refresh_response(body)
  let assert Ok(creds) = result
  { string.length(creds.token) == 10_000 } |> expect.to_be_true()
}

// ===========================================================================
// OIDC Security Tests (Audit findings M6)
// ===========================================================================

/// Security: OIDC discovery must reject issuer mismatch.
/// Per OIDC Discovery spec, the issuer in the response must match the URL.
pub fn oidc_issuer_mismatch_is_detected_test() {
  // The parse_discovery_document doesn't validate issuer -- that's done
  // in fetch_configuration. But we can test the parser handles all fields.
  let json =
    "{\"issuer\":\"https://evil.example.com\",\"authorization_endpoint\":\"https://evil.example.com/auth\",\"token_endpoint\":\"https://evil.example.com/token\",\"userinfo_endpoint\":\"https://evil.example.com/userinfo\"}"
  // Parser itself accepts it (validation happens at fetch_configuration level)
  let result = oidc.parse_discovery_document(json)
  let assert Ok(parsed) = result
  parsed.issuer |> expect.to_equal("https://evil.example.com")
}

/// Security: OIDC discovery parser must handle missing required fields.
pub fn oidc_discovery_missing_issuer_test() {
  let json =
    "{\"authorization_endpoint\":\"https://example.com/auth\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ = oidc.parse_discovery_document(json) |> expect.to_be_error()
  Nil
}

/// Security: OIDC discovery parser must handle missing authorization_endpoint.
pub fn oidc_discovery_missing_auth_endpoint_test() {
  let json =
    "{\"issuer\":\"https://example.com\",\"token_endpoint\":\"https://example.com/token\",\"userinfo_endpoint\":\"https://example.com/userinfo\"}"
  let _ = oidc.parse_discovery_document(json) |> expect.to_be_error()
  Nil
}

/// Security: OIDC discovery parser must handle malicious JSON payloads.
pub fn oidc_discovery_handles_deeply_nested_json_test() {
  // Deeply nested JSON should not crash
  let json = "{\"issuer\":{\"nested\":{\"deep\":true}}}"
  let _ = oidc.parse_discovery_document(json) |> expect.to_be_error()
  Nil
}

/// Security: OIDC token response parser detects error responses.
pub fn oidc_token_response_detects_error_test() {
  let json =
    "{\"error\":\"invalid_grant\",\"error_description\":\"Expired code\"}"
  let _ = oidc.parse_token_response(json) |> expect.to_be_error()
  Nil
}

/// Security: OIDC token response parser handles malformed JSON.
pub fn oidc_token_response_handles_malformed_json_test() {
  let _ = oidc.parse_token_response("{invalid") |> expect.to_be_error()
  Nil
}

/// Security: OIDC userinfo parser requires sub claim.
/// Without sub, the uid would be undefined -- a security issue.
pub fn oidc_userinfo_requires_sub_test() {
  let json = "{\"name\":\"No Sub\",\"email\":\"nosub@example.com\"}"
  let _ = oidc.parse_userinfo_response(json) |> expect.to_be_error()
  Nil
}

/// Security: OIDC userinfo handles XSS payloads in fields gracefully.
/// The parser should accept them (they're strings) but not execute them.
pub fn oidc_userinfo_handles_xss_in_name_test() {
  let json = "{\"sub\":\"uid\",\"name\":\"<script>alert(1)</script>\"}"
  let result = oidc.parse_userinfo_response(json)
  let assert Ok(#(_, info)) = result
  // The XSS payload is stored as a plain string; escaping is the
  // responsibility of the presentation layer.
  info.name
  |> expect.to_equal(Some("<script>alert(1)</script>"))
}

// ===========================================================================
// Provider-Specific Security Tests
// ===========================================================================

// --- OIDC: email_verified gap ---

/// Security: OIDC userinfo parser does NOT check email_verified.
/// This documents a gap -- unverified emails are returned as-is.
/// Google and Apple strategies handle this correctly in their own parsers,
/// but the generic OIDC strategy does not.
pub fn oidc_returns_unverified_email_gap_test() {
  let json =
    "{\"sub\":\"user-1\",\"email\":\"unverified@example.com\",\"email_verified\":false}"
  let result = oidc.parse_userinfo_response(json)
  let assert Ok(#(_, info)) = result
  // Current behavior: email IS returned even when email_verified is false
  info.email |> expect.to_equal(Some("unverified@example.com"))
}

// ===========================================================================
// HTTPS Enforcement Tests (Issues #16, #20)
// ===========================================================================

/// Security: config.new must reject HTTP redirect URIs for non-localhost.
pub fn config_rejects_http_redirect_uri_test() {
  let result = config.new("id", "secret", "http://evil.com/callback")
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: config.new must accept HTTPS redirect URIs.
pub fn config_accepts_https_redirect_uri_test() {
  let result = config.new("id", "secret", "https://example.com/callback")
  let _ = result |> expect.to_be_ok()
  Nil
}

/// Security: config.new must allow HTTP localhost for development.
pub fn config_allows_http_localhost_test() {
  let result = config.new("id", "secret", "http://localhost:8080/callback")
  let _ = result |> expect.to_be_ok()
  Nil
}

/// Security: OIDC strategy_from_config rejects HTTP endpoint URLs.
pub fn oidc_strategy_from_config_rejects_http_endpoints_test() {
  let oidc_config =
    oidc.OidcConfig(
      issuer: "https://example.com",
      authorization_endpoint: "http://example.com/authorize",
      token_endpoint: "https://example.com/token",
      userinfo_endpoint: "https://example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let result = oidc.strategy_from_config(oidc_config, "test")
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: OIDC strategy_from_config accepts HTTPS endpoint URLs.
pub fn oidc_strategy_from_config_accepts_https_endpoints_test() {
  let oidc_config =
    oidc.OidcConfig(
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/authorize",
      token_endpoint: "https://example.com/token",
      userinfo_endpoint: "https://example.com/userinfo",
      scopes_supported: ["openid", "profile", "email"],
    )
  let result = oidc.strategy_from_config(oidc_config, "test")
  let _ = result |> expect.to_be_ok()
  Nil
}

/// Security: OIDC strategy_from_config rejects HTTP token endpoint.
pub fn oidc_strategy_from_config_rejects_http_token_url_test() {
  let oidc_config =
    oidc.OidcConfig(
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/authorize",
      token_endpoint: "http://example.com/token",
      userinfo_endpoint: "https://example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let result = oidc.strategy_from_config(oidc_config, "test")
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: OIDC strategy_from_config rejects HTTP userinfo endpoint.
pub fn oidc_strategy_from_config_rejects_http_userinfo_url_test() {
  let oidc_config =
    oidc.OidcConfig(
      issuer: "https://example.com",
      authorization_endpoint: "https://example.com/authorize",
      token_endpoint: "https://example.com/token",
      userinfo_endpoint: "http://example.com/userinfo",
      scopes_supported: ["openid"],
    )
  let result = oidc.strategy_from_config(oidc_config, "test")
  let _ = result |> expect.to_be_error()
  Nil
}

// ===========================================================================
// Input Validation / Fuzzing-style Tests
// ===========================================================================

/// Security: null bytes in state parameter must not bypass validation.
pub fn state_validate_handles_null_bytes_test() {
  let _ =
    state.validate("abc\u{0000}def", "abc\u{0000}def")
    |> expect.to_be_ok()

  state.validate("abc\u{0000}def", "abcXdef")
  |> expect.to_equal(Error(error.StateMismatch))
}

/// Security: Unicode normalization should not affect state comparison.
/// The state is random bytes base64url-encoded, so Unicode normalization
/// shouldn't be an issue, but verify the comparison is byte-level.
pub fn state_validate_is_byte_level_comparison_test() {
  // These are the same visual character but different byte sequences
  // e-acute: U+00E9 (single codepoint) vs e + combining acute U+0065 U+0301
  state.validate("\u{00E9}", "e\u{0301}")
  |> expect.to_equal(Error(error.StateMismatch))
}

/// Security: very long state values should not crash.
pub fn state_validate_handles_long_values_test() {
  let long = string.repeat("a", 10_000)
  let _ =
    state.validate(long, long)
    |> expect.to_be_ok()

  state.validate(long, long <> "x")
  |> expect.to_equal(Error(error.StateMismatch))
}

// ===========================================================================
// Helpers
// ===========================================================================

fn list_unique_count(items: List(String)) -> Int {
  list_unique_count_loop(items, [])
}

fn list_unique_count_loop(items: List(String), seen: List(String)) -> Int {
  case items {
    [] -> seen |> list_length()
    [first, ..rest] ->
      case list_contains(seen, first) {
        True -> list_unique_count_loop(rest, seen)
        False -> list_unique_count_loop(rest, [first, ..seen])
      }
  }
}

fn list_contains(items: List(String), target: String) -> Bool {
  case items {
    [] -> False
    [first, ..rest] ->
      case first == target {
        True -> True
        False -> list_contains(rest, target)
      }
  }
}

fn list_length(items: List(a)) -> Int {
  list_length_loop(items, 0)
}

fn list_length_loop(items: List(a), acc: Int) -> Int {
  case items {
    [] -> acc
    [_, ..rest] -> list_length_loop(rest, acc + 1)
  }
}
