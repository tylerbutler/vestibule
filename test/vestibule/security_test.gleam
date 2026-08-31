//// Security-focused tests for vestibule core.
////
//// These tests verify security properties identified during the
//// 2026-02-25 security audit. Each test documents what security
//// property it verifies and the finding it relates to.

import gleam/dict
import gleam/option.{None, Some}
import gleam/set
import gleam/string
import vestibule
import vestibule/authorization_request
import vestibule/config
import vestibule/credential
import vestibule/error
import vestibule/pkce
import vestibule/provider_support
import vestibule/state
import vestibule/strategy.{type Strategy}
import vestibule/user_info

// ---------------------------------------------------------------------------
// Helper: test strategy that captures inputs for verification
// ---------------------------------------------------------------------------

fn test_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: ["scope"],
    authorize_url: fn(_config, _options, scopes, state) {
      Ok(
        "https://test.example.com/auth?scope="
        <> string.join(scopes, " ")
        <> "&state="
        <> state,
      )
    },
    exchange_code: fn(_config, code, _verifier) {
      case code {
        "valid_code" ->
          Ok(
            strategy.exchange_result(
              credential.new(
                token: "tok",
                refresh_token: None,
                token_type: "bearer",
                expires_in: None,
                scopes: [],
              ),
            ),
          )
        _ -> Error(error.code_exchange(reason: "bad code"))
      }
    },
    fetch_user: fn(_config, _exchange) {
      Ok(strategy.user_result(
        uid: "uid",
        info: user_info.new(),
        extra: dict.new(),
      ))
    },
  )
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.config(reason: "refresh not implemented"))
  })
}

// ===========================================================================
// CSRF State Security Tests (Audit finding L1, M5)
// ===========================================================================

/// Security: empty state values must always be rejected.
pub fn state_validate_rejects_both_empty_test() -> Nil {
  assert state.validate(received: "", expected: "")
    == Error(error.state_mismatch())
}

/// Security: whitespace-only state values must be rejected.
pub fn state_validate_rejects_whitespace_only_test() -> Nil {
  assert state.validate(received: "   ", expected: "   ")
    == Error(error.state_mismatch())
}

/// Security: generated states must have sufficient entropy.
/// 32 bytes of CSPRNG = 256 bits. Base64url encoding produces 43 chars.
pub fn state_generation_entropy_is_sufficient_test() -> Nil {
  let state_value = state.generate()
  // Must be at least 43 chars (256 bits base64url-encoded)
  assert string.length(state_value) >= 43
}

/// Security: state tokens must be unique across generations.
/// Tests that 10 consecutive calls produce 10 distinct values.
pub fn state_generation_produces_unique_values_test() -> Nil {
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
  assert unique_count(states) == 10
}

/// Security: near-miss states must be rejected.
/// Verifies the comparison isn't doing prefix-only or length-only checks.
pub fn state_validate_rejects_near_miss_test() -> Nil {
  let state_value = state.generate()
  // Flip the last character
  let prefix = string.drop_end(state_value, 1)
  let tampered = prefix <> "X"
  assert state.validate(received: tampered, expected: state_value)
    == Error(error.state_mismatch())
}

/// Security: swapped state values must be rejected.
pub fn state_validate_rejects_swapped_values_test() -> Nil {
  let first_state = state.generate()
  let second_state = state.generate()
  assert state.validate(received: first_state, expected: second_state)
    == Error(error.state_mismatch())
}

// ===========================================================================
// PKCE Security Tests (Audit: verified compliant)
// ===========================================================================

/// Security: PKCE verifier must use URL-safe base64 characters only.
/// No +, /, or = padding (RFC 7636 Section 4.1).
pub fn pkce_verifier_uses_url_safe_chars_only_test() -> Nil {
  let verifier = pkce.generate_verifier()
  assert !string.contains(verifier, "+")
  assert !string.contains(verifier, "/")
  assert !string.contains(verifier, "=")
}

/// Security: PKCE challenge must use URL-safe base64 characters only.
pub fn pkce_challenge_uses_url_safe_chars_only_test() -> Nil {
  let verifier = pkce.generate_verifier()
  let challenge = pkce.compute_challenge(verifier)
  assert !string.contains(challenge, "+")
  assert !string.contains(challenge, "/")
  assert !string.contains(challenge, "=")
}

/// Security: PKCE verifiers must be unique (CSPRNG).
pub fn pkce_verifiers_are_unique_test() -> Nil {
  let verifiers = [
    pkce.generate_verifier(),
    pkce.generate_verifier(),
    pkce.generate_verifier(),
    pkce.generate_verifier(),
    pkce.generate_verifier(),
  ]
  assert unique_count(verifiers) == 5
}

/// Security: different verifiers must produce different challenges.
/// Ensures the hash function actually incorporates the verifier.
pub fn pkce_different_verifiers_produce_different_challenges_test() -> Nil {
  let c1 = pkce.generate_verifier() |> pkce.compute_challenge()
  let c2 = pkce.generate_verifier() |> pkce.compute_challenge()
  assert c1 != c2
}

// ===========================================================================
// Authorization URL Security Tests
// ===========================================================================

/// Security: authorization URL must always include PKCE parameters.
/// No code path should produce first_state URL without code_challenge.
pub fn create_authorization_request_always_includes_pkce_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let assert Ok(authorization_request_value) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(authorization_request_value)
  assert string.contains(url, "code_challenge=")
  assert string.contains(url, "code_challenge_method=S256")
}

/// Security: create_authorization_request state and verifier must differ on each call.
pub fn create_authorization_request_produces_fresh_state_and_verifier_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let assert Ok(req1) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let assert Ok(req2) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  assert authorization_request.state(req1) != authorization_request.state(req2)
  assert authorization_request.code_verifier(req1)
    != authorization_request.code_verifier(req2)
}

// ===========================================================================
// Callback Security Tests (Audit findings M4)
// ===========================================================================

/// Security: state mismatch must reject the callback before any
/// server-side operations (code exchange, user fetch).
pub fn callback_rejects_state_mismatch_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let parameters =
    dict.from_list([#("code", "valid_code"), #("state", "attacker_state")])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: "real_state",
      code_verifier: "verifier",
      expected_nonce: None,
    )
  assert result == Error(error.state_mismatch())
}

/// Security: missing state parameter must be rejected.
pub fn callback_rejects_missing_state_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let parameters = dict.from_list([#("code", "valid_code")])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: None,
    )
  assert result == Error(error.missing_callback_param("state"))
}

/// Security: empty callback parameters must be rejected.
pub fn callback_rejects_empty_parameters_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: dict.new(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: None,
    )
  assert result == Error(error.missing_callback_param("state"))
}

/// Security: provider error responses must be detected.
/// When first_state provider returns error=access_denied (user denied consent),
/// the library should propagate the ProviderError, not first_state generic message.
pub fn callback_detects_provider_error_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let state_value = "matching_state"
  let parameters =
    dict.from_list([
      #("state", state_value),
      #("error", "access_denied"),
      #("error_description", "User denied access"),
    ])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: state_value,
      code_verifier: "verifier",
      expected_nonce: None,
    )
  assert result
    == Error(error.provider(
      code: "access_denied",
      description: "User denied access",
      uri: None,
    ))
}

pub fn callback_preserves_provider_error_uri_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let state_value = "matching_state"
  let parameters =
    dict.from_list([
      #("state", state_value),
      #("error", "access_denied"),
      #("error_description", "User denied access"),
      #("error_uri", "https://example.com/access-denied"),
    ])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: state_value,
      code_verifier: "verifier",
      expected_nonce: None,
    )
  assert result
    == Error(error.provider(
      code: "access_denied",
      description: "User denied access",
      uri: Some("https://example.com/access-denied"),
    ))
}

/// Security: state validation must happen before provider errors are surfaced.
pub fn callback_rejects_provider_error_when_state_mismatch_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let parameters =
    dict.from_list([
      #("state", "attacker_state"),
      #("error", "access_denied"),
      #("error_description", "User denied access"),
    ])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: "expected_state",
      code_verifier: "verifier",
      expected_nonce: None,
    )
  assert result == Error(error.state_mismatch())
}

/// Security: extra unexpected parameters should not cause crashes.
pub fn callback_ignores_extra_parameters_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "https://localhost/cb",
    )
  let state_value = "test_state"
  let parameters =
    dict.from_list([
      #("code", "valid_code"),
      #("state", state_value),
      #("unexpected_param", "some_value"),
      #("another", "<script>alert(1)</script>"),
    ])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: state_value,
      code_verifier: "verifier",
      expected_nonce: None,
    )
  let assert Ok(_) = result
  Nil
}

// ===========================================================================
// Token Refresh Security Tests (Audit finding M1)
// ===========================================================================

/// Security: refresh response parser must handle malformed JSON gracefully.
pub fn refresh_response_handles_html_error_page_test() -> Nil {
  let body = "<html><body><h1>500 Internal Server Error</h1></body></html>"
  let assert Error(_) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  Nil
}

/// Security: refresh response parser must handle empty body.
pub fn refresh_response_handles_empty_body_test() -> Nil {
  let assert Error(_) =
    provider_support.parse_oauth_token_response(
      "",
      provider_support.OptionalScope(" "),
    )
  Nil
}

/// Security: refresh response parser handles error without description.
/// Finding L5 -- some providers omit error_description.
pub fn refresh_response_handles_error_without_description_test() -> Nil {
  let body = "{\"error\":\"invalid_grant\"}"
  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
    == Error(error.provider(code: "invalid_grant", description: "", uri: None))
}

/// Security: refresh response with extremely long token should not crash.
pub fn refresh_response_handles_long_token_test() -> Nil {
  let long_token = string.repeat("a", 10_000)
  let body =
    "{\"access_token\":\"" <> long_token <> "\",\"token_type\":\"bearer\"}"
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  let assert Ok(oauth_credentials) = result
  assert string.length(credential.token(oauth_credentials)) == 10_000
}

// ===========================================================================
// Input Validation / Fuzzing-style Tests
// ===========================================================================

/// Security: null bytes in state parameter must not bypass validation.
pub fn state_validate_handles_null_bytes_test() -> Nil {
  let assert Ok(_) =
    state.validate(received: "abc\u{0000}def", expected: "abc\u{0000}def")

  assert state.validate(received: "abc\u{0000}def", expected: "abcXdef")
    == Error(error.state_mismatch())
}

/// Security: Unicode normalization should not affect state comparison.
/// The state is random bytes base64url-encoded, so Unicode normalization
/// shouldn't be an issue, but verify the comparison is byte-level.
pub fn state_validate_is_byte_level_comparison_test() -> Nil {
  // These are the same visual character but different byte sequences
  // e-acute: U+00E9 (single codepoint) vs e + combining acute U+0065 U+0301
  assert state.validate(received: "\u{00E9}", expected: "e\u{0301}")
    == Error(error.state_mismatch())
}

/// Security: very long state values should not crash.
pub fn state_validate_handles_long_values_test() -> Nil {
  let long = string.repeat("a", 10_000)
  let assert Ok(_) = state.validate(received: long, expected: long)

  assert state.validate(received: long, expected: long <> "x")
    == Error(error.state_mismatch())
}

// ===========================================================================
// Helpers
// ===========================================================================

fn unique_count(items: List(String)) -> Int {
  items
  |> set.from_list()
  |> set.size()
}
