/// Security-focused tests for the Apple Sign In strategy.
///
/// These tests verify security properties identified during the
/// 2026-02-25 security audit. The Apple strategy uses ywt_core for
/// JWT parsing/claims with a custom FFI backend for crypto verification.
import gleam/json as gleam_json
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import startest
import startest/expect
import vestibule_apple
import vestibule_apple/id_token_cache
import vestibule_apple/jwks
import vestibule_apple/jwt
import ywt/claim
import ywt/verify_key

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// ===========================================================================
// JWT Signature Verification Tests (Audit finding C1 -- FIXED)
// ===========================================================================

/// Security: verify_id_token rejects a JWT signed with the wrong key.
/// This is the core fix for finding C1.
pub fn verify_id_token_rejects_wrong_key_test() {
  let attacker_key = jwt.generate_test_key()
  let legit_key = jwt.generate_test_key()

  let token =
    jwt.encode(
      [
        #("sub", gleam_json.string("attacker-uid")),
        #("email", gleam_json.string("victim@example.com")),
        #("email_verified", gleam_json.string("true")),
      ],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      attacker_key,
    )

  let result =
    vestibule_apple.verify_id_token(
      token,
      [verify_key.derived(legit_key)],
      "com.example.app",
    )
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: verify_id_token accepts a JWT signed with the correct key.
pub fn verify_id_token_accepts_correct_key_test() {
  let key = jwt.generate_test_key()

  let token =
    jwt.encode(
      [
        #("sub", gleam_json.string("user-123")),
        #("email", gleam_json.string("user@example.com")),
        #("email_verified", gleam_json.string("true")),
      ],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      key,
    )

  let result =
    vestibule_apple.verify_id_token(
      token,
      [verify_key.derived(key)],
      "com.example.app",
    )
  let assert Ok(#(uid, info)) = result
  uid |> expect.to_equal("user-123")
  info.email |> expect.to_equal(Some("user@example.com"))
}

/// Security: verify_id_token rejects JWT with wrong issuer.
pub fn verify_id_token_rejects_wrong_issuer_test() {
  let key = jwt.generate_test_key()

  let token =
    jwt.encode(
      [#("sub", gleam_json.string("uid"))],
      [
        claim.issuer("https://evil.example.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      key,
    )

  let result =
    vestibule_apple.verify_id_token(
      token,
      [verify_key.derived(key)],
      "com.example.app",
    )
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: verify_id_token rejects JWT with wrong audience.
pub fn verify_id_token_rejects_wrong_audience_test() {
  let key = jwt.generate_test_key()

  let token =
    jwt.encode(
      [#("sub", gleam_json.string("uid"))],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.wrong.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      key,
    )

  let result =
    vestibule_apple.verify_id_token(
      token,
      [verify_key.derived(key)],
      "com.example.app",
    )
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: verify_id_token rejects a completely forged JWT.
pub fn verify_id_token_rejects_forged_jwt_test() {
  let key = jwt.generate_test_key()

  let forged_payload =
    "eyJzdWIiOiJhdHRhY2tlci11aWQiLCJlbWFpbCI6InZpY3RpbUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSJ9"
  let forged_jwt = "eyJhbGciOiJIUzI1NiJ9." <> forged_payload <> ".AAAA"

  let result =
    vestibule_apple.verify_id_token(
      forged_jwt,
      [verify_key.derived(key)],
      "com.example.app",
    )
  let _ = result |> expect.to_be_error()
  Nil
}

/// Security: verify_id_token handles email_verified correctly.
pub fn verify_id_token_unverified_email_not_returned_test() {
  let key = jwt.generate_test_key()

  let token =
    jwt.encode(
      [
        #("sub", gleam_json.string("uid")),
        #("email", gleam_json.string("user@example.com")),
        #("email_verified", gleam_json.string("false")),
      ],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      key,
    )

  let assert Ok(#(_, info)) =
    vestibule_apple.verify_id_token(
      token,
      [verify_key.derived(key)],
      "com.example.app",
    )
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(Some("user@example.com"))
}

// ===========================================================================
// JWKS Parsing Tests
// ===========================================================================

/// Security: JWKS parser handles valid Apple-format JWKS.
pub fn parse_jwks_valid_test() {
  let jwks_json =
    "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"test-key\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]}"
  let _ = jwks.parse_jwks(jwks_json) |> expect.to_be_ok()
  Nil
}

/// Security: JWKS parser rejects invalid JSON.
pub fn parse_jwks_rejects_invalid_json_test() {
  let _ = jwks.parse_jwks("not json") |> expect.to_be_error()
  Nil
}

/// Security: JWKS parser accepts empty key set.
pub fn parse_jwks_accepts_empty_keys_test() {
  let result = jwks.parse_jwks("{\"keys\":[]}")
  let assert Ok(keys) = result
  keys |> expect.to_equal([])
}

// ===========================================================================
// Token Response Security Tests
// ===========================================================================

/// Security: error response without error_description should still be detected.
pub fn apple_token_error_without_description_test() {
  let _ =
    vestibule_apple.parse_token_response("{\"error\":\"invalid_client\"}")
    |> expect.to_be_error()
  Nil
}

/// Security: HTML error response from misconfigured proxy should not crash.
pub fn apple_token_response_handles_html_test() {
  let _ =
    vestibule_apple.parse_token_response(
      "<html><body>502 Bad Gateway</body></html>",
    )
    |> expect.to_be_error()
  Nil
}

/// Security: empty response should not crash.
pub fn apple_token_response_handles_empty_test() {
  let _ =
    vestibule_apple.parse_token_response("")
    |> expect.to_be_error()
  Nil
}

// ===========================================================================
// Cache Key Security Tests (Issue #23 -- random cache key)
// ===========================================================================

/// Security: access token cannot be used to retrieve cached ID token.
/// The cache stores under a random key, not the access token.
pub fn cache_access_token_cannot_retrieve_id_token_test() {
  let cache = id_token_cache.init_named("sec_cache_access_token")
  let access_token = "apple_access_token_abc123"
  let random_cache_key = "random_key_xyz789"
  let id_token_data = "header.payload.signature\ncom.example.app"

  // Store under random cache key (as the fixed code does)
  id_token_cache.store(cache, random_cache_key, id_token_data)

  // Attempting to retrieve with the access token should fail
  id_token_cache.retrieve(cache, access_token)
  |> expect.to_be_error()
}

/// Security: random cache key successfully retrieves cached ID token.
pub fn cache_random_key_retrieves_id_token_test() {
  let cache = id_token_cache.init_named("sec_cache_random_key")
  let random_cache_key = "random_key_abc456"
  let id_token_data = "header.payload.signature\ncom.example.app"

  id_token_cache.store(cache, random_cache_key, id_token_data)

  let assert Ok(cached) = id_token_cache.retrieve(cache, random_cache_key)
  cached |> expect.to_equal(id_token_data)
}

/// Security: cached ID token can only be retrieved once (one-time use).
pub fn cache_id_token_consumed_after_retrieval_test() {
  let cache = id_token_cache.init_named("sec_cache_one_time")
  let cache_key = "one_time_key_123"
  let id_token_data = "header.payload.signature\ncom.example.app"

  id_token_cache.store(cache, cache_key, id_token_data)

  // First retrieval succeeds
  let _ = id_token_cache.retrieve(cache, cache_key) |> expect.to_be_ok()

  // Second retrieval fails (consumed)
  id_token_cache.retrieve(cache, cache_key)
  |> expect.to_be_error()
}

/// Security: parse_token_response preserves the original access token,
/// which is different from the random cache key used internally.
pub fn parse_token_response_returns_original_access_token_test() {
  let body =
    "{\"access_token\":\"original_apple_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"h.p.s\"}"
  let assert Ok(#(creds, _id_token)) =
    vestibule_apple.parse_token_response(body)

  // parse_token_response returns the original access token
  // (the random cache key substitution happens in exchange_code, not here)
  creds.token |> expect.to_equal("original_apple_token")
}

/// Security: different cache entries use different keys, preventing
/// cross-session ID token leakage.
pub fn cache_different_keys_isolate_tokens_test() {
  let cache = id_token_cache.init_named("sec_cache_isolation")
  let key_a = "random_key_session_a"
  let key_b = "random_key_session_b"
  let token_a = "id_token_a\nclient_a"
  let token_b = "id_token_b\nclient_b"

  id_token_cache.store(cache, key_a, token_a)
  id_token_cache.store(cache, key_b, token_b)

  // Each key retrieves only its own token
  let assert Ok(retrieved_a) = id_token_cache.retrieve(cache, key_a)
  retrieved_a |> expect.to_equal(token_a)

  let assert Ok(retrieved_b) = id_token_cache.retrieve(cache, key_b)
  retrieved_b |> expect.to_equal(token_b)
}

/// Security: the cached value format includes client_id for verification.
pub fn cache_stores_id_token_with_client_id_test() {
  let cache = id_token_cache.init_named("sec_cache_format")
  let cache_key = "format_test_key"
  let id_token = "eyJhbGciOiJFUzI1NiJ9.payload.sig"
  let client_id = "com.example.app"

  // Store in the format used by exchange_code: "id_token\nclient_id"
  id_token_cache.store(cache, cache_key, id_token <> "\n" <> client_id)

  let assert Ok(cached) = id_token_cache.retrieve(cache, cache_key)
  let assert Ok(#(retrieved_token, retrieved_client_id)) =
    string.split_once(cached, "\n")
  retrieved_token |> expect.to_equal(id_token)
  retrieved_client_id |> expect.to_equal(client_id)
}
