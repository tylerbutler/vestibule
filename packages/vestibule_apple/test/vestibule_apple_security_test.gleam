//// Security-focused tests for the Apple Sign In strategy.
////
//// These tests verify security properties identified during the
//// 2026-02-25 security audit. The Apple strategy uses ywt_core for
//// JWT parsing/claims with a custom FFI backend for crypto verification.

import gleam/crypto
import gleam/http/request
import gleam/http/response
import gleam/json as gleam_json
import gleam/list
import gleam/option.{None, Some}
import gleam/time/duration
import vestibule/error
import vestibule/nonce
import vestibule/user_info
import vestibule_apple
import vestibule_apple/jwks
import vestibule_apple/jwt_signing
import ywt/claim
import ywt/sign_key
import ywt/verify_key

// ===========================================================================
// JWT Signature Verification Tests (Audit finding C1 -- FIXED)
// ===========================================================================

/// Security: verify_id_token rejects a JWT signed with the wrong key.
/// This is the core fix for finding C1.
pub fn verify_id_token_rejects_wrong_key_test() -> Nil {
  let signing_key = jwt_signing.test_key()
  let assert Ok(other_keys) = jwks.parse_jwks(jwt_signing.other_key_jwks())

  let token =
    jwt_signing.encode(
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
      signing_key,
    )

  let result =
    vestibule_apple.verify_id_token(
      jwt: token,
      keys: other_keys,
      client_id: "com.example.app",
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

/// Security: verify_id_token accepts a JWT signed with the correct key.
pub fn verify_id_token_accepts_correct_key_test() -> Nil {
  let key = jwt_signing.test_key()

  let token =
    jwt_signing.encode(
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
      jwt: token,
      keys: [jwt_signing.test_verify_key()],
      client_id: "com.example.app",
    )
  let assert Ok(#(user_id, user_information)) = result
  let _ =
    user_id
    |> fn(actual) {
      assert actual == "user-123"
    }
  let _ =
    user_info.email(user_information)
    |> fn(actual) {
      assert actual == Some("user@example.com")
    }
  Nil
}

/// Security: verify_id_token rejects JWT with wrong issuer.
pub fn verify_id_token_rejects_wrong_issuer_test() -> Nil {
  let key = jwt_signing.test_key()

  let token =
    jwt_signing.encode(
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
      jwt: token,
      keys: [jwt_signing.test_verify_key()],
      client_id: "com.example.app",
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

/// Security: verify_id_token rejects JWT with wrong audience.
pub fn verify_id_token_rejects_wrong_audience_test() -> Nil {
  let key = jwt_signing.test_key()

  let token =
    jwt_signing.encode(
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
      jwt: token,
      keys: [jwt_signing.test_verify_key()],
      client_id: "com.example.app",
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

/// Security: verify_id_token rejects a completely forged JWT.
pub fn verify_id_token_rejects_forged_jwt_test() -> Nil {
  let forged_payload =
    "eyJzdWIiOiJhdHRhY2tlci11aWQiLCJlbWFpbCI6InZpY3RpbUBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSJ9"
  let forged_jwt = "eyJhbGciOiJIUzI1NiJ9." <> forged_payload <> ".AAAA"

  let result =
    vestibule_apple.verify_id_token(
      jwt: forged_jwt,
      keys: [jwt_signing.test_verify_key()],
      client_id: "com.example.app",
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

/// Security: verify_id_token handles email_verified correctly.
pub fn verify_id_token_unverified_email_not_returned_test() -> Nil {
  let key = jwt_signing.test_key()

  let token =
    jwt_signing.encode(
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

  let assert Ok(#(_, user_information)) =
    vestibule_apple.verify_id_token(
      jwt: token,
      keys: [jwt_signing.test_verify_key()],
      client_id: "com.example.app",
    )
  let _ =
    user_info.email(user_information)
    |> fn(actual) {
      assert actual == None
    }
  let _ =
    user_info.nickname(user_information)
    |> fn(actual) {
      assert actual == Some("user@example.com")
    }
  Nil
}

/// Security: Apple tokens must use RS256, preventing algorithm confusion.
pub fn verify_id_token_rejects_algorithm_confusion_test() -> Nil {
  let rs256_token =
    jwt_signing.encode(
      [#("sub", gleam_json.string("uid"))],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      jwt_signing.test_key(),
    )
  ["HS256", "ES256", "RS384", "PS256"]
  |> list.each(fn(algorithm) {
    let assert Error(authentication_error) =
      vestibule_apple.verify_id_token(
        jwt: jwt_signing.with_algorithm(rs256_token, algorithm),
        keys: [jwt_signing.test_verify_key()],
        client_id: "com.example.app",
      )
    assert error.kind(authentication_error) == error.UserInfoKind
  })
}

/// Security: caller-supplied symmetric keys are never accepted for Apple.
pub fn verify_id_token_rejects_hmac_key_test() -> Nil {
  let token =
    jwt_signing.encode(
      [#("sub", gleam_json.string("uid"))],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      jwt_signing.test_key(),
    )
  let assert Ok(hmac_key) = sign_key.hs256(crypto.strong_random_bytes(32))

  let assert Error(authentication_error) =
    vestibule_apple.verify_id_token(
      jwt: token,
      keys: [verify_key.derived(hmac_key)],
      client_id: "com.example.app",
    )
  assert error.kind(authentication_error) == error.UserInfoKind
}

/// Security: caller-supplied ECDSA keys are never accepted for Apple.
pub fn verify_id_token_rejects_ecdsa_key_test() -> Nil {
  let token =
    jwt_signing.encode(
      [#("sub", gleam_json.string("uid"))],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      jwt_signing.test_key(),
    )
  let ec_jwk =
    "{\"kty\":\"EC\",\"kid\":\"apple-test-key\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}"
  let assert Ok(ec_key) = gleam_json.parse(ec_jwk, verify_key.decoder())

  let assert Error(authentication_error) =
    vestibule_apple.verify_id_token(
      jwt: token,
      keys: [ec_key],
      client_id: "com.example.app",
    )
  assert error.kind(authentication_error) == error.UserInfoKind
}

/// Security: expired Apple ID tokens are rejected after RSA verification.
pub fn verify_id_token_rejects_expired_token_test() -> Nil {
  let token =
    jwt_signing.encode(
      [#("sub", gleam_json.string("uid"))],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(-5),
          leeway: duration.seconds(0),
        ),
      ],
      jwt_signing.test_key(),
    )

  let assert Error(authentication_error) =
    vestibule_apple.verify_id_token(
      jwt: token,
      keys: [jwt_signing.test_verify_key()],
      client_id: "com.example.app",
    )
  assert error.kind(authentication_error) == error.UserInfoKind
}

/// Security: nonce values from signed ID tokens remain subject to the core
/// constant-time callback binding check.
pub fn signed_id_token_nonce_binding_test() -> Nil {
  let token =
    jwt_signing.encode(
      [
        #("sub", gleam_json.string("uid")),
        #("nonce", gleam_json.string("expected-nonce")),
      ],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      jwt_signing.test_key(),
    )

  let assert Ok(_) =
    vestibule_apple.verify_id_token(
      jwt: token,
      keys: [jwt_signing.test_verify_key()],
      client_id: "com.example.app",
    )
  assert nonce.validate(received: "expected-nonce", expected: "expected-nonce")
    == Ok(Nil)
  let assert Error(authentication_error) =
    nonce.validate(received: "attacker-nonce", expected: "expected-nonce")
  assert error.kind(authentication_error) == error.InvalidNonceKind
}

// ===========================================================================
// JWKS Parsing Tests
// ===========================================================================

/// Security: JWKS parser handles valid Apple-format JWKS.
pub fn parse_jwks_valid_test() -> Nil {
  let jwks_json =
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"7YayUS1XhvLBTpAUpYtLbqjfT7er5h2X1C8AMS6p4QZFGUy7bF7niXRZ6ljVFLEmqctz_yRDP56rcnZoAt5DBd7FNdY-UtgwjvNnvCT3nxRSagjr43a1J0dXgzBiUNFXOkvsYfCFqgvRP8MiY_UcxUFPdQSTukEOhS7pCeK3ZGYFaq7Yk2E1qkg8YaQJ5h0JyLGC3qzNIKEi_J7ZH4D7mXxZ-oqeyQiAJS1YDzeWGdk6OINHHdkw-4DjdpCteQDVaZK_MUwWqQArazXIjhHLSBOoShIEDaR62trJ7VRindA56AtuaJTq2gYnSbNgvENDPag6NVRRaOYdoGjVJokhbQ\",\"e\":\"AQAB\"}]}"
  let _ =
    jwks.parse_jwks(jwks_json)
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
  Nil
}

pub fn parse_jwks_rejects_wrong_key_type_test() -> Nil {
  let ec_jwks =
    "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"test-key\",\"use\":\"sig\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}]}"
  let assert Error(authentication_error) = jwks.parse_jwks(ec_jwks)
  assert error.kind(authentication_error) == error.ConfigKind
}

pub fn parse_jwks_rejects_non_rs256_rsa_key_test() -> Nil {
  let rsa_jwks =
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test-key\",\"use\":\"sig\",\"alg\":\"RS384\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}"
  let assert Error(authentication_error) = jwks.parse_jwks(rsa_jwks)
  assert error.kind(authentication_error) == error.ConfigKind
}

pub fn parse_jwks_rejects_malformed_rsa_key_without_crashing_test() -> Nil {
  let malformed_jwks =
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"%%%\",\"e\":\"\"}]}"
  let assert Error(authentication_error) = jwks.parse_jwks(malformed_jwks)
  assert error.kind(authentication_error) == error.ConfigKind
}

pub fn zero_rsa_key_cannot_crash_verification_test() -> Nil {
  let zero_key_jwks =
    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"apple-test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"AA\",\"e\":\"AA\"}]}"
  let assert Ok(keys) = jwks.parse_jwks(zero_key_jwks)
  let token =
    jwt_signing.encode(
      [#("sub", gleam_json.string("uid"))],
      [
        claim.issuer("https://appleid.apple.com", []),
        claim.audience("com.example.app", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
      jwt_signing.test_key(),
    )
  let assert Error(authentication_error) =
    vestibule_apple.verify_id_token(
      jwt: token,
      keys: keys,
      client_id: "com.example.app",
    )
  assert error.kind(authentication_error) == error.UserInfoKind
}

pub fn verify_id_token_malformed_inputs_never_crash_test() -> Nil {
  let malformed_tokens = [
    "",
    "not-a-jwt",
    "a.b",
    "a.b.c.d",
    "%%%.e30.AAAA",
    "eyJhbGciOiJSUzI1NiJ9.%%%.AAAA",
    "eyJhbGciOiJSUzI1NiJ9.e30.%%%",
  ]
  malformed_tokens
  |> list.each(fn(token) {
    let assert Error(_) =
      vestibule_apple.verify_id_token(
        jwt: token,
        keys: [jwt_signing.test_verify_key()],
        client_id: "com.example.app",
      )
    Nil
  })
}

/// Security: JWKS parser rejects invalid JSON.
pub fn parse_jwks_rejects_invalid_json_test() -> Nil {
  let _ =
    jwks.parse_jwks("not json")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

/// Security: JWKS parser accepts empty key set.
pub fn parse_jwks_accepts_empty_keys_test() -> Nil {
  let result = jwks.parse_jwks("{\"keys\":[]}")
  let assert Ok(keys) = result
  let _ =
    keys
    |> fn(actual) {
      assert actual == []
    }
  Nil
}

pub fn jwks_request_and_response_are_separate_test() -> Nil {
  let assert Ok(http_request) = jwks.build_jwks_request()
  assert http_request.host == "appleid.apple.com"
  assert http_request.path == "/auth/keys"
  assert request.get_header(http_request, "accept") == Ok("application/json")

  let http_response =
    response.Response(status: 200, headers: [], body: "{\"keys\":[]}")
  let assert Ok(keys) = jwks.parse_jwks_response(http_response)
  assert keys == []
}

// ===========================================================================
// Token Response Security Tests
// ===========================================================================

/// Security: error response without error_description should still be detected.
pub fn apple_token_error_without_description_test() -> Nil {
  let _ =
    vestibule_apple.parse_token_response("{\"error\":\"invalid_client\"}")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

/// Security: HTML error response from misconfigured proxy should not crash.
pub fn apple_token_response_handles_html_test() -> Nil {
  let _ =
    vestibule_apple.parse_token_response(
      "<html><body>502 Bad Gateway</body></html>",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

/// Security: empty response should not crash.
pub fn apple_token_response_handles_empty_test() -> Nil {
  let _ =
    vestibule_apple.parse_token_response("")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}
