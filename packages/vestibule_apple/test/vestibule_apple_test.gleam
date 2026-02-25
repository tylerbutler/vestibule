import gleam/option.{None, Some}
import startest
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule_apple

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// --- Strategy construction ---

pub fn strategy_provider_test() {
  let s = vestibule_apple.strategy()
  s.provider |> expect.to_equal("apple")
}

pub fn strategy_default_scopes_test() {
  let s = vestibule_apple.strategy()
  s.default_scopes |> expect.to_equal(["name", "email"])
}

pub fn strategy_token_url_test() {
  let s = vestibule_apple.strategy()
  s.token_url |> expect.to_equal("https://appleid.apple.com/auth/token")
}

// --- Token response parsing ---

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"a1b2c3.test_access_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"r4e5f6.test_refresh\",\"id_token\":\"header.payload.signature\"}"
  let assert Ok(#(creds, id_token)) = vestibule_apple.parse_token_response(body)
  creds
  |> expect.to_equal(
    Credentials(
      token: "a1b2c3.test_access_token",
      refresh_token: Some("r4e5f6.test_refresh"),
      token_type: "Bearer",
      expires_at: Some(3600),
      scopes: [],
    ),
  )
  id_token |> expect.to_equal(Some("header.payload.signature"))
}

pub fn parse_token_response_without_refresh_token_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"id_token\":\"h.p.s\"}"
  let assert Ok(#(creds, id_token)) = vestibule_apple.parse_token_response(body)
  creds.token |> expect.to_equal("test_token")
  creds.refresh_token |> expect.to_equal(None)
  id_token |> expect.to_equal(Some("h.p.s"))
}

pub fn parse_token_response_without_id_token_test() {
  let body =
    "{\"access_token\":\"test_token\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
  let assert Ok(#(creds, id_token)) = vestibule_apple.parse_token_response(body)
  creds.token |> expect.to_equal("test_token")
  id_token |> expect.to_equal(None)
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"The code has expired.\"}"
  let _ =
    vestibule_apple.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn parse_token_response_error_without_description_test() {
  let body = "{\"error\":\"invalid_client\"}"
  let _ =
    vestibule_apple.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

// --- ID token JWT decoding ---

pub fn decode_id_token_valid_test() {
  // Build a valid JWT with a base64url-encoded payload
  // Payload: {"iss":"https://appleid.apple.com","sub":"000000.abcdef1234567890.0000","aud":"com.example.app","email":"user@example.com","email_verified":"true"}
  // Base64url of that payload:
  let payload =
    "eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwic3ViIjoiMDAwMDAwLmFiY2RlZjEyMzQ1Njc4OTAuMDAwMCIsImF1ZCI6ImNvbS5leGFtcGxlLmFwcCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSJ9"
  let jwt = "eyJhbGciOiJSUzI1NiJ9." <> payload <> ".fake_signature"
  let assert Ok(#(uid, info)) = vestibule_apple.decode_id_token(jwt)
  uid |> expect.to_equal("000000.abcdef1234567890.0000")
  info.email |> expect.to_equal(Some("user@example.com"))
  info.nickname |> expect.to_equal(Some("user@example.com"))
  info.name |> expect.to_equal(None)
  info.image |> expect.to_equal(None)
}

pub fn decode_id_token_unverified_email_test() {
  // Payload: {"sub":"uid-123","email":"user@example.com","email_verified":"false"}
  let payload =
    "eyJzdWIiOiJ1aWQtMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJmYWxzZSJ9"
  let jwt = "header." <> payload <> ".sig"
  let assert Ok(#(uid, info)) = vestibule_apple.decode_id_token(jwt)
  uid |> expect.to_equal("uid-123")
  // Email should be None because it's not verified
  info.email |> expect.to_equal(None)
  // Nickname should still have the email
  info.nickname |> expect.to_equal(Some("user@example.com"))
}

pub fn decode_id_token_boolean_email_verified_test() {
  // Some Apple responses use boolean true instead of string "true"
  // Payload: {"sub":"uid-456","email":"test@example.com","email_verified":true}
  let payload =
    "eyJzdWIiOiJ1aWQtNDU2IiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWV9"
  let jwt = "header." <> payload <> ".sig"
  let assert Ok(#(uid, info)) = vestibule_apple.decode_id_token(jwt)
  uid |> expect.to_equal("uid-456")
  info.email |> expect.to_equal(Some("test@example.com"))
}

pub fn decode_id_token_minimal_test() {
  // Payload: {"sub":"minimal-uid"}
  let payload = "eyJzdWIiOiJtaW5pbWFsLXVpZCJ9"
  let jwt = "header." <> payload <> ".sig"
  let assert Ok(#(uid, info)) = vestibule_apple.decode_id_token(jwt)
  uid |> expect.to_equal("minimal-uid")
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(None)
  info.name |> expect.to_equal(None)
}

pub fn decode_id_token_malformed_jwt_test() {
  let _ =
    vestibule_apple.decode_id_token("not-a-jwt")
    |> expect.to_be_error()
  Nil
}

pub fn decode_id_token_invalid_base64_test() {
  let _ =
    vestibule_apple.decode_id_token("header.!!!invalid!!!.sig")
    |> expect.to_be_error()
  Nil
}

// --- ID token claims parsing ---

pub fn parse_id_token_claims_full_test() {
  let json_string =
    "{\"iss\":\"https://appleid.apple.com\",\"sub\":\"000000.abcdef.0000\",\"email\":\"user@example.com\",\"email_verified\":\"true\"}"
  let assert Ok(#(uid, info)) =
    vestibule_apple.parse_id_token_claims(json_string)
  uid |> expect.to_equal("000000.abcdef.0000")
  info.email |> expect.to_equal(Some("user@example.com"))
  info.nickname |> expect.to_equal(Some("user@example.com"))
}

pub fn parse_id_token_claims_without_email_test() {
  let json_string = "{\"sub\":\"uid-only\"}"
  let assert Ok(#(uid, info)) =
    vestibule_apple.parse_id_token_claims(json_string)
  uid |> expect.to_equal("uid-only")
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(None)
}

pub fn parse_id_token_claims_email_verified_as_string_true_test() {
  let json_string =
    "{\"sub\":\"uid\",\"email\":\"a@b.com\",\"email_verified\":\"true\"}"
  let assert Ok(#(_uid, info)) =
    vestibule_apple.parse_id_token_claims(json_string)
  info.email |> expect.to_equal(Some("a@b.com"))
}

pub fn parse_id_token_claims_email_verified_as_string_false_test() {
  let json_string =
    "{\"sub\":\"uid\",\"email\":\"a@b.com\",\"email_verified\":\"false\"}"
  let assert Ok(#(_uid, info)) =
    vestibule_apple.parse_id_token_claims(json_string)
  info.email |> expect.to_equal(None)
}

pub fn parse_id_token_claims_email_verified_as_bool_test() {
  let json_string =
    "{\"sub\":\"uid\",\"email\":\"a@b.com\",\"email_verified\":true}"
  let assert Ok(#(_uid, info)) =
    vestibule_apple.parse_id_token_claims(json_string)
  info.email |> expect.to_equal(Some("a@b.com"))
}

pub fn parse_id_token_claims_invalid_json_test() {
  let _ =
    vestibule_apple.parse_id_token_claims("not json")
    |> expect.to_be_error()
  Nil
}
