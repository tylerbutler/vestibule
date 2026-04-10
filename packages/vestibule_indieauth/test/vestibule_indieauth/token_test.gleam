import gleam/option.{None, Some}
import startest
import startest/expect

import vestibule_indieauth/token

pub fn main() {
  startest.run(startest.default_config())
}

// === parse_token_response ===

pub fn parse_token_response_full_test() {
  let json =
    "{
    \"access_token\": \"XXXXXX\",
    \"token_type\": \"Bearer\",
    \"scope\": \"profile email create\",
    \"me\": \"https://user.example.net/\",
    \"expires_in\": 3600,
    \"refresh_token\": \"RRRRRR\"
  }"

  let result = token.parse_token_response(json)
  let assert Ok(creds) = result

  creds.token
  |> expect.to_equal("XXXXXX")

  creds.token_type
  |> expect.to_equal("Bearer")

  creds.scopes
  |> expect.to_equal(["profile", "email", "create"])

  creds.expires_at
  |> expect.to_equal(Some(3600))

  creds.refresh_token
  |> expect.to_equal(Some("RRRRRR"))
}

pub fn parse_token_response_minimal_test() {
  let json =
    "{
    \"access_token\": \"abc123\",
    \"token_type\": \"Bearer\",
    \"scope\": \"profile\",
    \"me\": \"https://user.example.net/\"
  }"

  let result = token.parse_token_response(json)
  let assert Ok(creds) = result

  creds.token
  |> expect.to_equal("abc123")

  creds.scopes
  |> expect.to_equal(["profile"])

  creds.expires_at
  |> expect.to_equal(None)

  creds.refresh_token
  |> expect.to_equal(None)
}

pub fn parse_token_response_empty_scope_test() {
  let json =
    "{
    \"access_token\": \"abc\",
    \"token_type\": \"Bearer\",
    \"me\": \"https://user.example.net/\"
  }"

  let result = token.parse_token_response(json)
  let assert Ok(creds) = result

  creds.scopes
  |> expect.to_equal([])
}

pub fn parse_token_response_error_test() {
  let json =
    "{
    \"error\": \"invalid_grant\",
    \"error_description\": \"The authorization code has expired\"
  }"

  let _ =
    token.parse_token_response(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_token_response_error_no_description_test() {
  let json = "{ \"error\": \"access_denied\" }"

  let _ =
    token.parse_token_response(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_token_response_invalid_json_test() {
  let _ =
    token.parse_token_response("not json at all")
    |> expect.to_be_error()
  Nil
}

// === parse_profile_from_token_response ===

pub fn parse_profile_full_test() {
  let json =
    "{
    \"access_token\": \"XXXXXX\",
    \"token_type\": \"Bearer\",
    \"scope\": \"profile email\",
    \"me\": \"https://user.example.net/\",
    \"profile\": {
      \"name\": \"Example User\",
      \"url\": \"https://user.example.net/\",
      \"photo\": \"https://user.example.net/photo.jpg\",
      \"email\": \"user@example.net\"
    }
  }"

  let result = token.parse_profile_from_token_response(json)
  let assert Ok(profile) = result

  profile.me
  |> expect.to_equal("https://user.example.net/")

  profile.name
  |> expect.to_equal(Some("Example User"))

  profile.url
  |> expect.to_equal(Some("https://user.example.net/"))

  profile.photo
  |> expect.to_equal(Some("https://user.example.net/photo.jpg"))

  profile.email
  |> expect.to_equal(Some("user@example.net"))
}

pub fn parse_profile_no_profile_object_test() {
  let json =
    "{
    \"access_token\": \"abc\",
    \"token_type\": \"Bearer\",
    \"me\": \"https://user.example.net/\"
  }"

  let result = token.parse_profile_from_token_response(json)
  let assert Ok(profile) = result

  profile.me
  |> expect.to_equal("https://user.example.net/")

  profile.name
  |> expect.to_equal(None)

  profile.email
  |> expect.to_equal(None)
}

pub fn parse_profile_partial_test() {
  let json =
    "{
    \"access_token\": \"abc\",
    \"token_type\": \"Bearer\",
    \"me\": \"https://user.example.net/\",
    \"profile\": {
      \"name\": \"Just a Name\"
    }
  }"

  let result = token.parse_profile_from_token_response(json)
  let assert Ok(profile) = result

  profile.name
  |> expect.to_equal(Some("Just a Name"))

  profile.email
  |> expect.to_equal(None)

  profile.photo
  |> expect.to_equal(None)
}

pub fn parse_profile_missing_me_test() {
  let json = "{ \"access_token\": \"abc\", \"token_type\": \"Bearer\" }"

  let _ =
    token.parse_profile_from_token_response(json)
    |> expect.to_be_error()
  Nil
}

// === parse_userinfo_response ===

pub fn parse_userinfo_full_test() {
  let json =
    "{
    \"me\": \"https://user.example.net/\",
    \"name\": \"Example User\",
    \"url\": \"https://user.example.net/\",
    \"photo\": \"https://user.example.net/photo.jpg\",
    \"email\": \"user@example.net\"
  }"

  let result = token.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result

  uid
  |> expect.to_equal("https://user.example.net/")

  info.name
  |> expect.to_equal(Some("Example User"))

  info.email
  |> expect.to_equal(Some("user@example.net"))

  info.image
  |> expect.to_equal(Some("https://user.example.net/photo.jpg"))
}

pub fn parse_userinfo_minimal_test() {
  let json = "{ \"me\": \"https://user.example.net/\" }"

  let result = token.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result

  uid
  |> expect.to_equal("https://user.example.net/")

  info.name
  |> expect.to_equal(None)

  info.email
  |> expect.to_equal(None)
}

pub fn parse_userinfo_invalid_json_test() {
  let _ =
    token.parse_userinfo_response("bad json")
    |> expect.to_be_error()
  Nil
}
