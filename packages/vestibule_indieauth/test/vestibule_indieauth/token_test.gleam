import gleam/option.{None, Some}

import vestibule/credentials
import vestibule/user_info

import vestibule_indieauth/token

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

  assert credentials.token(creds) == "XXXXXX"

  assert credentials.token_type(creds) == "Bearer"

  assert credentials.scopes(creds) == ["profile", "email", "create"]

  assert credentials.expires_in(creds) == Some(3600)

  assert credentials.refresh_token(creds) == Some("RRRRRR")
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

  assert credentials.token(creds) == "abc123"

  assert credentials.scopes(creds) == ["profile"]

  assert credentials.expires_in(creds) == None

  assert credentials.refresh_token(creds) == None
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

  assert credentials.scopes(creds) == []
}

pub fn parse_token_response_error_test() {
  let json =
    "{
    \"error\": \"invalid_grant\",
    \"error_description\": \"The authorization code has expired\"
  }"

  let assert Error(_) = token.parse_token_response(json)
  Nil
}

pub fn parse_token_response_error_no_description_test() {
  let json = "{ \"error\": \"access_denied\" }"

  let assert Error(_) = token.parse_token_response(json)
  Nil
}

pub fn parse_token_response_invalid_json_test() {
  let assert Error(_) = token.parse_token_response("not json at all")
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

  assert profile.me == "https://user.example.net/"

  assert profile.name == Some("Example User")

  assert profile.url == Some("https://user.example.net/")

  assert profile.photo == Some("https://user.example.net/photo.jpg")

  assert profile.email == Some("user@example.net")
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

  assert profile.me == "https://user.example.net/"

  assert profile.name == None

  assert profile.email == None
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

  assert profile.name == Some("Just a Name")

  assert profile.email == None

  assert profile.photo == None
}

pub fn parse_profile_missing_me_test() {
  let json = "{ \"access_token\": \"abc\", \"token_type\": \"Bearer\" }"

  let assert Error(_) = token.parse_profile_from_token_response(json)
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

  assert uid == "https://user.example.net/"

  assert user_info.name(info) == Some("Example User")

  assert user_info.email(info) == Some("user@example.net")

  assert user_info.image(info) == Some("https://user.example.net/photo.jpg")
}

pub fn parse_userinfo_minimal_test() {
  let json = "{ \"me\": \"https://user.example.net/\" }"

  let result = token.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result

  assert uid == "https://user.example.net/"

  assert user_info.name(info) == None

  assert user_info.email(info) == None
}

pub fn parse_userinfo_invalid_json_test() {
  let assert Error(_) = token.parse_userinfo_response("bad json")
  Nil
}
