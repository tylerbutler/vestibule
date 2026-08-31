import gleam/http
import gleam/http/response
import gleam/option.{None, Some}
import gleam/string

import vestibule/credential
import vestibule/error
import vestibule/provider_support
import vestibule/user_info

import vestibule_indieauth/token

// === parse_token_response ===

pub fn parse_token_response_full_test() -> Nil {
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
  let assert Ok(oauth_credentials) = result

  oauth_credentials
  |> credential.token
  |> fn(actual) {
    assert actual == "XXXXXX"
  }

  oauth_credentials
  |> credential.token_type
  |> fn(actual) {
    assert actual == "Bearer"
  }

  oauth_credentials
  |> credential.scopes
  |> fn(actual) {
    assert actual == ["profile", "email", "create"]
  }

  oauth_credentials
  |> credential.expires_in
  |> fn(actual) {
    assert actual == Some(3600)
  }

  oauth_credentials
  |> credential.refresh_token
  |> fn(actual) {
    assert actual == Some("RRRRRR")
  }
}

pub fn parse_token_response_minimal_test() -> Nil {
  let json =
    "{
    \"access_token\": \"abc123\",
    \"token_type\": \"Bearer\",
    \"scope\": \"profile\",
    \"me\": \"https://user.example.net/\"
  }"

  let result = token.parse_token_response(json)
  let assert Ok(oauth_credentials) = result

  oauth_credentials
  |> credential.token
  |> fn(actual) {
    assert actual == "abc123"
  }

  oauth_credentials
  |> credential.scopes
  |> fn(actual) {
    assert actual == ["profile"]
  }

  oauth_credentials
  |> credential.expires_in
  |> fn(actual) {
    assert actual == None
  }

  oauth_credentials
  |> credential.refresh_token
  |> fn(actual) {
    assert actual == None
  }
}

pub fn parse_token_response_empty_scope_test() -> Nil {
  let json =
    "{
    \"access_token\": \"abc\",
    \"token_type\": \"Bearer\",
    \"me\": \"https://user.example.net/\"
  }"

  let result = token.parse_token_response(json)
  let assert Ok(oauth_credentials) = result

  oauth_credentials
  |> credential.scopes
  |> fn(actual) {
    assert actual == []
  }
}

pub fn parse_token_response_error_test() -> Nil {
  let json =
    "{
    \"error\": \"invalid_grant\",
    \"error_description\": \"The authorization code has expired\"
  }"

  let _ =
    token.parse_token_response(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_token_response_error_no_description_test() -> Nil {
  let json = "{ \"error\": \"access_denied\" }"

  let _ =
    token.parse_token_response(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_token_response_invalid_json_test() -> Nil {
  let _ =
    token.parse_token_response("not json at all")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// === parse_profile_from_token_response ===

pub fn parse_profile_full_test() -> Nil {
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
  |> fn(actual) {
    assert actual == "https://user.example.net/"
  }

  profile.name
  |> fn(actual) {
    assert actual == Some("Example User")
  }

  profile.url
  |> fn(actual) {
    assert actual == Some("https://user.example.net/")
  }

  profile.photo
  |> fn(actual) {
    assert actual == Some("https://user.example.net/photo.jpg")
  }

  profile.email
  |> fn(actual) {
    assert actual == Some("user@example.net")
  }
}

pub fn parse_profile_no_profile_object_test() -> Nil {
  let json =
    "{
    \"access_token\": \"abc\",
    \"token_type\": \"Bearer\",
    \"me\": \"https://user.example.net/\"
  }"

  let result = token.parse_profile_from_token_response(json)
  let assert Ok(profile) = result

  profile.me
  |> fn(actual) {
    assert actual == "https://user.example.net/"
  }

  profile.name
  |> fn(actual) {
    assert actual == None
  }

  profile.email
  |> fn(actual) {
    assert actual == None
  }
}

pub fn parse_profile_partial_test() -> Nil {
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
  |> fn(actual) {
    assert actual == Some("Just a Name")
  }

  profile.email
  |> fn(actual) {
    assert actual == None
  }

  profile.photo
  |> fn(actual) {
    assert actual == None
  }
}

pub fn parse_profile_missing_me_test() -> Nil {
  let json = "{ \"access_token\": \"abc\", \"token_type\": \"Bearer\" }"

  let _ =
    token.parse_profile_from_token_response(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// === parse_userinfo_response ===

pub fn parse_userinfo_full_test() -> Nil {
  let json =
    "{
    \"me\": \"https://user.example.net/\",
    \"name\": \"Example User\",
    \"url\": \"https://user.example.net/\",
    \"photo\": \"https://user.example.net/photo.jpg\",
    \"email\": \"user@example.net\"
  }"

  let result = token.parse_userinfo_response(json)
  let assert Ok(#(user_id, profile_info)) = result

  user_id
  |> fn(actual) {
    assert actual == "https://user.example.net/"
  }

  user_info.name(profile_info)
  |> fn(actual) {
    assert actual == Some("Example User")
  }

  user_info.email(profile_info)
  |> fn(actual) {
    assert actual == Some("user@example.net")
  }

  user_info.image(profile_info)
  |> fn(actual) {
    assert actual == Some("https://user.example.net/photo.jpg")
  }
}

pub fn parse_userinfo_minimal_test() -> Nil {
  let json = "{ \"me\": \"https://user.example.net/\" }"

  let result = token.parse_userinfo_response(json)
  let assert Ok(#(user_id, profile_info)) = result

  user_id
  |> fn(actual) {
    assert actual == "https://user.example.net/"
  }

  user_info.name(profile_info)
  |> fn(actual) {
    assert actual == None
  }

  user_info.email(profile_info)
  |> fn(actual) {
    assert actual == None
  }
}

pub fn parse_userinfo_invalid_json_test() -> Nil {
  let _ =
    token.parse_userinfo_response("bad json")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// === exchange response: me is required ===

pub fn parse_profile_requires_me_test() -> Nil {
  let json = "{ \"access_token\": \"abc\", \"token_type\": \"Bearer\" }"
  let assert Error(auth_error) = token.parse_profile_from_token_response(json)
  error.kind(auth_error)
  |> fn(actual) {
    assert actual == error.UserInfoKind
  }
}

// === request sites refuse non-public endpoints before any network I/O ===

pub fn exchange_code_rejects_non_public_token_endpoint_test() -> Nil {
  let assert Error(auth_error) =
    token.exchange_code(
      "http://169.254.169.254/latest/api/token",
      "https://app.example.com/",
      "https://app.example.com/callback",
      "code",
      None,
    )
  error.kind(auth_error)
  |> fn(actual) {
    assert actual == error.ConfigKind
  }
}

pub fn refresh_rejects_non_public_token_endpoint_test() -> Nil {
  let assert Error(auth_error) =
    token.refresh("https://10.0.0.5/token", "https://app.example.com/", "rt")
  error.kind(auth_error)
  |> fn(actual) {
    assert actual == error.ConfigKind
  }
}

pub fn fetch_userinfo_rejects_non_public_endpoint_test() -> Nil {
  let oauth_credentials =
    credential.new(
      token: "t",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: [],
    )
  let assert Error(auth_error) =
    token.fetch_userinfo("https://localhost/userinfo", oauth_credentials)
  error.kind(auth_error)
  |> fn(actual) {
    assert actual == error.ConfigKind
  }
}

pub fn sans_io_token_request_and_response_test() -> Nil {
  let assert Ok(http_request) =
    token.build_authorization_code_request(
      "https://auth.example.com/token",
      "https://app.example.com/",
      "https://app.example.com/callback",
      "code-123",
      Some("verifier-123"),
    )
  assert provider_support.secure_request_method(http_request) == http.Post
  assert provider_support.secure_request_uri(http_request).host
    == Some("auth.example.com")
  assert string.contains(
    provider_support.secure_request_body(http_request),
    "code=code-123",
  )
  assert string.contains(
    provider_support.secure_request_body(http_request),
    "code_verifier=verifier-123",
  )
  assert provider_support.secure_request_header(http_request, "accept")
    == Ok("application/json")
  assert provider_support.secure_request_response_limit(http_request)
    == provider_support.TokenResponse

  let http_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"access-123\",\"token_type\":\"Bearer\",\"scope\":\"profile\",\"me\":\"https://user.example.com/\"}",
    )
  let assert Ok(#(oauth_credentials, profile)) =
    token.parse_authorization_code_response(http_response)
  assert credential.token(oauth_credentials) == "access-123"
  assert profile.me == "https://user.example.com/"
}

pub fn sans_io_refresh_and_user_info_test() -> Nil {
  let assert Ok(refresh_request) =
    token.build_refresh_token_request(
      "https://auth.example.com/token",
      "https://app.example.com/",
      "refresh-123",
    )
  assert string.contains(
    provider_support.secure_request_body(refresh_request),
    "grant_type=refresh_token",
  )
  let refresh_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"new-access\",\"token_type\":\"Bearer\",\"me\":\"https://user.example.com/\"}",
    )
  let assert Ok(refreshed_credentials) =
    token.parse_refresh_token_response(refresh_response)
  assert credential.token(refreshed_credentials) == "new-access"

  let oauth_credentials =
    credential.new(
      token: "access-123",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: [],
    )
  let assert Ok(user_request) =
    token.build_user_info_request(
      "https://auth.example.com/userinfo",
      oauth_credentials,
    )
  assert provider_support.secure_request_header(user_request, "authorization")
    == Ok("Bearer access-123")

  assert provider_support.secure_request_response_limit(user_request)
    == provider_support.UserInfoResponse

  let user_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"me\":\"https://user.example.com/\"}",
    )
  let assert Ok(#(user_id, _)) = token.parse_user_info_response(user_response)
  assert user_id == "https://user.example.com/"
}
