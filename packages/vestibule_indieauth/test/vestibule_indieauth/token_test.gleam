import gleam/option.{None, Some}

import vestibule/credentials
import vestibule/error
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
  |> credentials.token
  |> fn(actual) {
    assert actual == "XXXXXX"
  }

  oauth_credentials
  |> credentials.token_type
  |> fn(actual) {
    assert actual == "Bearer"
  }

  oauth_credentials
  |> credentials.scopes
  |> fn(actual) {
    assert actual == ["profile", "email", "create"]
  }

  oauth_credentials
  |> credentials.expires_in
  |> fn(actual) {
    assert actual == Some(3600)
  }

  oauth_credentials
  |> credentials.refresh_token
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
  |> credentials.token
  |> fn(actual) {
    assert actual == "abc123"
  }

  oauth_credentials
  |> credentials.scopes
  |> fn(actual) {
    assert actual == ["profile"]
  }

  oauth_credentials
  |> credentials.expires_in
  |> fn(actual) {
    assert actual == None
  }

  oauth_credentials
  |> credentials.refresh_token
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
  |> credentials.scopes
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
  let assert Ok(#(uid, info)) = result

  uid
  |> fn(actual) {
    assert actual == "https://user.example.net/"
  }

  user_info.name(info)
  |> fn(actual) {
    assert actual == Some("Example User")
  }

  user_info.email(info)
  |> fn(actual) {
    assert actual == Some("user@example.net")
  }

  user_info.image(info)
  |> fn(actual) {
    assert actual == Some("https://user.example.net/photo.jpg")
  }
}

pub fn parse_userinfo_minimal_test() -> Nil {
  let json = "{ \"me\": \"https://user.example.net/\" }"

  let result = token.parse_userinfo_response(json)
  let assert Ok(#(uid, info)) = result

  uid
  |> fn(actual) {
    assert actual == "https://user.example.net/"
  }

  user_info.name(info)
  |> fn(actual) {
    assert actual == None
  }

  user_info.email(info)
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
  let assert Error(err) = token.parse_profile_from_token_response(json)
  error.kind(err)
  |> fn(actual) {
    assert actual == error.UserInfoKind
  }
}

// === request sites refuse non-public endpoints before any network I/O ===

pub fn exchange_code_rejects_non_public_token_endpoint_test() -> Nil {
  let assert Error(err) =
    token.exchange_code(
      "http://169.254.169.254/latest/api/token",
      "https://app.example.com/",
      "https://app.example.com/callback",
      "code",
      None,
    )
  error.kind(err)
  |> fn(actual) {
    assert actual == error.ConfigKind
  }
}

pub fn refresh_rejects_non_public_token_endpoint_test() -> Nil {
  let assert Error(err) =
    token.refresh("https://10.0.0.5/token", "https://app.example.com/", "rt")
  error.kind(err)
  |> fn(actual) {
    assert actual == error.ConfigKind
  }
}

pub fn fetch_userinfo_rejects_non_public_endpoint_test() -> Nil {
  let creds =
    credentials.new(
      token: "t",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: [],
    )
  let assert Error(err) =
    token.fetch_userinfo("https://localhost/userinfo", creds)
  error.kind(err)
  |> fn(actual) {
    assert actual == error.ConfigKind
  }
}
