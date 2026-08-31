import gleam/dict
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import vestibule/config
import vestibule/credential
import vestibule/strategy
import vestibule/user_info
import vestibule_github

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn parse_token_response_success_test() -> Nil {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email\"}"
  vestibule_github.parse_token_response(json)
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual
      == credential.new(
        token: "gho_abc123",
        refresh_token: None,
        token_type: "bearer",
        expires_in: None,
        scopes: ["user:email"],
      )
  }
}

pub fn parse_token_response_with_multiple_scopes_test() -> Nil {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email,read:org\"}"
  let result = vestibule_github.parse_token_response(json)
  let assert Ok(oauth_credentials) = result
  credential.scopes(oauth_credentials)
  |> fn(actual) {
    assert actual == ["user:email", "read:org"]
  }
}

pub fn parse_token_response_empty_scope_test() -> Nil {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"\"}"
  let assert Ok(oauth_credentials) = vestibule_github.parse_token_response(json)
  credential.scopes(oauth_credentials)
  |> fn(actual) {
    assert actual == []
  }
}

pub fn parse_token_response_error_test() -> Nil {
  let json =
    "{\"error\":\"bad_verification_code\",\"error_description\":\"The code has expired\"}"
  let _ =
    vestibule_github.parse_token_response(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_user_response_full_test() -> Nil {
  let json =
    "{\"id\":12345,\"login\":\"octocat\",\"name\":\"The Octocat\",\"avatar_url\":\"https://avatars.githubusercontent.com/u/12345\",\"bio\":\"A cat that codes\",\"html_url\":\"https://github.com/octocat\"}"
  let result = vestibule_github.parse_user_response(json)
  let assert Ok(#(user_id, user_information)) = result
  user_id
  |> fn(actual) {
    assert actual == "12345"
  }
  user_info.name(user_information)
  |> fn(actual) {
    assert actual == Some("The Octocat")
  }
  user_info.nickname(user_information)
  |> fn(actual) {
    assert actual == Some("octocat")
  }
  user_info.image(user_information)
  |> fn(actual) {
    assert actual == Some("https://avatars.githubusercontent.com/u/12345")
  }
  user_info.description(user_information)
  |> fn(actual) {
    assert actual == Some("A cat that codes")
  }
  user_info.urls(user_information)
  |> fn(actual) {
    assert actual
      == dict.from_list([
        #("html_url", "https://github.com/octocat"),
      ])
  }
}

pub fn parse_user_response_minimal_test() -> Nil {
  let json = "{\"id\":99,\"login\":\"minimal\"}"
  let result = vestibule_github.parse_user_response(json)
  let assert Ok(#(user_id, user_information)) = result
  user_id
  |> fn(actual) {
    assert actual == "99"
  }
  user_info.name(user_information)
  |> fn(actual) {
    assert actual == None
  }
  user_info.email(user_information)
  |> fn(actual) {
    assert actual == None
  }
}

pub fn parse_emails_response_test() -> Nil {
  let json =
    "[{\"email\":\"octocat@github.com\",\"primary\":true,\"verified\":true},{\"email\":\"other@example.com\",\"primary\":false,\"verified\":true}]"
  vestibule_github.parse_primary_email(json)
  |> fn(actual) {
    assert actual == Ok(Some("octocat@github.com"))
  }
}

pub fn parse_emails_no_verified_primary_test() -> Nil {
  let json =
    "[{\"email\":\"unverified@example.com\",\"primary\":true,\"verified\":false}]"
  vestibule_github.parse_primary_email(json)
  |> fn(actual) {
    assert actual == Ok(None)
  }
}

pub fn parse_emails_malformed_json_is_error_test() -> Nil {
  let _ =
    vestibule_github.parse_primary_email("not json")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() -> Nil {
  let github_strategy = vestibule_github.strategy()
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.ClientSecret("secret"),
    )
  let _ =
    strategy.build_authorize_url(
      github_strategy,
      config: client_configuration,
      options: config.authorize_options(),
      scopes: ["user:email"],
      state: "state",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn authorize_url_includes_extra_parameters_test() -> Nil {
  let github_strategy = vestibule_github.strategy()
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("allow_signup", "false")])
  let assert Ok(authorization_url) =
    strategy.build_authorize_url(
      github_strategy,
      config: client_configuration,
      options: options,
      scopes: ["user:email"],
      state: "state",
    )
  { string.contains(authorization_url, "allow_signup=false") }
  |> fn(actual) {
    assert actual
  }
}

pub fn sans_io_token_request_and_response_test() -> Nil {
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("client-secret"),
    )
  let assert Ok(http_request) =
    vestibule_github.build_authorization_code_request(
      client_configuration,
      "code-123",
      Some("verifier-123"),
    )
  assert http_request.method == http.Post
  assert http_request.host == "github.com"
  assert string.ends_with(http_request.path, "/login/oauth/access_token")
  assert string.contains(http_request.body, "code=code-123")
  assert string.contains(http_request.body, "code_verifier=verifier-123")
  assert request.get_header(http_request, "accept") == Ok("application/json")

  let http_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email\"}",
    )
  let assert Ok(exchange) =
    vestibule_github.parse_authorization_code_response(http_response)
  assert exchange
    |> strategy.exchange_credentials
    |> credential.token
    == "gho_abc123"
}

pub fn sans_io_refresh_and_user_requests_test() -> Nil {
  let client_configuration =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.ClientSecret("client-secret"),
    )
  let assert Ok(refresh_request) =
    vestibule_github.build_refresh_token_request(
      client_configuration,
      "refresh-123",
    )
  assert string.contains(refresh_request.body, "grant_type=refresh_token")
  assert string.contains(refresh_request.body, "refresh_token=refresh-123")
  let refresh_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"new-access\",\"token_type\":\"Bearer\",\"scope\":\"user:email\"}",
    )
  let assert Ok(refreshed_credentials) =
    vestibule_github.parse_refresh_token_response(refresh_response)
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
    vestibule_github.build_user_info_request(oauth_credentials)
  assert user_request.host == "api.github.com"
  assert user_request.path == "/user"
  assert request.get_header(user_request, "authorization")
    == Ok("Bearer access-123")

  let user_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"id\":99,\"login\":\"sans-io\"}",
    )
  let assert Ok(#(user_id, _)) =
    vestibule_github.parse_user_info_response(user_response)
  assert user_id == "99"

  let assert Ok(email_request) =
    vestibule_github.build_user_email_request(oauth_credentials)
  assert email_request.path == "/user/emails"
  let email_response =
    response.Response(
      status: 200,
      headers: [],
      body: "[{\"email\":\"user@example.com\",\"primary\":true,\"verified\":true}]",
    )
  assert vestibule_github.parse_user_email_response(email_response)
    == Ok(Some("user@example.com"))
}
