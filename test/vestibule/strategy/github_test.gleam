import gleam/dict
import gleam/option.{None, Some}
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule/strategy/github

pub fn parse_token_response_success_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email\"}"
  github.parse_token_response(json)
  |> expect.to_be_ok()
  |> expect.to_equal(Credentials(
    token: "gho_abc123",
    refresh_token: None,
    token_type: "bearer",
    expires_at: None,
    scopes: ["user:email"],
  ))
}

pub fn parse_token_response_with_multiple_scopes_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email,read:org\"}"
  let result = github.parse_token_response(json)
  let assert Ok(creds) = result
  creds.scopes |> expect.to_equal(["user:email", "read:org"])
}

pub fn parse_token_response_error_test() {
  let json =
    "{\"error\":\"bad_verification_code\",\"error_description\":\"The code has expired\"}"
  let _ =
    github.parse_token_response(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_user_response_full_test() {
  let json =
    "{\"id\":12345,\"login\":\"octocat\",\"name\":\"The Octocat\",\"avatar_url\":\"https://avatars.githubusercontent.com/u/12345\",\"bio\":\"A cat that codes\",\"html_url\":\"https://github.com/octocat\"}"
  let result = github.parse_user_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> expect.to_equal("12345")
  info.name |> expect.to_equal(Some("The Octocat"))
  info.nickname |> expect.to_equal(Some("octocat"))
  info.image
  |> expect.to_equal(Some(
    "https://avatars.githubusercontent.com/u/12345",
  ))
  info.description |> expect.to_equal(Some("A cat that codes"))
  info.urls
  |> expect.to_equal(dict.from_list([
    #("html_url", "https://github.com/octocat"),
  ]))
}

pub fn parse_user_response_minimal_test() {
  let json = "{\"id\":99,\"login\":\"minimal\"}"
  let result = github.parse_user_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> expect.to_equal("99")
  info.name |> expect.to_equal(None)
  info.email |> expect.to_equal(None)
}

pub fn parse_emails_response_test() {
  let json =
    "[{\"email\":\"octocat@github.com\",\"primary\":true,\"verified\":true},{\"email\":\"other@example.com\",\"primary\":false,\"verified\":true}]"
  github.parse_primary_email(json)
  |> expect.to_equal(Some("octocat@github.com"))
}

pub fn parse_emails_no_verified_primary_test() {
  let json =
    "[{\"email\":\"unverified@example.com\",\"primary\":true,\"verified\":false}]"
  github.parse_primary_email(json)
  |> expect.to_equal(None)
}
