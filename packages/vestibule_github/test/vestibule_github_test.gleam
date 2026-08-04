import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import startest
import startest/expect
import vestibule/config
import vestibule/credentials
import vestibule/strategy
import vestibule/user_info
import vestibule_github

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn parse_token_response_success_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email\"}"
  vestibule_github.parse_token_response(json)
  |> expect.to_be_ok()
  |> expect.to_equal(
    credentials.new(
      token: "gho_abc123",
      refresh_token: None,
      token_type: "bearer",
      expires_in: None,
      scopes: ["user:email"],
    ),
  )
}

pub fn parse_token_response_with_multiple_scopes_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email,read:org\"}"
  let result = vestibule_github.parse_token_response(json)
  let assert Ok(creds) = result
  credentials.scopes(creds) |> expect.to_equal(["user:email", "read:org"])
}

pub fn parse_token_response_empty_scope_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"\"}"
  let assert Ok(creds) = vestibule_github.parse_token_response(json)
  credentials.scopes(creds) |> expect.to_equal([])
}

pub fn parse_token_response_error_test() {
  let json =
    "{\"error\":\"bad_verification_code\",\"error_description\":\"The code has expired\"}"
  let _ =
    vestibule_github.parse_token_response(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_user_response_full_test() {
  let json =
    "{\"id\":12345,\"login\":\"octocat\",\"name\":\"The Octocat\",\"avatar_url\":\"https://avatars.githubusercontent.com/u/12345\",\"bio\":\"A cat that codes\",\"html_url\":\"https://github.com/octocat\"}"
  let result = vestibule_github.parse_user_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> expect.to_equal("12345")
  user_info.name(info) |> expect.to_equal(Some("The Octocat"))
  user_info.nickname(info) |> expect.to_equal(Some("octocat"))
  user_info.image(info)
  |> expect.to_equal(Some("https://avatars.githubusercontent.com/u/12345"))
  user_info.description(info) |> expect.to_equal(Some("A cat that codes"))
  user_info.urls(info)
  |> expect.to_equal(
    dict.from_list([
      #("html_url", "https://github.com/octocat"),
    ]),
  )
}

pub fn parse_user_response_minimal_test() {
  let json = "{\"id\":99,\"login\":\"minimal\"}"
  let result = vestibule_github.parse_user_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> expect.to_equal("99")
  user_info.name(info) |> expect.to_equal(None)
  user_info.email(info) |> expect.to_equal(None)
}

pub fn parse_emails_response_test() {
  let json =
    "[{\"email\":\"octocat@github.com\",\"primary\":true,\"verified\":true},{\"email\":\"other@example.com\",\"primary\":false,\"verified\":true}]"
  vestibule_github.parse_primary_email(json)
  |> expect.to_equal(Some("octocat@github.com"))
}

pub fn parse_emails_no_verified_primary_test() {
  let json =
    "[{\"email\":\"unverified@example.com\",\"primary\":true,\"verified\":false}]"
  vestibule_github.parse_primary_email(json)
  |> expect.to_equal(None)
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() {
  let strat = vestibule_github.strategy()
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.ClientSecret("secret"),
    )
  let _ =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: config.authorize_options(),
      scopes: ["user:email"],
      state: "state",
    )
    |> expect.to_be_error()
  Nil
}

pub fn authorize_url_includes_extra_params_test() {
  let strat = vestibule_github.strategy()
  let conf =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("allow_signup", "false")])
  let assert Ok(url) =
    strategy.build_authorize_url(
      strat,
      config: conf,
      options: options,
      scopes: ["user:email"],
      state: "state",
    )
  { string.contains(url, "allow_signup=false") } |> expect.to_be_true()
}
