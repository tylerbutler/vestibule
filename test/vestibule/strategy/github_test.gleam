import gleam/option.{None, Some}
import gleeunit/should
import vestibule/credentials.{Credentials}
import vestibule/strategy/github

pub fn parse_token_response_success_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email\"}"
  github.parse_token_response(json)
  |> should.be_ok()
  |> should.equal(Credentials(
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
  creds.scopes |> should.equal(["user:email", "read:org"])
}

pub fn parse_token_response_error_test() {
  let json =
    "{\"error\":\"bad_verification_code\",\"error_description\":\"The code has expired\"}"
  github.parse_token_response(json)
  |> should.be_error()
}
