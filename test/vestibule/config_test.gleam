import gleam/dict
import gleeunit/should
import vestibule/config

pub fn new_creates_config_with_empty_defaults_test() {
  let c = config.new("id", "secret", "http://localhost/callback")
  c.client_id |> should.equal("id")
  c.client_secret |> should.equal("secret")
  c.redirect_uri |> should.equal("http://localhost/callback")
  c.scopes |> should.equal([])
  c.extra_params |> should.equal(dict.new())
}

pub fn with_scopes_replaces_scopes_test() {
  let c =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_scopes(["user:email", "read:org"])
  c.scopes |> should.equal(["user:email", "read:org"])
}

pub fn with_extra_params_adds_params_test() {
  let c =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_extra_params([#("allow_signup", "false")])
  c.extra_params |> should.equal(dict.from_list([#("allow_signup", "false")]))
}
