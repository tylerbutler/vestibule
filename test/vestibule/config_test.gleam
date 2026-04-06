import gleam/dict
import startest/expect
import vestibule/config

pub fn new_creates_config_with_empty_defaults_test() {
  let c = config.new("id", "secret", "http://localhost/callback")
  config.client_id(c) |> expect.to_equal("id")
  config.client_secret(c) |> expect.to_equal("secret")
  config.redirect_uri(c) |> expect.to_equal("http://localhost/callback")
  config.scopes(c) |> expect.to_equal([])
  config.extra_params(c) |> expect.to_equal(dict.new())
}

pub fn with_scopes_replaces_scopes_test() {
  let c =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_scopes(["user:email", "read:org"])
  config.scopes(c) |> expect.to_equal(["user:email", "read:org"])
}

pub fn with_extra_params_adds_params_test() {
  let c =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_extra_params([#("allow_signup", "false")])
  config.extra_params(c)
  |> expect.to_equal(dict.from_list([#("allow_signup", "false")]))
}
