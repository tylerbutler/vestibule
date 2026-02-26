import gleam/dict
import startest/expect
import vestibule/config

pub fn new_creates_config_with_empty_defaults_test() {
  let assert Ok(c) = config.new("id", "secret", "http://localhost/callback")
  c.client_id |> expect.to_equal("id")
  c.client_secret |> expect.to_equal("secret")
  c.redirect_uri |> expect.to_equal("http://localhost/callback")
  c.scopes |> expect.to_equal([])
  c.extra_params |> expect.to_equal(dict.new())
}

pub fn with_scopes_replaces_scopes_test() {
  let assert Ok(c) = config.new("id", "secret", "http://localhost/callback")
  let c = c |> config.with_scopes(["user:email", "read:org"])
  c.scopes |> expect.to_equal(["user:email", "read:org"])
}

pub fn with_extra_params_adds_params_test() {
  let assert Ok(c) = config.new("id", "secret", "http://localhost/callback")
  let c = c |> config.with_extra_params([#("allow_signup", "false")])
  c.extra_params
  |> expect.to_equal(dict.from_list([#("allow_signup", "false")]))
}

pub fn new_accepts_https_redirect_uri_test() {
  let result = config.new("id", "secret", "https://example.com/callback")
  let _ = result |> expect.to_be_ok()
  Nil
}

pub fn new_accepts_http_localhost_redirect_uri_test() {
  let result = config.new("id", "secret", "http://localhost/callback")
  let _ = result |> expect.to_be_ok()
  Nil
}

pub fn new_accepts_http_127001_redirect_uri_test() {
  let result = config.new("id", "secret", "http://127.0.0.1:8080/callback")
  let _ = result |> expect.to_be_ok()
  Nil
}

pub fn new_rejects_http_redirect_uri_test() {
  let result = config.new("id", "secret", "http://example.com/callback")
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn new_rejects_ftp_redirect_uri_test() {
  let result = config.new("id", "secret", "ftp://example.com/callback")
  let _ = result |> expect.to_be_error()
  Nil
}
