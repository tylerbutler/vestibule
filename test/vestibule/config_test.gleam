import gleam/dict
import startest/expect
import vestibule/config
import vestibule/error

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
  let assert Ok(c) =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_extra_params([#("allow_signup", "false")])
  config.extra_params(c)
  |> expect.to_equal(dict.from_list([#("allow_signup", "false")]))
}

pub fn with_extra_params_rejects_reserved_authorization_params_test() {
  assert_reserved_param_rejected("response_type")
  assert_reserved_param_rejected("client_id")
  assert_reserved_param_rejected("redirect_uri")
  assert_reserved_param_rejected("scope")
  assert_reserved_param_rejected("state")
  assert_reserved_param_rejected("code_challenge")
  assert_reserved_param_rejected("code_challenge_method")
}

fn assert_reserved_param_rejected(param: String) {
  let result =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_extra_params([#(param, "attacker-value")])

  case result {
    Error(error.ConfigError(reason:)) ->
      reason
      |> expect.to_equal(
        "Reserved authorization parameter not allowed: " <> param,
      )
    _ -> panic as "expected ConfigError for reserved authorization parameter"
  }
}
