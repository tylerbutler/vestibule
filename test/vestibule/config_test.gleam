import gleam/dict
import gleam/string
import startest/expect
import vestibule/config
import vestibule/error

pub fn new_creates_client_config_test() -> Nil {
  let c =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )

  config.client_id(c) |> expect.to_equal("id")
  config.redirect_uri(c) |> expect.to_equal("http://localhost/callback")
  config.client_auth(c) |> expect.to_equal(config.ClientSecret("secret"))
}

pub fn client_secret_returns_secret_for_secret_auth_test() -> Nil {
  let c =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )

  config.client_secret(c) |> expect.to_equal(Ok("secret"))
}

pub fn client_secret_rejects_assertion_auth_test() -> Nil {
  let c =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientAssertion("assertion"),
    )

  case config.client_secret(c) {
    Error(err) -> {
      error.kind(err) |> expect.to_equal(error.ConfigKind)
      error.message(err)
      |> expect.to_equal(
        "Invalid configuration: Client authentication does not provide a client_secret",
      )
    }
    _ -> panic as "expected ConfigError for client assertion"
  }
}

pub fn client_secret_rejects_public_client_test() -> Nil {
  let c =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.PublicClient,
    )

  case config.client_secret(c) {
    Error(err) -> {
      error.kind(err) |> expect.to_equal(error.ConfigKind)
      error.message(err)
      |> expect.to_equal(
        "Invalid configuration: Client authentication does not provide a client_secret",
      )
    }
    _ -> panic as "expected ConfigError for public client"
  }
}

pub fn authorize_options_start_empty_test() -> Nil {
  let options = config.authorize_options()

  config.scopes(options) |> expect.to_equal([])
  config.extra_params(options) |> expect.to_equal(dict.new())
}

pub fn with_scopes_replaces_authorize_option_scopes_test() -> Nil {
  let options =
    config.authorize_options()
    |> config.with_scopes(["user:email", "read:org"])
    |> config.with_scopes(["profile"])

  config.scopes(options) |> expect.to_equal(["profile"])
}

pub fn with_extra_params_adds_authorize_option_params_test() -> Nil {
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("allow_signup", "false")])

  config.extra_params(options)
  |> expect.to_equal(dict.from_list([#("allow_signup", "false")]))
}

pub fn with_extra_params_merges_across_calls_test() -> Nil {
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("allow_signup", "false"), #("login", "a")])
  let assert Ok(options) =
    options
    |> config.with_extra_params([#("login", "b"), #("prompt", "consent")])

  config.extra_params(options)
  |> expect.to_equal(
    dict.from_list([
      #("allow_signup", "false"),
      #("login", "b"),
      #("prompt", "consent"),
    ]),
  )
}

pub fn with_extra_params_rejects_reserved_authorization_params_test() -> Nil {
  assert_reserved_param_rejected("response_type")
  assert_reserved_param_rejected("client_id")
  assert_reserved_param_rejected("redirect_uri")
  assert_reserved_param_rejected("scope")
  assert_reserved_param_rejected("state")
  assert_reserved_param_rejected("code_challenge")
  assert_reserved_param_rejected("code_challenge_method")
  assert_reserved_param_rejected("nonce")
  assert_reserved_param_rejected("response_mode")
}

fn assert_reserved_param_rejected(param: String) -> Nil {
  let result =
    config.authorize_options()
    |> config.with_extra_params([#(param, "attacker-value")])

  case result {
    Error(err) -> {
      error.kind(err) |> expect.to_equal(error.ConfigKind)
      error.message(err)
      |> string.contains(
        "Reserved authorization parameter not allowed: " <> param,
      )
      |> expect.to_be_true()
    }
    _ -> panic as "expected ConfigError for reserved authorization parameter"
  }
}
