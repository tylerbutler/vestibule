import gleam/dict
import gleam/string
import vestibule/config
import vestibule/error

pub fn new_creates_client_config_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )

  assert config.client_id(client_config) == "id"
  assert config.redirect_uri(client_config) == "http://localhost/callback"
  assert config.client_auth(client_config) == config.ClientSecret("secret")
}

pub fn client_secret_returns_secret_for_secret_auth_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientSecret("secret"),
    )

  assert config.client_secret(client_config) == Ok("secret")
}

pub fn client_secret_rejects_assertion_auth_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.ClientAssertion("assertion"),
    )

  case config.client_secret(client_config) {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert error.message(auth_error)
        == "Invalid configuration: Client authentication does not provide a client_secret"
    }
    Ok(_) -> panic as "expected ConfigError for client assertion"
  }
}

pub fn client_secret_rejects_public_client_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.PublicClient,
    )

  case config.client_secret(client_config) {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert error.message(auth_error)
        == "Invalid configuration: Client authentication does not provide a client_secret"
    }
    Ok(_) -> panic as "expected ConfigError for public client"
  }
}

pub fn authorize_options_start_empty_test() -> Nil {
  let options = config.authorize_options()

  assert config.scopes(options) == []
  assert config.extra_params(options) == dict.new()
}

pub fn with_scopes_replaces_authorize_option_scopes_test() -> Nil {
  let options =
    config.authorize_options()
    |> config.with_scopes(["user:email", "read:org"])
    |> config.with_scopes(["profile"])

  assert config.scopes(options) == ["profile"]
}

pub fn with_extra_parameters_adds_authorize_option_parameters_test() -> Nil {
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("allow_signup", "false")])

  assert config.extra_params(options)
    == dict.from_list([#("allow_signup", "false")])
}

pub fn with_extra_parameters_merges_across_calls_test() -> Nil {
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([
      #("allow_signup", "false"),
      #("login", "a"),
    ])
  let assert Ok(options) =
    options
    |> config.with_extra_params([#("login", "b"), #("prompt", "consent")])

  assert config.extra_params(options)
    == dict.from_list([
      #("allow_signup", "false"),
      #("login", "b"),
      #("prompt", "consent"),
    ])
}

pub fn with_extra_parameters_rejects_reserved_authorization_parameters_test() -> Nil {
  assert_reserved_parameter_rejected("response_type")
  assert_reserved_parameter_rejected("client_id")
  assert_reserved_parameter_rejected("redirect_uri")
  assert_reserved_parameter_rejected("scope")
  assert_reserved_parameter_rejected("state")
  assert_reserved_parameter_rejected("code_challenge")
  assert_reserved_parameter_rejected("code_challenge_method")
  assert_reserved_parameter_rejected("nonce")
  assert_reserved_parameter_rejected("response_mode")
}

fn assert_reserved_parameter_rejected(parameter: String) -> Nil {
  let result =
    config.authorize_options()
    |> config.with_extra_params([#(parameter, "attacker-value")])

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert string.contains(
        error.message(auth_error),
        "Reserved authorization parameter not allowed: " <> parameter,
      )
    }
    Ok(_) -> panic as "expected ConfigError for reserved authorization parameter"
  }
}
