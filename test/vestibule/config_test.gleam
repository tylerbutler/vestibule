import gleam/dict
import gleam/result
import gleam/string
import vestibule/config
import vestibule/error
import vestibule/registry
import vestibule/strategy

const client_secret = "CLIENT-SECRET-7f3a"

const client_assertion = "CLIENT-ASSERTION-9b21"

pub fn try_new_accepts_secure_and_local_demo_redirects_test() -> Nil {
  assert config.try_new(
      client_id: "id",
      redirect_uri: "https://example.com/callback",
      auth: config.public_client(),
    )
    |> result.is_ok()
  assert config.try_new(
      client_id: "id",
      redirect_uri: "http://localhost:8000/callback",
      auth: config.public_client(),
    )
    |> result.is_ok()
  assert config.try_new(
      client_id: "id",
      redirect_uri: "http://127.0.0.1:8000/callback",
      auth: config.public_client(),
    )
    |> result.is_ok()
}

pub fn try_new_rejects_empty_client_id_test() -> Nil {
  let assert Error([validation_error]) =
    config.try_new(
      client_id: " ",
      redirect_uri: "https://example.com/callback",
      auth: config.public_client(),
    )
  assert config.validation_error_field(validation_error) == "client_id"
  assert config.validation_error_reason(validation_error) == "must not be empty"
}

pub fn try_new_rejects_malformed_redirect_uri_test() -> Nil {
  let assert Error([validation_error]) =
    config.try_new(
      client_id: "id",
      redirect_uri: "https://[invalid",
      auth: config.public_client(),
    )
  assert config.validation_error_field(validation_error) == "redirect_uri"
  assert config.validation_error_reason(validation_error)
    == "must be a valid URL"
}

pub fn try_new_rejects_insecure_redirect_uri_test() -> Nil {
  let assert Error([validation_error]) =
    config.try_new(
      client_id: "id",
      redirect_uri: "http://example.com/callback",
      auth: config.public_client(),
    )
  assert config.validation_error_field(validation_error) == "redirect_uri"
  assert string.contains(
    config.validation_error_reason(validation_error),
    "must use HTTPS",
  )
}

pub fn try_new_rejects_redirect_uri_fragment_test() -> Nil {
  let assert Error([validation_error]) =
    config.try_new(
      client_id: "id",
      redirect_uri: "https://example.com/callback#fragment",
      auth: config.public_client(),
    )
  assert config.validation_error_field(validation_error) == "redirect_uri"
  assert config.validation_error_reason(validation_error)
    == "must not include a fragment"
}

pub fn try_new_rejects_missing_credentials_test() -> Nil {
  let assert Error([secret_error]) =
    config.try_new(
      client_id: "id",
      redirect_uri: "https://example.com/callback",
      auth: config.client_secret_auth(" "),
    )
  assert config.validation_error_field(secret_error) == "auth"
  assert config.validation_error_reason(secret_error)
    == "client secret must not be empty"

  let assert Error([assertion_error]) =
    config.try_new(
      client_id: "id",
      redirect_uri: "https://example.com/callback",
      auth: config.client_assertion_auth(""),
    )
  assert config.validation_error_field(assertion_error) == "auth"
  assert config.validation_error_reason(assertion_error)
    == "client assertion must not be empty"
}

pub fn new_creates_client_config_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth(client_secret),
    )

  assert config.client_id(client_config) == "id"
  assert config.redirect_uri(client_config) == "http://localhost/callback"
  assert config.client_auth(client_config)
    |> config.client_auth_kind()
    == config.ClientSecretAuth
}

pub fn client_secret_returns_secret_for_secret_auth_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth(client_secret),
    )

  assert config.client_secret(client_config) == Ok(client_secret)
}

pub fn client_secret_rejects_assertion_auth_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_assertion_auth(client_assertion),
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
      auth: config.public_client(),
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

pub fn client_assertion_returns_assertion_for_assertion_auth_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_assertion_auth(client_assertion),
    )

  assert config.client_assertion(client_config) == Ok(client_assertion)
}

pub fn inspect_client_auth_and_config_do_not_leak_credentials_test() -> Nil {
  let client_auth = config.client_secret_auth(client_secret)
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: client_auth,
    )

  assert !string.contains(string.inspect(client_auth), client_secret)
  assert !string.contains(string.inspect(client_config), client_secret)
  assert !string.contains(erlang_term(client_auth), client_secret)
  assert !string.contains(erlang_term(client_config), client_secret)
}

pub fn assertion_inspection_does_not_leak_test() -> Nil {
  let client_auth = config.client_assertion_auth(client_assertion)

  assert !string.contains(string.inspect(client_auth), client_assertion)
  assert !string.contains(erlang_term(client_auth), client_assertion)
}

pub fn registry_inspection_does_not_leak_client_secret_test() -> Nil {
  let provider =
    strategy.new(
      provider: "test",
      default_scopes: [],
      authorize_url: fn(_config, _options, _scopes, _state) {
        Ok("https://example.com")
      },
      exchange_code: fn(_config, _code, _verifier) {
        Error(error.config(reason: "not used"))
      },
      fetch_user: fn(_config, _exchange) {
        Error(error.config(reason: "not used"))
      },
    )
  let client_config =
    config.new(
      client_id: "id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth(client_secret),
    )
  let assert Ok(provider_registry) =
    registry.new()
    |> registry.register(strategy: provider, config: client_config)

  assert !string.contains(string.inspect(provider_registry), client_secret)
  assert !string.contains(erlang_term(provider_registry), client_secret)
}

pub fn authorize_options_start_empty_test() -> Nil {
  let options = config.authorize_options()

  assert config.scopes(options) == []
  assert config.extra_parameters(options) == dict.new()
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
    |> config.with_extra_parameters([#("allow_signup", "false")])

  assert config.extra_parameters(options)
    == dict.from_list([#("allow_signup", "false")])
}

pub fn with_extra_parameters_merges_across_calls_test() -> Nil {
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_parameters([
      #("allow_signup", "false"),
      #("login", "a"),
    ])
  let assert Ok(options) =
    options
    |> config.with_extra_parameters([#("login", "b"), #("prompt", "consent")])

  assert config.extra_parameters(options)
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
    |> config.with_extra_parameters([#(parameter, "attacker-value")])

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

@external(erlang, "vestibule_secret_test_ffi", "format_term")
fn erlang_term(value: a) -> String
