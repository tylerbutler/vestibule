import gleam/list
import startest/expect
import vestibule/config
import vestibule/error
import vestibule/registry
import vestibule/strategy.{type Strategy}

fn test_strategy(name: String) -> Strategy(e) {
  strategy.new(
    provider: name,
    default_scopes: [],
    authorize_url: fn(_config, _options, _scopes, _state) {
      Ok("https://example.com")
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.config(reason: "test"))
    },
    fetch_user: fn(_config, _exchange) { Error(error.config(reason: "test")) },
  )
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.config(reason: "test"))
  })
}

fn test_config() -> config.ClientConfig {
  config.new(
    client_id: "client_id",
    auth: config.ClientSecret("client_secret"),
    redirect_uri: "https://example.com/callback",
  )
}

pub fn new_registry_has_no_providers_test() -> Nil {
  let reg = registry.new()
  registry.providers(reg)
  |> expect.to_equal([])
}

pub fn register_and_get_provider_test() -> Nil {
  let strategy = test_strategy("github")
  let client_config = test_config()
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: strategy, config: client_config)
  let assert Ok(#(s, _c)) = registry.get(reg, provider: "github")
  strategy.provider(s) |> expect.to_equal("github")
}

pub fn get_unknown_provider_returns_error_test() -> Nil {
  let reg = registry.new()
  registry.get(reg, provider: "unknown")
  |> expect.to_be_error()
  |> expect.to_equal(Nil)
}

pub fn providers_returns_registered_names_test() -> Nil {
  let assert Ok(reg) =
    registry.new()
    |> registry.register(
      strategy: test_strategy("github"),
      config: test_config(),
    )
  let assert Ok(reg) =
    reg
    |> registry.register(
      strategy: test_strategy("microsoft"),
      config: test_config(),
    )
  let names = registry.providers(reg)
  names |> list.contains("github") |> expect.to_be_true()
  names |> list.contains("microsoft") |> expect.to_be_true()
  names |> list.length |> expect.to_equal(2)
}

pub fn register_duplicate_provider_is_rejected_test() -> Nil {
  let assert Ok(reg) =
    registry.new()
    |> registry.register(
      strategy: test_strategy("github"),
      config: test_config(),
    )

  reg
  |> registry.register(strategy: test_strategy("github"), config: test_config())
  |> expect.to_be_error()
  |> expect.to_equal(registry.DuplicateProvider("github"))
}

pub fn register_duplicate_does_not_replace_trusted_entry_test() -> Nil {
  let trusted_cfg =
    config.new(
      client_id: "trusted_id",
      auth: config.ClientSecret("trusted_secret"),
      redirect_uri: "https://example.com/callback",
    )
  let attacker_cfg =
    config.new(
      client_id: "attacker_id",
      auth: config.ClientSecret("attacker_secret"),
      redirect_uri: "https://evil.example/callback",
    )

  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: test_strategy("github"), config: trusted_cfg)

  // A second registration under the same name must not overwrite the trusted
  // entry.
  let _ =
    reg
    |> registry.register(
      strategy: test_strategy("github"),
      config: attacker_cfg,
    )

  let assert Ok(#(_s, c)) = registry.get(reg, provider: "github")
  config.client_id(c) |> expect.to_equal("trusted_id")
}

pub fn register_or_replace_overwrites_existing_test() -> Nil {
  let first_cfg =
    config.new(
      client_id: "first_id",
      auth: config.ClientSecret("first_secret"),
      redirect_uri: "https://example.com/callback",
    )
  let second_cfg =
    config.new(
      client_id: "second_id",
      auth: config.ClientSecret("second_secret"),
      redirect_uri: "https://example.com/callback",
    )

  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: test_strategy("github"), config: first_cfg)
  let reg =
    reg
    |> registry.register_or_replace(
      strategy: test_strategy("github"),
      config: second_cfg,
    )

  let assert Ok(#(_s, c)) = registry.get(reg, provider: "github")
  config.client_id(c) |> expect.to_equal("second_id")
  registry.providers(reg) |> list.length |> expect.to_equal(1)
}
