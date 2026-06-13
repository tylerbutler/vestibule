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
    authorize_url: fn(_config, _scopes, _state) { Ok("https://example.com") },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.ConfigError(reason: "test"))
    },
    refresh_token: fn(_config, _refresh_token) {
      Error(error.ConfigError(reason: "test"))
    },
    fetch_user: fn(_config, _exchange) {
      Error(error.ConfigError(reason: "test"))
    },
  )
}

fn test_config() -> config.Config {
  config.new("client_id", "client_secret", "https://example.com/callback")
}

pub fn new_registry_has_no_providers_test() {
  let reg = registry.new()
  registry.providers(reg)
  |> expect.to_equal([])
}

pub fn register_and_get_provider_test() {
  let strategy = test_strategy("github")
  let cfg = test_config()
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy, cfg)
  let assert Ok(#(s, _c)) = registry.get(reg, "github")
  strategy.provider(s) |> expect.to_equal("github")
}

pub fn get_unknown_provider_returns_error_test() {
  let reg = registry.new()
  registry.get(reg, "unknown")
  |> expect.to_be_error()
  |> expect.to_equal(Nil)
}

pub fn providers_returns_registered_names_test() {
  let assert Ok(reg) =
    registry.new()
    |> registry.register(test_strategy("github"), test_config())
  let assert Ok(reg) =
    reg
    |> registry.register(test_strategy("microsoft"), test_config())
  let names = registry.providers(reg)
  names |> list.contains("github") |> expect.to_be_true()
  names |> list.contains("microsoft") |> expect.to_be_true()
  names |> list.length |> expect.to_equal(2)
}

pub fn register_duplicate_provider_is_rejected_test() {
  let assert Ok(reg) =
    registry.new()
    |> registry.register(test_strategy("github"), test_config())

  reg
  |> registry.register(test_strategy("github"), test_config())
  |> expect.to_be_error()
  |> expect.to_equal(registry.DuplicateProvider("github"))
}

pub fn register_duplicate_does_not_replace_trusted_entry_test() {
  let trusted_cfg =
    config.new("trusted_id", "trusted_secret", "https://example.com/callback")
  let attacker_cfg =
    config.new(
      "attacker_id",
      "attacker_secret",
      "https://evil.example/callback",
    )

  let assert Ok(reg) =
    registry.new()
    |> registry.register(test_strategy("github"), trusted_cfg)

  // A second registration under the same name must not overwrite the trusted
  // entry.
  let _ =
    reg
    |> registry.register(test_strategy("github"), attacker_cfg)

  let assert Ok(#(_s, c)) = registry.get(reg, "github")
  config.client_id(c) |> expect.to_equal("trusted_id")
}

pub fn register_or_replace_overwrites_existing_test() {
  let first_cfg =
    config.new("first_id", "first_secret", "https://example.com/callback")
  let second_cfg =
    config.new("second_id", "second_secret", "https://example.com/callback")

  let assert Ok(reg) =
    registry.new()
    |> registry.register(test_strategy("github"), first_cfg)
  let reg =
    reg
    |> registry.register_or_replace(test_strategy("github"), second_cfg)

  let assert Ok(#(_s, c)) = registry.get(reg, "github")
  config.client_id(c) |> expect.to_equal("second_id")
  registry.providers(reg) |> list.length |> expect.to_equal(1)
}
