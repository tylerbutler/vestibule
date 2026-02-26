import gleam/list
import startest/expect
import vestibule/config
import vestibule/error
import vestibule/registry
import vestibule/strategy.{type Strategy, Strategy}

fn test_strategy(name: String) -> Strategy(e) {
  Strategy(
    provider: name,
    default_scopes: [],
    token_url: "https://example.com/oauth/token",
    authorize_url: fn(_config, _scopes, _state) { Ok("https://example.com") },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.ConfigError(reason: "test"))
    },
    fetch_user: fn(_creds) { Error(error.ConfigError(reason: "test")) },
  )
}

fn test_config() -> config.Config {
  let assert Ok(cfg) =
    config.new("client_id", "client_secret", "https://example.com/callback")
  cfg
}

pub fn new_registry_has_no_providers_test() {
  let reg = registry.new()
  registry.providers(reg)
  |> expect.to_equal([])
}

pub fn register_and_get_provider_test() {
  let strategy = test_strategy("github")
  let cfg = test_config()
  let reg =
    registry.new()
    |> registry.register(strategy, cfg)
  let assert Ok(#(s, _c)) = registry.get(reg, "github")
  s.provider |> expect.to_equal("github")
}

pub fn get_unknown_provider_returns_error_test() {
  let reg = registry.new()
  registry.get(reg, "unknown")
  |> expect.to_be_error()
  |> expect.to_equal(Nil)
}

pub fn providers_returns_registered_names_test() {
  let reg =
    registry.new()
    |> registry.register(test_strategy("github"), test_config())
    |> registry.register(test_strategy("microsoft"), test_config())
  let names = registry.providers(reg)
  names |> list.contains("github") |> expect.to_be_true()
  names |> list.contains("microsoft") |> expect.to_be_true()
  names |> list.length |> expect.to_equal(2)
}
