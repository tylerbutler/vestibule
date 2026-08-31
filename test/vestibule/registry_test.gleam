import gleam/list
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
  let provider_registry = registry.new()
  assert registry.providers(provider_registry) == []
}

pub fn register_and_get_provider_test() -> Nil {
  let strategy = test_strategy("github")
  let client_config = test_config()
  let assert Ok(provider_registry) =
    registry.new()
    |> registry.register(strategy: strategy, config: client_config)
  let assert Ok(#(provider_strategy, _client_config)) =
    registry.get(provider_registry, provider: "github")
  assert strategy.provider(provider_strategy) == "github"
}

pub fn get_unknown_provider_returns_error_test() -> Nil {
  let provider_registry = registry.new()
  assert registry.get(provider_registry, provider: "unknown") == Error(Nil)
}

pub fn providers_returns_registered_names_test() -> Nil {
  let assert Ok(provider_registry) =
    registry.new()
    |> registry.register(
      strategy: test_strategy("github"),
      config: test_config(),
    )
  let assert Ok(provider_registry) =
    provider_registry
    |> registry.register(
      strategy: test_strategy("microsoft"),
      config: test_config(),
    )
  let names = registry.providers(provider_registry)
  assert list.contains(names, "github")
  assert list.contains(names, "microsoft")
  assert list.length(names) == 2
}

pub fn register_duplicate_provider_is_rejected_test() -> Nil {
  let assert Ok(provider_registry) =
    registry.new()
    |> registry.register(
      strategy: test_strategy("github"),
      config: test_config(),
    )

  assert registry.register(
      provider_registry,
      strategy: test_strategy("github"),
      config: test_config(),
    )
    == Error(registry.DuplicateProvider("github"))
}

pub fn register_duplicate_does_not_replace_trusted_entry_test() -> Nil {
  let trusted_config =
    config.new(
      client_id: "trusted_id",
      auth: config.ClientSecret("trusted_secret"),
      redirect_uri: "https://example.com/callback",
    )
  let attacker_config =
    config.new(
      client_id: "attacker_id",
      auth: config.ClientSecret("attacker_secret"),
      redirect_uri: "https://evil.example/callback",
    )

  let assert Ok(provider_registry) =
    registry.new()
    |> registry.register(
      strategy: test_strategy("github"),
      config: trusted_config,
    )

  // A second registration under the same name must not overwrite the trusted
  // entry.
  let _ =
    provider_registry
    |> registry.register(
      strategy: test_strategy("github"),
      config: attacker_config,
    )

  let assert Ok(#(_provider_strategy, client_config)) =
    registry.get(provider_registry, provider: "github")
  assert config.client_id(client_config) == "trusted_id"
}

pub fn register_or_replace_overwrites_existing_test() -> Nil {
  let first_config =
    config.new(
      client_id: "first_id",
      auth: config.ClientSecret("first_secret"),
      redirect_uri: "https://example.com/callback",
    )
  let second_config =
    config.new(
      client_id: "second_id",
      auth: config.ClientSecret("second_secret"),
      redirect_uri: "https://example.com/callback",
    )

  let assert Ok(provider_registry) =
    registry.new()
    |> registry.register(
      strategy: test_strategy("github"),
      config: first_config,
    )
  let provider_registry =
    provider_registry
    |> registry.register_or_replace(
      strategy: test_strategy("github"),
      config: second_config,
    )

  let assert Ok(#(_provider_strategy, client_config)) =
    registry.get(provider_registry, provider: "github")
  assert config.client_id(client_config) == "second_id"
  assert list.length(registry.providers(provider_registry)) == 1
}
