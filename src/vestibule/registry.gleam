import gleam/dict.{type Dict}
import vestibule/config.{type Config}
import vestibule/strategy.{type Strategy}

/// A registry mapping provider names to Strategy + Config pairs.
pub opaque type Registry {
  Registry(providers: Dict(String, #(Strategy, Config)))
}

/// Create an empty registry.
pub fn new() -> Registry {
  Registry(providers: dict.new())
}

/// Register a strategy with its config. Provider name is taken from the strategy.
pub fn register(
  registry: Registry,
  strategy: Strategy,
  config: Config,
) -> Registry {
  Registry(
    providers: dict.insert(registry.providers, strategy.provider, #(
      strategy,
      config,
    )),
  )
}

/// Look up a provider by name.
pub fn get(
  registry: Registry,
  provider: String,
) -> Result(#(Strategy, Config), Nil) {
  dict.get(registry.providers, provider)
}

/// List all registered provider names.
pub fn providers(registry: Registry) -> List(String) {
  dict.keys(registry.providers)
}
