import gleam/dict.{type Dict}
import vestibule/config.{type Config}
import vestibule/strategy.{type Strategy}

/// A registry mapping provider names to Strategy + Config pairs.
///
/// The type parameter `e` must match across all registered strategies.
pub opaque type Registry(e) {
  Registry(providers: Dict(String, #(Strategy(e), Config)))
}

/// Create an empty registry.
pub fn new() -> Registry(e) {
  Registry(providers: dict.new())
}

/// Register a strategy with its config. Provider name is taken from the strategy.
pub fn register(
  registry: Registry(e),
  strategy: Strategy(e),
  config: Config,
) -> Registry(e) {
  Registry(
    providers: dict.insert(registry.providers, strategy.provider, #(
      strategy,
      config,
    )),
  )
}

/// Look up a provider by name.
pub fn get(
  registry: Registry(e),
  provider: String,
) -> Result(#(Strategy(e), Config), Nil) {
  dict.get(registry.providers, provider)
}

/// List all registered provider names.
pub fn providers(registry: Registry(e)) -> List(String) {
  dict.keys(registry.providers)
}
