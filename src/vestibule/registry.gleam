//// In-memory registry that maps provider names ("google", "apple", ...)
//// to `Strategy` values. Used by the middleware to dispatch incoming
//// authorize/callback requests to the right provider.

import gleam/dict.{type Dict}
import vestibule/config.{type Config}
import vestibule/strategy.{type Strategy}

/// A registry mapping provider names to Strategy + Config pairs.
///
/// The type parameter `e` must match across all registered strategies.
pub opaque type Registry(e) {
  Registry(providers: Dict(String, #(Strategy(e), Config)))
}

/// Errors returned when registering a strategy.
pub type RegistryError {
  /// A strategy with this provider name is already registered. Use
  /// `register_or_replace` if you intend to overwrite the existing entry.
  DuplicateProvider(name: String)
}

/// Create an empty registry.
pub fn new() -> Registry(e) {
  Registry(providers: dict.new())
}

/// Register a strategy with its config. Provider name is taken from the
/// strategy.
///
/// Registration is rejected with `Error(DuplicateProvider(name))` if a
/// strategy is already registered under the same provider name. This prevents
/// a later (possibly untrusted) registration from silently replacing a trusted
/// provider — which would otherwise enable provider impersonation when account
/// identity is keyed by `provider + uid`.
///
/// When accepting provider names from dynamic or partly untrusted
/// configuration, namespace custom names (for example `"custom:acme"`) so they
/// cannot collide with built-in trusted providers. Trusted callers that
/// genuinely need to overwrite an entry should use `register_or_replace`.
pub fn register(
  registry: Registry(e),
  strategy strategy: Strategy(e),
  config config: Config,
) -> Result(Registry(e), RegistryError) {
  let name = strategy.provider(strategy)
  case dict.has_key(registry.providers, name) {
    True -> Error(DuplicateProvider(name))
    False ->
      Ok(
        Registry(
          providers: dict.insert(registry.providers, name, #(strategy, config)),
        ),
      )
  }
}

/// Register a strategy with its config, replacing any existing strategy
/// registered under the same provider name.
///
/// This is the explicit, trusted-caller counterpart to `register`. Only use it
/// when the provider name and strategy are fully trusted, since it silently
/// overwrites a previously registered provider.
pub fn register_or_replace(
  registry: Registry(e),
  strategy strategy: Strategy(e),
  config config: Config,
) -> Registry(e) {
  Registry(
    providers: dict.insert(registry.providers, strategy.provider(strategy), #(
      strategy,
      config,
    )),
  )
}

/// Look up a provider by name.
pub fn get(
  registry: Registry(e),
  provider provider: String,
) -> Result(#(Strategy(e), Config), Nil) {
  dict.get(registry.providers, provider)
}

/// List all registered provider names.
pub fn providers(registry: Registry(e)) -> List(String) {
  dict.keys(registry.providers)
}
