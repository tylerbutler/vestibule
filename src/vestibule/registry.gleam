//// In-memory registry that maps provider names ("google", "apple", ...)
//// to `Strategy` values. Used by the middleware to dispatch incoming
//// authorize/callback requests to the right provider.

import gleam/dict.{type Dict}
import gleam/list
import vestibule/config.{type ClientConfig}
import vestibule/strategy.{type Strategy}

/// A registry mapping provider names to Strategy + ClientConfig pairs.
///
/// The type parameter `e` must match across all registered strategies.
pub opaque type Registry(e) {
  Registry(providers: Dict(String, #(Strategy(e), ClientConfig)))
}

/// Errors returned when registering a strategy.
pub type RegistryError {
  /// A strategy with this provider name is already registered. Use
  /// `register_or_replace` if you intend to overwrite the existing entry.
  DuplicateProvider(name: String)
}

/// An invalid provider registration found during startup validation.
pub type ValidationError {
  ValidationError(provider: String, field: String, reason: String)
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
  config config: ClientConfig,
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
  config config: ClientConfig,
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
) -> Result(#(Strategy(e), ClientConfig), Nil) {
  dict.get(registry.providers, provider)
}

/// List all registered provider names.
pub fn providers(registry: Registry(e)) -> List(String) {
  dict.keys(registry.providers)
}

/// Validate every registered provider without making network requests.
///
/// All errors are returned together so startup diagnostics can identify every
/// invalid provider, field, and reason in one pass.
pub fn validate(registry: Registry(e)) -> Result(Nil, List(ValidationError)) {
  let errors =
    registry.providers
    |> dict.to_list()
    |> list.flat_map(fn(entry) {
      let #(provider, #(provider_strategy, client_config)) = entry
      case strategy.validate_config(provider_strategy, client_config) {
        Ok(Nil) -> []
        Error(validation_errors) ->
          list.map(validation_errors, fn(validation_error) {
            ValidationError(
              provider: provider,
              field: config.validation_error_field(validation_error),
              reason: config.validation_error_reason(validation_error),
            )
          })
      }
    })
  case errors {
    [] -> Ok(Nil)
    errors -> Error(errors)
  }
}

/// Return the provider associated with a registry validation error.
pub fn validation_error_provider(validation_error: ValidationError) -> String {
  validation_error.provider
}

/// Return the field associated with a registry validation error.
pub fn validation_error_field(validation_error: ValidationError) -> String {
  validation_error.field
}

/// Return the actionable reason associated with a registry validation error.
pub fn validation_error_reason(validation_error: ValidationError) -> String {
  validation_error.reason
}
