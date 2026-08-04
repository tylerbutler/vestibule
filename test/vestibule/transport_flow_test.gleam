import gleam/dict
import gleam/string
import startest/expect
import vestibule/config
import vestibule/error
import vestibule/registry
import vestibule/state_store
import vestibule/strategy
import vestibule/transport_flow

pub fn start_authorization_threads_custom_options_to_strategy_test() -> Nil {
  let strategy =
    strategy.new(
      provider: "custom",
      default_scopes: [],
      authorize_url: fn(_client_config, options, _scopes, _state) {
        let assert Ok(prompt) =
          options
          |> config.extra_params()
          |> dict.get("prompt")
        Ok("https://example.com/authorize?prompt=" <> prompt)
      },
      exchange_code: fn(_client_config, _code, _code_verifier) {
        Error(error.config(reason: "exchange not implemented"))
      },
      fetch_user: fn(_client_config, _exchange) {
        Error(error.config(reason: "fetch_user not implemented"))
      },
    )
  let client_config =
    config.new(
      client_id: "client_id",
      auth: config.ClientSecret("client_secret"),
      redirect_uri: "https://example.com/callback",
    )
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: strategy, config: client_config)
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "consent")])
  let assert Ok(store) =
    state_store.try_init_named("transport_flow_custom_options_test")

  let assert Ok(#(url, _session_id)) =
    transport_flow.start_authorization(
      reg,
      provider: "custom",
      store: store,
      ttl_seconds: 600,
      options: options,
    )

  url
  |> string.contains("prompt=consent")
  |> expect.to_be_true()
}
