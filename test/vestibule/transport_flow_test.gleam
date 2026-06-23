import gleam/dict
import gleam/string
import startest/expect
import vestibule/config
import vestibule/registry
import vestibule/state_store
import vestibule/strategy
import vestibule/transport_flow

pub fn start_authorization_threads_custom_options_to_strategy_test() {
  let strat =
    strategy.new(provider: "custom", default_scopes: [])
    |> strategy.with_authorize_url(fn(_cfg, options, _scopes, _state) {
      let assert Ok(prompt) =
        options
        |> config.extra_params()
        |> dict.get("prompt")
      Ok("https://example.com/authorize?prompt=" <> prompt)
    })
  let cfg =
    config.new(
      client_id: "client_id",
      auth: config.ClientSecret("client_secret"),
      redirect_uri: "https://example.com/callback",
    )
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: strat, config: cfg)
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "consent")])
  let store = state_store.init_named("transport_flow_custom_options_test")

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
