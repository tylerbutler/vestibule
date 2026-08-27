import gleam/dict
import gleam/option
import gleam/string
import startest/expect
import vestibule/auth
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/registry
import vestibule/state_store
import vestibule/strategy
import vestibule/transport_flow
import vestibule/user_info

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

// === provider binding (mix-up attack) ===

fn succeeding_strategy(provider: String) -> strategy.Strategy(Nil) {
  strategy.new(
    provider: provider,
    default_scopes: [],
    authorize_url: fn(_client_config, _options, _scopes, state) {
      Ok("https://" <> provider <> ".example/authorize?state=" <> state)
    },
    exchange_code: fn(_client_config, _code, _code_verifier) {
      Ok(
        strategy.exchange_result(
          credentials.new(
            token: "token",
            refresh_token: option.None,
            token_type: "Bearer",
            expires_in: option.None,
            scopes: [],
          ),
        ),
      )
    },
    fetch_user: fn(_client_config, _exchange) {
      Ok(strategy.user_result(
        uid: provider <> "-user",
        info: user_info.new(),
        extra: dict.new(),
      ))
    },
  )
}

pub fn finish_callback_rejects_session_started_for_another_provider_test() -> Nil {
  // The attacker's provider ("alpha") sees the victim's state and redirects
  // the browser to the honest provider's ("beta") callback with an attacker
  // authorization code. The state matches, so only provider binding stops it.
  let client_config =
    config.new(
      client_id: "client_id",
      auth: config.ClientSecret("client_secret"),
      redirect_uri: "https://example.com/callback",
    )
  let assert Ok(reg) =
    registry.new()
    |> registry.register(
      strategy: succeeding_strategy("alpha"),
      config: client_config,
    )
  let assert Ok(reg) =
    registry.register(
      reg,
      strategy: succeeding_strategy("beta"),
      config: client_config,
    )
  let assert Ok(store) = state_store.try_init_named("transport_flow_mixup_test")

  let assert Ok(#(_url, session_id)) =
    transport_flow.start_authorization(
      reg,
      provider: "alpha",
      store: store,
      ttl_seconds: 600,
      options: config.authorize_options(),
    )
  let assert Ok(#(state, _verifier, _nonce)) =
    state_store.peek(store, session_id, provider: "alpha")
  let params = dict.from_list([#("state", state), #("code", "attacker-code")])

  let assert Ok(beta) = transport_flow.ensure_callback_provider(reg, "beta")
  transport_flow.finish_callback(
    beta,
    store: store,
    params: params,
    session_id: session_id,
  )
  |> expect.to_equal(Error(transport_flow.CallbackSessionUnavailable))

  // The rejected attempt must not have burned the legitimate in-flight login.
  let assert Ok(alpha) = transport_flow.ensure_callback_provider(reg, "alpha")
  let assert Ok(auth) =
    transport_flow.finish_callback(
      alpha,
      store: store,
      params: params,
      session_id: session_id,
    )
  auth.uid(auth) |> expect.to_equal("alpha-user")
}
