//// Transport-independent OAuth request and callback flow helpers.

import gleam/dict.{type Dict}
import gleam/result

import vestibule
import vestibule/auth.{type Auth}
import vestibule/authorization_request
import vestibule/config.{type Config}
import vestibule/error.{type AuthError}
import vestibule/registry.{type Registry}
import vestibule/state
import vestibule/state_store.{type StateStore, type StateStoreError}
import vestibule/strategy.{type Strategy}

/// Errors that can occur while starting an authorization flow.
pub type RequestFlowError(e) {
  UnknownProvider(provider: String)
  AuthFailed(AuthError(e))
  StoreFailed(StateStoreError)
}

/// Errors that can occur while finishing a callback flow.
pub type CallbackFlowError(e) {
  CallbackUnknownProvider(provider: String)
  CallbackSessionUnavailable
  CallbackAuthFailed(AuthError(e))
}

/// Generate an authorization URL and store the expected state/verifier.
pub fn start_authorization(
  provider_registry: Registry(e),
  provider provider: String,
  store store: StateStore,
  ttl_seconds ttl_seconds: Int,
) -> Result(#(String, String), RequestFlowError(e)) {
  use #(strategy, config) <- result.try(
    registry.get(provider_registry, provider: provider)
    |> result.map_error(fn(_) { UnknownProvider(provider) }),
  )
  use auth_request <- result.try(
    vestibule.create_authorization_request(strategy, cfg: config)
    |> result.map_error(AuthFailed),
  )
  use session_id <- result.try(
    state_store.try_store_with_ttl(
      store,
      state: authorization_request.state(auth_request),
      code_verifier: authorization_request.code_verifier(auth_request),
      ttl_seconds: ttl_seconds,
    )
    |> result.map_error(StoreFailed),
  )

  Ok(#(authorization_request.url(auth_request), session_id))
}

/// Look up the provider's strategy and config without touching cookies,
/// request bodies, or the state store.
///
/// Transports call this first so that an unknown provider returns
/// `CallbackUnknownProvider` before any cookie or request-body parsing
/// happens. The returned strategy/config pair is threaded into
/// `finish_callback` to avoid a second registry lookup.
pub fn ensure_callback_provider(
  provider_registry: Registry(e),
  provider: String,
) -> Result(#(Strategy(e), Config), CallbackFlowError(e)) {
  registry.get(provider_registry, provider: provider)
  |> result.map_error(fn(_) { CallbackUnknownProvider(provider) })
}

/// Validate callback state, consume the stored verifier, and fetch auth data.
///
/// Pass the strategy/config pair returned by `ensure_callback_provider` to
/// reuse the provider lookup instead of querying the registry again.
pub fn finish_callback(
  strategy_config: #(Strategy(e), Config),
  store store: StateStore,
  params params: Dict(String, String),
  session_id session_id: String,
) -> Result(Auth, CallbackFlowError(e)) {
  let #(strategy, config) = strategy_config

  use received_state <- result.try(
    dict.get(params, "state")
    |> result.replace_error(
      CallbackAuthFailed(error.MissingCallbackParam("state")),
    ),
  )

  use #(expected_state, _code_verifier) <- result.try(
    state_store.peek(store, session_id)
    |> result.map_error(fn(_) { CallbackSessionUnavailable }),
  )

  use _ <- result.try(
    state.validate(received: received_state, expected: expected_state)
    |> result.map_error(CallbackAuthFailed),
  )

  use #(_, code_verifier) <- result.try(
    state_store.consume(store, session_id)
    |> result.map_error(fn(_) { CallbackSessionUnavailable }),
  )

  vestibule.handle_callback(
    strategy,
    cfg: config,
    callback_params: params,
    expected_state: expected_state,
    code_verifier: code_verifier,
  )
  |> result.map_error(CallbackAuthFailed)
}
