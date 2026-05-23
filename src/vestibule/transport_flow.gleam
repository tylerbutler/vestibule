//// Transport-independent OAuth request and callback flow helpers.

import gleam/dict.{type Dict}
import gleam/result

import vestibule
import vestibule/auth.{type Auth}
import vestibule/authorization_request
import vestibule/error.{type AuthError}
import vestibule/registry.{type Registry}
import vestibule/state
import vestibule/state_store.{type StateStore, type StateStoreError}

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
  provider: String,
  store: StateStore,
  ttl_seconds: Int,
) -> Result(#(String, String), RequestFlowError(e)) {
  use #(strategy, config) <- result.try(
    registry.get(provider_registry, provider)
    |> result.map_error(fn(_) { UnknownProvider(provider) }),
  )
  use auth_request <- result.try(
    vestibule.authorize_url(strategy, config)
    |> result.map_error(AuthFailed),
  )
  use session_id <- result.try(
    state_store.try_store_with_ttl(
      store,
      authorization_request.state(auth_request),
      authorization_request.code_verifier(auth_request),
      ttl_seconds,
    )
    |> result.map_error(StoreFailed),
  )

  Ok(#(authorization_request.url(auth_request), session_id))
}

/// Validate callback state, consume the stored verifier, and fetch auth data.
///
/// Transports that need to preserve provider-lookup precedence before parsing
/// cookies or request bodies can call this helper first.
pub fn ensure_callback_provider(
  provider_registry: Registry(e),
  provider: String,
) -> Result(Nil, CallbackFlowError(e)) {
  registry.get(provider_registry, provider)
  |> result.map(fn(_) { Nil })
  |> result.map_error(fn(_) { CallbackUnknownProvider(provider) })
}

/// Validate callback state, consume the stored verifier, and fetch auth data.
pub fn finish_callback(
  provider_registry: Registry(e),
  provider: String,
  store: StateStore,
  params: Dict(String, String),
  session_id: String,
) -> Result(Auth, CallbackFlowError(e)) {
  use #(strategy, config) <- result.try(
    registry.get(provider_registry, provider)
    |> result.map_error(fn(_) { CallbackUnknownProvider(provider) }),
  )

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
    state.validate(received_state, expected_state)
    |> result.map_error(CallbackAuthFailed),
  )

  use #(_, code_verifier) <- result.try(
    state_store.consume(store, session_id)
    |> result.map_error(fn(_) { CallbackSessionUnavailable }),
  )

  vestibule.handle_callback(
    strategy,
    config,
    params,
    expected_state,
    code_verifier,
  )
  |> result.map_error(CallbackAuthFailed)
}
