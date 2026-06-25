//// Transport-independent OAuth request and callback flow helpers.

import gleam/dict.{type Dict}
import gleam/option
import gleam/result

import vestibule
import vestibule/auth.{type Auth}
import vestibule/authorization_request
import vestibule/config.{type AuthorizeOptions, type ClientConfig}
import vestibule/error.{type AuthError}
import vestibule/logger
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
  options options: AuthorizeOptions,
) -> Result(#(String, String), RequestFlowError(e)) {
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.transport.request.start",
      phase: "request",
      outcome: "start",
      provider: option.Some(provider),
      fields: [],
    ),
  )

  let started = {
    use #(strategy, config) <- result.try(
      registry.get(provider_registry, provider: provider)
      |> result.map_error(fn(_) { UnknownProvider(provider) }),
    )
    use auth_request <- result.try(
      vestibule.create_authorization_request(
        strategy,
        cfg: config,
        options: options,
      )
      |> result.map_error(AuthFailed),
    )
    use session_id <- result.try(
      state_store.try_store_with_ttl(
        store,
        state: authorization_request.state(auth_request),
        code_verifier: authorization_request.code_verifier(auth_request),
        nonce: authorization_request.nonce(auth_request),
        ttl_seconds: ttl_seconds,
      )
      |> result.map_error(StoreFailed),
    )

    Ok(#(authorization_request.url(auth_request), session_id))
  }

  case started {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Info,
          event: "vestibule.transport.request.success",
          phase: "request",
          outcome: "success",
          provider: option.Some(provider),
          fields: [],
        ),
      )
    Error(UnknownProvider(_)) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "unknown_provider")],
        ),
      )
    Error(AuthFailed(err)) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
    Error(StoreFailed(_)) ->
      logger.emit(
        logger.new(
          level: logger.Error,
          event: "vestibule.transport.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "state_store_failed")],
        ),
      )
  }

  started
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
) -> Result(#(Strategy(e), ClientConfig), CallbackFlowError(e)) {
  let lookup =
    registry.get(provider_registry, provider: provider)
    |> result.map_error(fn(_) { CallbackUnknownProvider(provider) })

  case lookup {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.transport.callback.provider_found",
          phase: "callback",
          outcome: "success",
          provider: option.Some(provider),
          fields: [],
        ),
      )
    Error(_) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.provider_missing",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "unknown_provider")],
        ),
      )
  }

  lookup
}

/// Validate callback state, consume the stored verifier, and fetch auth data.
///
/// Pass the strategy/config pair returned by `ensure_callback_provider` to
/// reuse the provider lookup instead of querying the registry again.
pub fn finish_callback(
  strategy_config: #(Strategy(e), ClientConfig),
  store store: StateStore,
  params params: Dict(String, String),
  session_id session_id: String,
) -> Result(Auth, CallbackFlowError(e)) {
  let #(strategy, config) = strategy_config
  let provider = strategy.provider(strategy)

  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.transport.callback.start",
      phase: "callback",
      outcome: "start",
      provider: option.Some(provider),
      fields: [],
    ),
  )

  let state_result =
    dict.get(params, "state")
    |> result.replace_error(
      CallbackAuthFailed(error.missing_callback_param("state")),
    )
  case state_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.transport.callback.state_received.success",
          phase: "callback",
          outcome: "success",
          provider: option.Some(provider),
          fields: [],
        ),
      )
    Error(_) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.state_received.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("error_category", "missing_callback_param"),
            logger.field("missing_param", "state"),
          ],
        ),
      )
  }
  use received_state <- result.try(state_result)

  let peek_result =
    state_store.peek(store, session_id)
    |> result.map_error(fn(_) { CallbackSessionUnavailable })
  case peek_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.transport.callback.state_peek.success",
          phase: "callback",
          outcome: "success",
          provider: option.Some(provider),
          fields: [],
        ),
      )
    Error(_) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.state_peek.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "session_unavailable")],
        ),
      )
  }
  use #(expected_state, _code_verifier, _nonce) <- result.try(peek_result)

  let validate_result =
    state.validate(received: received_state, expected: expected_state)
    |> result.map_error(CallbackAuthFailed)
  case validate_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.transport.callback.state_validate.success",
          phase: "callback",
          outcome: "success",
          provider: option.Some(provider),
          fields: [],
        ),
      )
    Error(_) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.state_validate.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "state_mismatch")],
        ),
      )
  }
  use _ <- result.try(validate_result)

  let consume_result =
    state_store.consume(store, session_id)
    |> result.map_error(fn(_) { CallbackSessionUnavailable })
  case consume_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.transport.callback.state_consume.success",
          phase: "callback",
          outcome: "success",
          provider: option.Some(provider),
          fields: [],
        ),
      )
    Error(_) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.state_consume.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "session_unavailable")],
        ),
      )
  }
  use #(_, code_verifier, expected_nonce) <- result.try(consume_result)

  let finished =
    vestibule.handle_callback(
      strategy,
      cfg: config,
      callback_params: params,
      expected_state: expected_state,
      code_verifier: code_verifier,
      expected_nonce: expected_nonce,
    )
    |> result.map_error(CallbackAuthFailed)

  case finished {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Info,
          event: "vestibule.transport.callback.success",
          phase: "callback",
          outcome: "success",
          provider: option.Some(provider),
          fields: [],
        ),
      )
    Error(CallbackAuthFailed(err)) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
    // Exhaustive-match guards: `handle_callback` only ever returns
    // `CallbackAuthFailed`; these arms are structurally required by the
    // type system but are unreachable at runtime.
    Error(CallbackSessionUnavailable) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "session_unavailable")],
        ),
      )
    Error(CallbackUnknownProvider(_)) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "unknown_provider")],
        ),
      )
  }

  finished
}
