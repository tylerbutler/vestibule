//// Transport-independent OAuth request and callback flow helpers.
////
//// This module is internal plumbing shared by the first-party transport
//// middlewares (`vestibule_wisp` and `vestibule_mist`). It is not part of
//// vestibule's stable public API: its tuple shapes and error variants may
//// change without a major version bump. Transport authors should depend on
//// the middleware packages rather than this module.

import gleam/dict.{type Dict}
import gleam/list
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
  CallbackSessionProviderMismatch
  CallbackAuthFailed(AuthError(e))
}

/// Convert raw callback parameter pairs to a dictionary, rejecting every
/// repeated name. OAuth parameters are single-valued; choosing the first or
/// last duplicate makes validation depend on parser and proxy ordering.
pub fn callback_parameters(
  query: List(#(String, String)),
  body: List(#(String, String)),
) -> Result(Dict(String, String), String) {
  unique_parameters(list.append(query, body), dict.new())
}

fn unique_parameters(
  parameters: List(#(String, String)),
  values: Dict(String, String),
) -> Result(Dict(String, String), String) {
  case parameters {
    [] -> Ok(values)
    [#(name, value), ..rest] ->
      case dict.has_key(values, name) {
        True -> Error(name)
        False -> unique_parameters(rest, dict.insert(values, name, value))
      }
  }
}

/// Generate an authorization URL and store the expected state/verifier.
pub fn start_authorization(
  provider_registry: Registry(e),
  provider provider: String,
  store store: StateStore,
  ttl_seconds ttl_seconds: Int,
  options options: AuthorizeOptions,
) -> Result(#(String, String), RequestFlowError(e)) {
  start_authorization_for_client(
    provider_registry,
    provider: provider,
    store: store,
    client_key: "unidentified",
    ttl_seconds: ttl_seconds,
    options: options,
  )
}

/// Generate an authorization URL after applying admission limits for a
/// stable direct-client identifier.
pub fn start_authorization_for_client(
  provider_registry: Registry(e),
  provider provider: String,
  store store: StateStore,
  client_key client_key: String,
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
    use authorization_request_value <- result.try(
      vestibule.create_authorization_request(
        strategy,
        config: config,
        options: options,
      )
      |> result.map_error(AuthFailed),
    )
    use session_id <- result.try(
      state_store.store_for_client_with_ttl(
        store,
        client_key: client_key,
        provider: strategy.provider(strategy),
        state: authorization_request.state(authorization_request_value),
        code_verifier: authorization_request.code_verifier(
          authorization_request_value,
        ),
        nonce: authorization_request.nonce(authorization_request_value),
        ttl_seconds: ttl_seconds,
      )
      |> result.map_error(StoreFailed),
    )

    Ok(#(authorization_request.url(authorization_request_value), session_id))
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
    Error(AuthFailed(auth_error)) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.request.failure",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
    Error(StoreFailed(state_store.ClientLimitReached))
    | Error(StoreFailed(state_store.StoreFull)) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.request.rejected",
          phase: "request",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "admission_limit")],
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
  parameters parameters: Dict(String, String),
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
    dict.get(parameters, "state")
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
    state_store.peek_with_error(store, session_id, provider: provider)
    |> result.map_error(fn(error) {
      case error {
        state_store.SessionMissing -> CallbackSessionUnavailable
        state_store.SessionProviderMismatch -> CallbackSessionProviderMismatch
      }
    })
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
    Error(peek_error) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.state_peek.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field("error_category", case peek_error {
              CallbackSessionProviderMismatch -> "provider_mismatch"
              CallbackSessionUnavailable -> "session_unavailable"
              CallbackUnknownProvider(_) -> "unknown_provider"
              CallbackAuthFailed(_) -> "authentication_failed"
            }),
          ],
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
    state_store.consume(store, session_id, provider: provider)
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
      config: config,
      callback_params: parameters,
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
    Error(CallbackAuthFailed(auth_error)) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
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
    Error(CallbackSessionProviderMismatch) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.transport.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: option.Some(provider),
          fields: [logger.field("error_category", "provider_mismatch")],
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
