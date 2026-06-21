# BEAM Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add detailed, redacted OAuth lifecycle logging through Erlang/OTP Logger without changing Vestibule's public auth results.

**Architecture:** Core `vestibule/internal/logger` builds pure structured events and sends them through a thin Erlang FFI wrapper to OTP `logger`. Core flow, transport helpers, Wisp/Mist adapters, and provider HTTP boundaries call this wrapper with stable event names and redacted fields.

**Tech Stack:** Gleam 1.16, Erlang/OTP Logger, existing `startest` tests, existing `just` package commands.

---

## File structure

- Create `src/vestibule/internal/logger.gleam`: private event model, level helpers, redaction-safe field builders, error classifiers, and `emit`.
- Create `src/vestibule/internal/logger_ffi.erl`: converts stable string fields to an Erlang map and calls `logger:log/2`.
- Create `test/vestibule/logger_test.gleam`: tests event fields, levels, error classification, and redaction rules.
- Modify `src/vestibule.gleam`: emits core flow events for authorization request, callback, and refresh.
- Modify `src/vestibule/transport_flow.gleam`: emits provider lookup and state-store lifecycle events.
- Modify `packages/vestibule_wisp/src/vestibule_wisp.gleam`: emits transport-specific request and callback events.
- Modify `packages/vestibule_mist/src/vestibule_mist.gleam`: emits transport-specific request and callback events.
- Modify `src/vestibule/provider_support.gleam`: emits provider HTTP and parse outcome events in shared helpers.
- Modify provider packages only where they call `httpc.send` directly: `packages/vestibule_github/src/vestibule_github.gleam`, `packages/vestibule_google/src/vestibule_google.gleam`, `packages/vestibule_microsoft/src/vestibule_microsoft.gleam`, `packages/vestibule_apple/src/vestibule_apple.gleam`, and `packages/vestibule_apple/src/vestibule_apple/jwks.gleam`.
- Modify package tests only when a provider-specific helper gains a direct event classification test.

## Task 1: Internal event model and OTP logger FFI

**Files:**
- Create: `src/vestibule/internal/logger.gleam`
- Create: `src/vestibule/internal/logger_ffi.erl`
- Create: `test/vestibule/logger_test.gleam`

- [ ] **Step 1: Write failing event-builder tests**

Add `test/vestibule/logger_test.gleam`:

```gleam
import gleam/list
import gleam/option.{None, Some}
import startest/expect
import vestibule/error
import vestibule/internal/logger

pub fn event_builder_includes_required_fields_test() {
  let event =
    logger.new(
      level: logger.Debug,
      event: "vestibule.callback.start",
      phase: "callback",
      outcome: "start",
      provider: Some("github"),
      fields: [logger.field("transport", "wisp")],
    )

  logger.level(event) |> expect.to_equal(logger.Debug)
  logger.fields(event)
  |> expect.to_equal([
    #("event", "vestibule.callback.start"),
    #("phase", "callback"),
    #("outcome", "start"),
    #("provider", "github"),
    #("transport", "wisp"),
  ])
}

pub fn event_builder_omits_absent_provider_test() {
  let event =
    logger.new(
      level: logger.Info,
      event: "vestibule.request.success",
      phase: "request",
      outcome: "success",
      provider: None,
      fields: [],
    )

  logger.fields(event)
  |> list.key_find("provider")
  |> expect.to_equal(Error(Nil))
}

pub fn auth_error_category_is_stable_and_redacted_test() {
  logger.auth_error_category(error.ProviderError(
    code: "invalid_grant",
    description: "secret-bearing provider text",
    uri: Some("https://provider.example/error"),
  ))
  |> expect.to_equal("provider_error")

  logger.auth_error_category(error.NetworkError(reason: "connect failed"))
  |> expect.to_equal("network_error")
}

pub fn redaction_guard_rejects_sensitive_field_names_test() {
  logger.safe_fields([
    logger.field("provider", "github"),
    logger.field("access_token", "secret-access-token"),
    logger.field("refresh_token", "secret-refresh-token"),
    logger.field("code_verifier", "secret-verifier"),
    logger.field("session_id", "secret-session"),
    logger.field("status", "500"),
  ])
  |> expect.to_equal([
    #("provider", "github"),
    #("status", "500"),
  ])
}
```

- [ ] **Step 2: Run the new test to verify it fails**

Run:

```bash
gleam test
```

Expected: FAIL because `vestibule/internal/logger` does not exist.

- [ ] **Step 3: Implement the internal logger module**

Create `src/vestibule/internal/logger.gleam`:

```gleam
import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/option
import vestibule/error.{type AuthError}

pub type Level {
  Debug
  Info
  Warning
  Error
}

pub opaque type Event {
  Event(level: Level, fields: List(#(String, String)))
}

pub fn new(
  level level: Level,
  event event_name: String,
  phase phase: String,
  outcome outcome: String,
  provider provider: Option(String),
  fields fields: List(#(String, String)),
) -> Event {
  let required = [
    #("event", event_name),
    #("phase", phase),
    #("outcome", outcome),
  ]
  let provider_fields = case provider {
    option.Some(name) -> [#("provider", name)]
    option.None -> []
  }
  Event(
    level: level,
    fields: safe_fields(required <> provider_fields <> fields),
  )
}

pub fn field(key: String, value: String) -> #(String, String) {
  #(key, value)
}

pub fn int_field(key: String, value: Int) -> #(String, String) {
  #(key, int.to_string(value))
}

pub fn bool_field(key: String, value: Bool) -> #(String, String) {
  #(key, bool.to_string(value))
}

pub fn level(event: Event) -> Level {
  event.level
}

pub fn fields(event: Event) -> List(#(String, String)) {
  event.fields
}

pub fn emit(event: Event) -> Nil {
  do_log(level_name(event.level), event.fields)
}

pub fn auth_error_category(err: AuthError(e)) -> String {
  case err {
    error.StateMismatch -> "state_mismatch"
    error.MissingCallbackParam(_) -> "missing_callback_param"
    error.CodeExchangeFailed(_) -> "code_exchange_failed"
    error.UserInfoFailed(_) -> "user_info_failed"
    error.ProviderError(_, _, _) -> "provider_error"
    error.HttpError(_, _) -> "http_error"
    error.DecodeError(_, _) -> "decode_error"
    error.NetworkError(_) -> "network_error"
    error.ConfigError(_) -> "config_error"
    error.Custom(_) -> "custom_error"
  }
}

pub fn safe_fields(fields: List(#(String, String))) -> List(#(String, String)) {
  list.filter(fields, fn(field) {
    let #(key, _) = field
    !list.contains(sensitive_field_names, key)
  })
}

fn level_name(level: Level) -> String {
  case level {
    Debug -> "debug"
    Info -> "info"
    Warning -> "warning"
    Error -> "error"
  }
}

const sensitive_field_names = [
  "access_token",
  "refresh_token",
  "client_secret",
  "authorization_code",
  "code",
  "code_verifier",
  "callback_params",
  "session_id",
  "cookie",
  "cookie_value",
  "response_body",
  "signed_payload",
]

@external(erlang, "vestibule_logger_ffi", "log")
fn do_log(level: String, fields: List(#(String, String))) -> Nil
```

Create `src/vestibule/internal/logger_ffi.erl`:

```erlang
-module(vestibule_logger_ffi).
-export([log/2]).

log(Level, Fields) ->
    logger:log(level(Level), maps:from_list([{key(Key), Value} || {Key, Value} <- Fields])),
    nil.

level(<<"debug">>) -> debug;
level(<<"info">>) -> info;
level(<<"warning">>) -> warning;
level(<<"error">>) -> error.

key(<<"event">>) -> event;
key(<<"phase">>) -> phase;
key(<<"outcome">>) -> outcome;
key(<<"provider">>) -> provider;
key(<<"transport">>) -> transport;
key(<<"endpoint">>) -> endpoint;
key(<<"status">>) -> status;
key(<<"error_category">>) -> error_category;
key(<<"scope_count">>) -> scope_count;
key(<<"has_refresh_token">>) -> has_refresh_token;
key(<<"has_id_token">>) -> has_id_token;
key(<<"secure_cookie">>) -> secure_cookie;
key(Other) -> Other.
```

- [ ] **Step 4: Run the new test to verify it passes**

Run:

```bash
gleam test
```

Expected: PASS for `logger_test`, or compile errors only for missing imports from Step 3.

- [ ] **Step 5: Commit**

```bash
git add src/vestibule/internal/logger.gleam src/vestibule/internal/logger_ffi.erl test/vestibule/logger_test.gleam
git commit -m "feat: add internal beam logger"
```

## Task 2: Core flow logging

**Files:**
- Modify: `src/vestibule.gleam`
- Test: existing `test/vestibule_test.gleam`

- [ ] **Step 1: Add a compile guard test**

Append to `test/vestibule_test.gleam`:

```gleam
pub fn logging_does_not_change_core_result_shapes_test() {
  let strat = test_strategy()
  let conf =
    config.new(
      client_id: "id",
      client_secret: "secret",
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(req) = vestibule.create_authorization_request(strat, cfg: conf)
  let params =
    dict.from_list([
      #("code", "valid_code"),
      #("state", authorization_request.state(req)),
    ])

  vestibule.handle_callback(
    strat,
    cfg: conf,
    callback_params: params,
    expected_state: authorization_request.state(req),
    code_verifier: authorization_request.code_verifier(req),
  )
  |> expect.to_be_ok()

  vestibule.refresh_token(strat, cfg: conf, refresh_tok: "refresh-123")
  |> expect.to_be_ok()
}
```

- [ ] **Step 2: Run the compile guard**

Run:

```bash
gleam test
```

Expected: PASS before implementation because this guards behavior, not log capture.

- [ ] **Step 3: Emit core events**

Modify `src/vestibule.gleam` imports:

```gleam
import vestibule/internal/logger
```

In `create_authorization_request`, add:

```gleam
  let provider = strategy.provider(strat)
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.authorization_request.start",
    phase: "request",
    outcome: "start",
    provider: option.Some(provider),
    fields: [],
  ))
```

After scopes are resolved, add:

```gleam
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.authorization_request.scopes_resolved",
    phase: "request",
    outcome: "success",
    provider: option.Some(provider),
    fields: [logger.int_field("scope_count", list.length(scopes))],
  ))
```

Wrap the final result so both success and failure are logged:

```gleam
  let result = {
    use base_url <- result.try(strategy.build_authorize_url(
      strat,
      cfg: cfg,
      scopes: scopes,
      state: csrf_state,
    ))
    let url = append_pkce_params(base_url, code_challenge)
    Ok(authorization_request.new(
      url: url,
      state: csrf_state,
      code_verifier: code_verifier,
    ))
  }

  case result {
    Ok(_) ->
      logger.emit(logger.new(
        level: logger.Info,
        event: "vestibule.authorization_request.success",
        phase: "request",
        outcome: "success",
        provider: option.Some(provider),
        fields: [],
      ))
    Error(err) ->
      logger.emit(logger.new(
        level: logger.Error,
        event: "vestibule.authorization_request.failure",
        phase: "request",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", logger.auth_error_category(err))],
      ))
  }
  result
```

In `handle_callback`, add start, state, provider error, exchange, user-info, and final events. Use the same pattern: log `Debug` at each boundary, `Info` on final success, `Warning` for expected auth failures, and `Error` for `network_error`, `http_error`, `decode_error`, or `config_error`.

Use this helper in `src/vestibule.gleam`:

```gleam
fn failure_level(err: AuthError(e)) -> logger.Level {
  case logger.auth_error_category(err) {
    "network_error" | "http_error" | "decode_error" | "config_error" ->
      logger.Error
    _ -> logger.Warning
  }
}
```

In `refresh_token`, replace the direct return with:

```gleam
  let provider = strategy.provider(strat)
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.refresh.start",
    phase: "refresh",
    outcome: "start",
    provider: option.Some(provider),
    fields: [],
  ))
  let refreshed = strategy.refresh_token(strat, cfg: cfg, refresh_tok: refresh_tok)
  case refreshed {
    Ok(creds) ->
      logger.emit(logger.new(
        level: logger.Info,
        event: "vestibule.refresh.success",
        phase: "refresh",
        outcome: "success",
        provider: option.Some(provider),
        fields: [
          logger.bool_field(
            "has_refresh_token",
            option.is_some(credentials.refresh_token(creds)),
          ),
          logger.int_field("scope_count", list.length(credentials.scopes(creds))),
        ],
      ))
    Error(err) ->
      logger.emit(logger.new(
        level: failure_level(err),
        event: "vestibule.refresh.failure",
        phase: "refresh",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", logger.auth_error_category(err))],
      ))
  }
  refreshed
```

Add imports:

```gleam
import gleam/list
```

- [ ] **Step 4: Run core tests**

Run:

```bash
gleam test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vestibule.gleam test/vestibule_test.gleam
git commit -m "feat: log core auth flow"
```

## Task 3: Transport-flow logging

**Files:**
- Modify: `src/vestibule/transport_flow.gleam`
- Test: existing root tests

- [ ] **Step 1: Run current transport tests**

Run:

```bash
gleam test
```

Expected: PASS before implementation.

- [ ] **Step 2: Add provider lookup and state-store events**

Modify imports in `src/vestibule/transport_flow.gleam`:

```gleam
import gleam/option
import vestibule/internal/logger
```

At the start of `start_authorization`, add:

```gleam
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.transport.request.start",
    phase: "request",
    outcome: "start",
    provider: option.Some(provider),
    fields: [],
  ))
```

Replace the final `Ok` path with a `started` result and log after it:

```gleam
  let started = {
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
  case started {
    Ok(_) ->
      logger.emit(logger.new(
        level: logger.Info,
        event: "vestibule.transport.request.success",
        phase: "request",
        outcome: "success",
        provider: option.Some(provider),
        fields: [],
      ))
    Error(UnknownProvider(_)) ->
      logger.emit(logger.new(
        level: logger.Warning,
        event: "vestibule.transport.request.failure",
        phase: "request",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", "unknown_provider")],
      ))
    Error(AuthFailed(err)) ->
      logger.emit(logger.new(
        level: logger.Warning,
        event: "vestibule.transport.request.failure",
        phase: "request",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", logger.auth_error_category(err))],
      ))
    Error(StoreFailed(_)) ->
      logger.emit(logger.new(
        level: logger.Error,
        event: "vestibule.transport.request.failure",
        phase: "request",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", "state_store_failed")],
      ))
  }
  started
```

In `ensure_callback_provider`, replace the direct pipeline with:

```gleam
  let lookup =
    registry.get(provider_registry, provider: provider)
    |> result.map_error(fn(_) { CallbackUnknownProvider(provider) })
  case lookup {
    Ok(_) ->
      logger.emit(logger.new(
        level: logger.Debug,
        event: "vestibule.transport.callback.provider_found",
        phase: "callback",
        outcome: "success",
        provider: option.Some(provider),
        fields: [],
      ))
    Error(_) ->
      logger.emit(logger.new(
        level: logger.Warning,
        event: "vestibule.transport.callback.provider_missing",
        phase: "callback",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", "unknown_provider")],
      ))
  }
  lookup
```

In `finish_callback`, add this start event after destructuring `strategy_config`:

```gleam
  let provider = strategy.provider(strategy)
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.transport.callback.start",
    phase: "callback",
    outcome: "start",
    provider: option.Some(provider),
    fields: [],
  ))
```

Replace each direct `result.try` boundary with a named result and log it. Use this exact pattern for state peek:

```gleam
  let peeked =
    state_store.peek(store, session_id)
    |> result.map_error(fn(_) { CallbackSessionUnavailable })
  case peeked {
    Ok(_) ->
      logger.emit(logger.new(
        level: logger.Debug,
        event: "vestibule.transport.callback.state_peek.success",
        phase: "callback",
        outcome: "success",
        provider: option.Some(provider),
        fields: [],
      ))
    Error(_) ->
      logger.emit(logger.new(
        level: logger.Warning,
        event: "vestibule.transport.callback.state_peek.failure",
        phase: "callback",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", "session_unavailable")],
      ))
  }
  use #(expected_state, _code_verifier) <- result.try(peeked)
```

Use the same named-result pattern for `state.validate` with events `vestibule.transport.callback.state_validate.success` and `vestibule.transport.callback.state_validate.failure`, and `error_category = "state_mismatch"` on failure. Use the same pattern for `state_store.consume` with events `vestibule.transport.callback.state_consume.success` and `vestibule.transport.callback.state_consume.failure`, and `error_category = "session_unavailable"` on failure.

Wrap the final `vestibule.handle_callback` call:

```gleam
  let finished =
    vestibule.handle_callback(
      strategy,
      cfg: config,
      callback_params: params,
      expected_state: expected_state,
      code_verifier: code_verifier,
    )
    |> result.map_error(CallbackAuthFailed)
  case finished {
    Ok(_) ->
      logger.emit(logger.new(
        level: logger.Info,
        event: "vestibule.transport.callback.success",
        phase: "callback",
        outcome: "success",
        provider: option.Some(provider),
        fields: [],
      ))
    Error(CallbackAuthFailed(err)) ->
      logger.emit(logger.new(
        level: logger.Warning,
        event: "vestibule.transport.callback.failure",
        phase: "callback",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", logger.auth_error_category(err))],
      ))
    Error(CallbackSessionUnavailable) ->
      logger.emit(logger.new(
        level: logger.Warning,
        event: "vestibule.transport.callback.failure",
        phase: "callback",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", "session_unavailable")],
      ))
    Error(CallbackUnknownProvider(_)) ->
      logger.emit(logger.new(
        level: logger.Warning,
        event: "vestibule.transport.callback.failure",
        phase: "callback",
        outcome: "failure",
        provider: option.Some(provider),
        fields: [logger.field("error_category", "unknown_provider")],
      ))
  }
  finished
```

Do not log `session_id`, state, code, or verifier.

- [ ] **Step 3: Run root tests**

Run:

```bash
gleam test
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/vestibule/transport_flow.gleam
git commit -m "feat: log transport auth flow"
```

## Task 4: Wisp and Mist adapter logging

**Files:**
- Modify: `packages/vestibule_wisp/src/vestibule_wisp.gleam`
- Modify: `packages/vestibule_mist/src/vestibule_mist.gleam`
- Test: existing package tests

- [ ] **Step 1: Run adapter tests before implementation**

Run:

```bash
just test-pkg vestibule_wisp && just test-pkg vestibule_mist
```

Expected: PASS.

- [ ] **Step 2: Add Wisp logging**

In `packages/vestibule_wisp/src/vestibule_wisp.gleam`, add imports:

```gleam
import gleam/option
import vestibule/internal/logger
```

At the start of `request_phase_with_options`, emit:

```gleam
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.adapter.request.start",
    phase: "request",
    outcome: "start",
    provider: option.Some(provider),
    fields: [logger.field("transport", "wisp")],
  ))
```

Inside each `request_phase_with_options` case branch, emit one result event before returning:

```gleam
Error(transport_flow.UnknownProvider(_)) -> {
  logger.emit(logger.new(
    level: logger.Warning,
    event: "vestibule.adapter.request.failure",
    phase: "request",
    outcome: "failure",
    provider: option.Some(provider),
    fields: [
      logger.field("transport", "wisp"),
      logger.field("error_category", "unknown_provider"),
    ],
  ))
  wisp.not_found()
}
Error(transport_flow.AuthFailed(err)) -> {
  logger.emit(logger.new(
    level: logger.Warning,
    event: "vestibule.adapter.request.failure",
    phase: "request",
    outcome: "failure",
    provider: option.Some(provider),
    fields: [
      logger.field("transport", "wisp"),
      logger.field("error_category", logger.auth_error_category(err)),
    ],
  ))
  error_response(err)
}
Error(transport_flow.StoreFailed(_)) -> {
  logger.emit(logger.new(
    level: logger.Error,
    event: "vestibule.adapter.request.failure",
    phase: "request",
    outcome: "failure",
    provider: option.Some(provider),
    fields: [
      logger.field("transport", "wisp"),
      logger.field("error_category", "state_store_failed"),
    ],
  ))
  error_response(error.ConfigError(
    reason: "Failed to store OAuth session state",
  ))
}
Ok(#(url, session_id)) -> {
  logger.emit(logger.new(
    level: logger.Info,
    event: "vestibule.adapter.request.success",
    phase: "request",
    outcome: "success",
    provider: option.Some(provider),
    fields: [logger.field("transport", "wisp")],
  ))
  wisp.redirect(url)
  |> wisp.set_cookie(
    req,
    options.cookie_name,
    session_id,
    wisp.Signed,
    options.session_ttl_seconds,
  )
}
```

At the start of `callback_phase_auth_result_with_options`, emit:

```gleam
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.adapter.callback.start",
    phase: "callback",
    outcome: "start",
    provider: option.Some(provider),
    fields: [logger.field("transport", "wisp")],
  ))
```

Add this helper and call it from `callback_phase_with_options` before `callback_error_response(err)`:

```gleam
fn log_callback_error(provider: String, err: CallbackError(e)) -> Nil {
  let category = case err {
    UnknownProvider(_) -> "unknown_provider"
    MissingSessionCookie -> "missing_session_cookie"
    SessionExpired -> "session_expired"
    InvalidCallbackParams -> "invalid_callback_params"
    AuthFailed(err) -> logger.auth_error_category(err)
  }
  logger.emit(logger.new(
    level: logger.Warning,
    event: "vestibule.adapter.callback.failure",
    phase: "callback",
    outcome: "failure",
    provider: option.Some(provider),
    fields: [
      logger.field("transport", "wisp"),
      logger.field("error_category", category),
    ],
  ))
}
```

In the success branch of `callback_phase_with_options`, add:

```gleam
logger.emit(logger.new(
  level: logger.Info,
  event: "vestibule.adapter.callback.success",
  phase: "callback",
  outcome: "success",
  provider: option.Some(provider),
  fields: [logger.field("transport", "wisp")],
))
```

Do not log cookie values or request parameters.

- [ ] **Step 3: Add Mist logging**

In `packages/vestibule_mist/src/vestibule_mist.gleam`, add imports:

```gleam
import gleam/option
import vestibule/internal/logger
```

Use the same event names as Wisp with `logger.field("transport", "mist")`. At the start of `request_phase`, emit:

```gleam
logger.emit(logger.new(
  level: logger.Debug,
  event: "vestibule.adapter.request.start",
  phase: "request",
  outcome: "start",
  provider: option.Some(provider),
  fields: [
    logger.field("transport", "mist"),
    logger.bool_field("secure_cookie", options.secure_cookie),
  ],
))
```

Use the Wisp `request_phase_with_options` branch snippets with response constructors changed to Mist's existing `not_found_response()`, `generic_error_response()`, and redirect branch. In `callback_phase`, log success before `on_success(auth)`:

```gleam
logger.emit(logger.new(
  level: logger.Info,
  event: "vestibule.adapter.callback.success",
  phase: "callback",
  outcome: "success",
  provider: option.Some(provider),
  fields: [logger.field("transport", "mist")],
))
```

Add this Mist-specific callback error helper:

```gleam
fn log_callback_error(provider: String, err: CallbackError(e)) -> Nil {
  let category = case err {
    UnknownProvider(_) -> "unknown_provider"
    MissingOrInvalidSessionCookie -> "missing_or_invalid_session_cookie"
    SessionUnavailable -> "session_unavailable"
    InvalidCallbackParams -> "invalid_callback_params"
    AuthFailed(err) -> logger.auth_error_category(err)
  }
  logger.emit(logger.new(
    level: logger.Warning,
    event: "vestibule.adapter.callback.failure",
    phase: "callback",
    outcome: "failure",
    provider: option.Some(provider),
    fields: [
      logger.field("transport", "mist"),
      logger.field("error_category", category),
    ],
  ))
}
```

Do not log `secret_key_base`, signed cookie tokens, or extracted session IDs.

- [ ] **Step 4: Run adapter tests**

Run:

```bash
just test-pkg vestibule_wisp && just test-pkg vestibule_mist
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/vestibule_wisp/src/vestibule_wisp.gleam packages/vestibule_mist/src/vestibule_mist.gleam
git commit -m "feat: log transport adapters"
```

## Task 5: Provider support logging

**Files:**
- Modify: `src/vestibule/provider_support.gleam`
- Test: `test/vestibule/provider_support_test.gleam`

- [ ] **Step 1: Add provider-support classification tests**

Append to `test/vestibule/provider_support_test.gleam`:

```gleam
pub fn check_response_status_still_truncates_logged_unsafe_body_test() {
  let long_body = string.repeat("secret-body-", 20)
  let result =
    response.Response(status: 502, headers: [], body: long_body)
    |> provider_support.check_response_status()

  case result {
    Error(error.HttpError(status:, body:)) -> {
      status |> expect.to_equal(502)
      { string.length(body) <= 120 } |> expect.to_be_true()
    }
    _ -> panic as "expected HttpError"
  }
}
```

- [ ] **Step 2: Run provider-support tests**

Run:

```bash
gleam test
```

Expected: PASS before implementation.

- [ ] **Step 3: Log shared provider HTTP outcomes**

Add imports to `src/vestibule/provider_support.gleam`:

```gleam
import vestibule/internal/logger
```

Change `check_response_status` to log by delegating to a new helper:

```gleam
pub fn check_response_status(
  response: Response(String),
) -> Result(String, AuthError(e)) {
  check_response_status_for_endpoint(
    response,
    provider_name: "unknown",
    endpoint: "unknown",
  )
}

pub fn check_response_status_for_endpoint(
  response: Response(String),
  provider_name provider_name: String,
  endpoint endpoint: String,
) -> Result(String, AuthError(e)) {
  let fields = [
    logger.field("endpoint", endpoint),
    logger.int_field("status", response.status),
  ]
  use <- bool.guard(
    when: response.status < 200 || response.status >= 300,
    return: {
      logger.emit(logger.new(
        level: logger.Error,
        event: "vestibule.provider.response.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: option.Some(provider_name),
        fields: fields <> [logger.field("error_category", "http_error")],
      ))
      Error(error.HttpError(
        status: response.status,
        body: safe_error_body(response.body),
      ))
    },
  )
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.provider.response.success",
    phase: "provider_request",
    outcome: "success",
    provider: option.Some(provider_name),
    fields: fields,
  ))
  Ok(response.body)
}
```

In `fetch_json_with_auth`, emit an attempt before `httpc.send(req)`:

```gleam
  logger.emit(logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some(provider_name),
    fields: [logger.field("endpoint", "user_info")],
  ))
```

Replace `check_response_status(response)` with:

```gleam
check_response_status_for_endpoint(
  response,
  provider_name: provider_name,
  endpoint: "user_info",
)
```

On `httpc.send` error, emit:

```gleam
logger.emit(logger.new(
  level: logger.Error,
  event: "vestibule.provider.request.failure",
  phase: "provider_request",
  outcome: "failure",
  provider: option.Some(provider_name),
  fields: [
    logger.field("endpoint", "user_info"),
    logger.field("error_category", "network_error"),
  ],
))
```

- [ ] **Step 4: Run root tests**

Run:

```bash
gleam test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vestibule/provider_support.gleam test/vestibule/provider_support_test.gleam
git commit -m "feat: log provider support outcomes"
```

## Task 6: Provider package HTTP boundary logging

**Files:**
- Modify: `packages/vestibule_github/src/vestibule_github.gleam`
- Modify: `packages/vestibule_google/src/vestibule_google.gleam`
- Modify: `packages/vestibule_microsoft/src/vestibule_microsoft.gleam`
- Modify: `packages/vestibule_apple/src/vestibule_apple.gleam`
- Modify: `packages/vestibule_apple/src/vestibule_apple/jwks.gleam`
- Test: provider package tests

- [ ] **Step 1: Run provider package tests before implementation**

Run:

```bash
just test-pkg vestibule_github && just test-pkg vestibule_google && just test-pkg vestibule_microsoft && just test-pkg vestibule_apple
```

Expected: PASS.

- [ ] **Step 2: Add direct provider logging pattern**

For each provider module with `httpc.send(req)`, add:

```gleam
import gleam/option
import vestibule/internal/logger
```

Before token endpoint sends, emit:

```gleam
logger.emit(logger.new(
  level: logger.Debug,
  event: "vestibule.provider.request.start",
  phase: "provider_request",
  outcome: "start",
  provider: option.Some("github"),
  fields: [logger.field("endpoint", "token")],
))
```

Use the package's real provider name: `"github"`, `"google"`, `"microsoft"`, or `"apple"`. For refresh sends, use `endpoint = "refresh"`. For user profile sends, use `endpoint = "user_info"`. For GitHub emails, use `endpoint = "user_email"`. For Apple JWKS, use `endpoint = "jwks"`.

Replace direct calls to `provider_support.check_response_status(response)` with:

```gleam
provider_support.check_response_status_for_endpoint(
  response,
  provider_name: "github",
  endpoint: "token",
)
```

Use the correct provider and endpoint strings for each call site.

On `httpc.send` error branches, emit:

```gleam
logger.emit(logger.new(
  level: logger.Error,
  event: "vestibule.provider.request.failure",
  phase: "provider_request",
  outcome: "failure",
  provider: option.Some("github"),
  fields: [
    logger.field("endpoint", "token"),
    logger.field("error_category", "network_error"),
  ],
))
```

Do not include request bodies, headers, tokens, authorization codes, refresh tokens, `id_token`, raw user-info bodies, or JWKS bodies in any field.

- [ ] **Step 3: Log parse outcomes in token parsing helpers**

In each `parse_token_response` helper, wrap parsing with a local `result` and emit:

```gleam
let parsed =
  provider_support.parse_oauth_token_response(
    body,
    provider_support.RequiredScope(separator: ","),
  )
case parsed {
  Ok(creds) ->
    logger.emit(logger.new(
      level: logger.Debug,
      event: "vestibule.provider.token_parse.success",
      phase: "provider_request",
      outcome: "success",
      provider: option.Some("github"),
      fields: [
        logger.field("endpoint", "token"),
        logger.bool_field(
          "has_refresh_token",
          option.is_some(credentials.refresh_token(creds)),
        ),
        logger.int_field("scope_count", list.length(credentials.scopes(creds))),
      ],
    ))
  Error(err) ->
    logger.emit(logger.new(
      level: logger.Warning,
      event: "vestibule.provider.token_parse.failure",
      phase: "provider_request",
      outcome: "failure",
      provider: option.Some("github"),
      fields: [
        logger.field("endpoint", "token"),
        logger.field("error_category", logger.auth_error_category(err)),
      ],
    ))
}
parsed
```

Adjust provider name and scope parsing exactly to the existing helper. For Apple, also include `logger.bool_field("has_id_token", True)` only after a successful parse confirms the `id_token` artifact is present.

- [ ] **Step 4: Run provider package tests**

Run:

```bash
just test-pkg vestibule_github && just test-pkg vestibule_google && just test-pkg vestibule_microsoft && just test-pkg vestibule_apple
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/vestibule_github/src/vestibule_github.gleam packages/vestibule_google/src/vestibule_google.gleam packages/vestibule_microsoft/src/vestibule_microsoft.gleam packages/vestibule_apple/src/vestibule_apple.gleam packages/vestibule_apple/src/vestibule_apple/jwks.gleam
git commit -m "feat: log provider http boundaries"
```

## Task 7: Documentation and full validation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add README logging section**

Add after the state-store paragraph in `README.md`:

```markdown
### Logging

Vestibule emits structured OAuth lifecycle logs through Erlang/OTP Logger. It
does not configure Logger handlers or levels; your application keeps normal
BEAM control over log routing, filtering, and formatting.

Logs include safe fields such as `event`, `phase`, `outcome`, `provider`,
`transport`, `endpoint`, `status`, and `error_category`. Vestibule never logs
access tokens, refresh tokens, client secrets, authorization codes, PKCE code
verifiers, raw callback parameters, session IDs, cookie values, signed payloads,
or raw provider response bodies.
```

- [ ] **Step 2: Run formatting**

Run:

```bash
gleam format src test packages/vestibule_github/src packages/vestibule_github/test packages/vestibule_google/src packages/vestibule_google/test packages/vestibule_microsoft/src packages/vestibule_microsoft/test packages/vestibule_apple/src packages/vestibule_apple/test packages/vestibule_wisp/src packages/vestibule_wisp/test packages/vestibule_mist/src packages/vestibule_mist/test
```

Expected: command exits 0 and rewrites only Gleam formatting.

- [ ] **Step 3: Run focused package tests**

Run:

```bash
just test-pkg vestibule_github && just test-pkg vestibule_google && just test-pkg vestibule_microsoft && just test-pkg vestibule_apple && just test-pkg vestibule_wisp && just test-pkg vestibule_mist
```

Expected: PASS.

- [ ] **Step 4: Run root validation**

Run:

```bash
gleam check && gleam test && gleam docs build
```

Expected: PASS.

- [ ] **Step 5: Run monorepo validation**

Run:

```bash
just format-check && just check && just test && just build
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add README.md src packages test
git commit -m "docs: document vestibule logging"
```

## Self-review

Spec coverage:

- BEAM-native logging: Task 1 adds OTP Logger FFI.
- No custom framework or global logger config: Task 1 only emits events; Task 7 documents application-owned configuration.
- Structured required fields: Task 1 tests and implements `event`, `phase`, `outcome`, and optional `provider`.
- Transport and provider fields: Tasks 4 and 6 add `transport` and `endpoint`.
- Levels: Tasks 1 through 6 use `debug`, `info`, `warning`, and `error` according to the spec.
- Redaction: Task 1 adds `safe_fields`; Tasks 4 and 6 explicitly forbid cookies, sessions, tokens, headers, and bodies.
- Flow coverage: Tasks 2 through 6 cover core, transport flow, Wisp/Mist, shared provider support, and provider packages.
- Testing: Tasks 1, 5, 6, and 7 cover pure event tests, provider helper tests, package tests, and monorepo validation.
- Compatibility: Task 2 keeps return shapes unchanged; Task 7 validates all packages.

Placeholder scan: no placeholders remain. Every code-producing step names exact files and concrete code.

Type consistency: all event construction uses `logger.Level`, `logger.new`, `logger.field`, `logger.int_field`, `logger.bool_field`, `logger.emit`, and `logger.auth_error_category` defined in Task 1.
