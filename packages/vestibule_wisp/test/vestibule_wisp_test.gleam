import gleam/http
import gleam/string
import startest
import startest/expect
import vestibule/config
import vestibule/error
import vestibule/registry
import vestibule/strategy.{type Strategy, Strategy}
import vestibule_wisp
import vestibule_wisp/state_store
import wisp
import wisp/simulate

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn store_and_retrieve_state_and_verifier_test() {
  let table = state_store.init_named("test_store_retrieve")
  let state = "test-csrf-state-value"
  let verifier = "test-pkce-code-verifier"
  let session_id = state_store.store(table, state, verifier)
  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}

pub fn retrieve_deletes_after_use_test() {
  let table = state_store.init_named("test_delete_after_use")
  let session_id =
    state_store.store(table, "one-time-state", "one-time-verifier")
  let _ = state_store.retrieve(table, session_id)
  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
}

pub fn retrieve_unknown_returns_error_test() {
  let table = state_store.init_named("test_unknown_returns_error")
  state_store.retrieve(table, "nonexistent-session-id")
  |> expect.to_be_error()
}

pub fn try_init_named_returns_error_for_duplicate_table_test() {
  let name = "vestibule_wisp_duplicate_test"
  let assert Ok(_) = state_store.try_init_named(name)
  let result = state_store.try_init_named(name)
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn state_store_survives_creator_process_exit_test() {
  state_store_survives_creator_process_exit()
  |> expect.to_be_true()
}

pub fn try_store_returns_session_id_and_retrievable_value_test() {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_wisp_try_store_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) = state_store.try_store(table, state, verifier)

  { string.length(session_id) > 0 } |> expect.to_be_true()
  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}

pub fn try_store_with_ttl_stores_retrievable_value_test() {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_wisp_try_store_ttl_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) =
    state_store.try_store_with_ttl(table, state, verifier, 600)

  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}

pub fn retrieve_consumes_expired_session_test() {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_wisp_expired_session_test")
  let assert Ok(session_id) =
    state_store.try_store_with_ttl(table, "state", "verifier", 0)

  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
}

pub fn callback_phase_auth_result_unknown_provider_test() {
  let req = simulate.request(http.Get, "/auth/unknown/callback")
  let store = state_store.init_named("test_callback_unknown_provider")

  vestibule_wisp.callback_phase_auth_result(
    req,
    registry.new(),
    "unknown",
    store,
  )
  |> expect.to_equal(Error(vestibule_wisp.UnknownProvider("unknown")))
}

pub fn callback_phase_auth_result_missing_session_cookie_test() {
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
  let store = state_store.init_named("test_callback_missing_session_cookie")
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_wisp.callback_phase_auth_result(req, reg, "test", store)
  |> expect.to_equal(Error(vestibule_wisp.MissingSessionCookie))
}

pub fn default_options_use_current_cookie_contract_test() {
  vestibule_wisp.default_options()
  |> expect.to_equal(vestibule_wisp.Options(
    cookie_name: "vestibule_session",
    session_ttl_seconds: 600,
  ))
}

pub fn callback_phase_auth_result_with_options_uses_cookie_name_test() {
  let store = state_store.init_named("test_callback_custom_cookie_name")
  let session_id = state_store.store(store, "state", "verifier")
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("vestibule_session", session_id, wisp.Signed)
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_wisp.callback_phase_auth_result_with_options(
    req,
    reg,
    "test",
    store,
    vestibule_wisp.Options(
      cookie_name: "custom_vestibule_session",
      session_ttl_seconds: 600,
    ),
  )
  |> expect.to_equal(Error(vestibule_wisp.MissingSessionCookie))
}

pub fn callback_phase_auth_result_malformed_post_body_returns_invalid_params_test() {
  let store = state_store.init_named("test_callback_malformed_post_body")
  let session_id = state_store.store(store, "state", "verifier")
  let req =
    simulate.request(http.Post, "/auth/test/callback?state=state&code=code")
    |> simulate.bit_array_body(<<255>>)
    |> simulate.cookie("vestibule_session", session_id, wisp.Signed)
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_wisp.callback_phase_auth_result(req, reg, "test", store)
  |> expect.to_equal(Error(vestibule_wisp.InvalidCallbackParams))
}

pub fn callback_phase_auth_result_missing_state_does_not_consume_session_test() {
  let store = state_store.init_named("test_callback_missing_state_reusable")
  let session_id = state_store.store(store, "state", "verifier")
  let req_missing_state =
    simulate.request(http.Get, "/auth/test/callback?code=code")
    |> simulate.cookie("vestibule_session", session_id, wisp.Signed)
  let req_with_state =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("vestibule_session", session_id, wisp.Signed)
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_wisp.callback_phase_auth_result(
    req_missing_state,
    reg,
    "test",
    store,
  )
  |> expect.to_equal(
    Error(vestibule_wisp.AuthFailed(error.MissingCallbackParam("state"))),
  )

  vestibule_wisp.callback_phase_auth_result(req_with_state, reg, "test", store)
  |> expect.to_equal(
    Error(vestibule_wisp.AuthFailed(error.ConfigError(reason: "test"))),
  )
}

fn test_strategy() -> Strategy(e) {
  Strategy(
    provider: "test",
    default_scopes: [],
    authorize_url: fn(_config, _scopes, _state) { Ok("https://example.com") },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.ConfigError(reason: "test"))
    },
    refresh_token: fn(_config, _refresh_token) {
      Error(error.ConfigError(reason: "test"))
    },
    fetch_user: fn(_config, _credentials) {
      Error(error.ConfigError(reason: "test"))
    },
  )
}

fn test_config() -> config.Config {
  config.new("client_id", "client_secret", "https://example.com/callback")
}

@external(erlang, "vestibule_wisp_state_store_test_ffi", "state_store_survives_creator_process_exit")
fn state_store_survives_creator_process_exit() -> Bool
