import gleam/http
import gleam/list
import gleam/option
import gleam/string
import startest
import startest/expect
import vestibule/config
import vestibule/error
import vestibule/registry
import vestibule/state_store
import vestibule/strategy.{type Strategy}
import vestibule_wisp
import wisp
import wisp/simulate

pub fn main() -> Nil {
  startest.run(startest.default_config())
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
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_wisp.callback_phase_auth_result(req, reg, "test", store)
  |> expect.to_equal(Error(vestibule_wisp.MissingSessionCookie))
}

pub fn default_options_use_current_cookie_contract_test() {
  vestibule_wisp.default_options()
  |> expect.to_equal(vestibule_wisp.Options(
    cookie_name: "__Host-vestibule_session",
    session_ttl_seconds: 600,
  ))
}

pub fn default_cookie_name_is_host_bound_test() {
  let options = vestibule_wisp.default_options()
  vestibule_wisp.is_host_bound_cookie_name(options.cookie_name)
  |> expect.to_be_true()
}

pub fn is_host_bound_cookie_name_rejects_non_prefixed_test() {
  vestibule_wisp.is_host_bound_cookie_name("vestibule_session")
  |> expect.to_be_false()
}

pub fn is_host_bound_cookie_name_accepts_host_prefixed_test() {
  vestibule_wisp.is_host_bound_cookie_name("__Host-custom_session")
  |> expect.to_be_true()
}

pub fn request_phase_sets_host_bound_cookie_test() {
  let store = state_store.init_named("test_request_phase_host_bound_cookie")
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())
  let req = simulate.request(http.Get, "/auth/test")

  let response = vestibule_wisp.request_phase(req, reg, "test", store)

  let set_cookie = case list.key_find(response.headers, "set-cookie") {
    Ok(value) -> value
    Error(_) -> panic as "expected a set-cookie header"
  }

  { string.contains(set_cookie, "__Host-vestibule_session=") }
  |> expect.to_be_true()
  { string.contains(set_cookie, "Secure") } |> expect.to_be_true()
  { string.contains(set_cookie, "Path=/") } |> expect.to_be_true()
  { string.contains(set_cookie, "Domain=") } |> expect.to_be_false()
}

pub fn callback_phase_auth_result_with_options_uses_cookie_name_test() {
  let store = state_store.init_named("test_callback_custom_cookie_name")
  let session_id =
    state_store.store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("vestibule_session", session_id, wisp.Signed)
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

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
  let session_id =
    state_store.store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Post, "/auth/test/callback?state=state&code=code")
    |> simulate.bit_array_body(<<255>>)
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_wisp.callback_phase_auth_result(req, reg, "test", store)
  |> expect.to_equal(Error(vestibule_wisp.InvalidCallbackParams))
}

pub fn callback_phase_auth_result_missing_state_does_not_consume_session_test() {
  let store = state_store.init_named("test_callback_missing_state_reusable")
  let session_id =
    state_store.store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req_missing_state =
    simulate.request(http.Get, "/auth/test/callback?code=code")
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let req_with_state =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(reg) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

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
  strategy.new(provider: "test", default_scopes: [])
  |> strategy.with_authorize_url(fn(_config, _scopes, _state) {
    Ok("https://example.com")
  })
  |> strategy.with_exchange_code(fn(_config, _code, _code_verifier) {
    Error(error.ConfigError(reason: "test"))
  })
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.ConfigError(reason: "test"))
  })
  |> strategy.with_fetch_user(fn(_config, _exchange) {
    Error(error.ConfigError(reason: "test"))
  })
}

fn leaky_error_strategy() -> Strategy(e) {
  strategy.new(provider: "test", default_scopes: [])
  |> strategy.with_authorize_url(fn(_config, _scopes, _state) {
    Ok("https://example.com")
  })
  |> strategy.with_exchange_code(fn(_config, _code, _code_verifier) {
    Error(error.ProviderError(
      code: "invalid_request",
      description: "provider-controlled phishing text secret-token",
      uri: option.None,
    ))
  })
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.ConfigError(reason: "test"))
  })
  |> strategy.with_fetch_user(fn(_config, _exchange) {
    Error(error.ConfigError(reason: "test"))
  })
}

fn test_config() -> config.Config {
  config.new(
    client_id: "client_id",
    client_secret: "client_secret",
    redirect_uri: "https://example.com/callback",
  )
}

pub fn callback_phase_default_error_response_does_not_render_provider_details_test() {
  let store = state_store.init_named("test_callback_generic_error_html")
  let session_id =
    state_store.store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(reg) =
    registry.new()
    |> registry.register(
      strategy: leaky_error_strategy(),
      config: test_config(),
    )

  let response =
    vestibule_wisp.callback_phase(
      req,
      reg: reg,
      provider: "test",
      state_store: store,
      on_success: fn(_auth) { wisp.html_response("success", 200) },
    )

  response.status |> expect.to_equal(400)
  let body = case response.body {
    wisp.Text(body) -> body
    _ -> panic as "expected text response body"
  }
  { string.contains(body, "secret-token") } |> expect.to_be_false()
  { string.contains(body, "provider-controlled phishing text") }
  |> expect.to_be_false()
  { string.contains(body, "Authentication failed") } |> expect.to_be_true()
}

pub fn callback_phase_auth_result_preserves_provider_error_details_test() {
  let store = state_store.init_named("test_callback_structured_error_details")
  let session_id =
    state_store.store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(reg) =
    registry.new()
    |> registry.register(
      strategy: leaky_error_strategy(),
      config: test_config(),
    )

  vestibule_wisp.callback_phase_auth_result(req, reg, "test", store)
  |> expect.to_equal(
    Error(
      vestibule_wisp.AuthFailed(error.ProviderError(
        code: "invalid_request",
        description: "provider-controlled phishing text secret-token",
        uri: option.None,
      )),
    ),
  )
}
