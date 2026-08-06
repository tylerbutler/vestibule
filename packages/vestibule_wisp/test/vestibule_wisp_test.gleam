import gleam/dict
import gleam/http
import gleam/http/request
import gleam/list
import gleam/option
import gleam/string
import gleeunit
import vestibule/config
import vestibule/error
import vestibule/registry
import vestibule/state_store
import vestibule/strategy.{type Strategy}
import vestibule_wisp
import wisp
import wisp/simulate

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn callback_phase_auth_result_unknown_provider_test() -> Nil {
  let req = simulate.request(http.Get, "/auth/unknown/callback")
  let assert Ok(store) =
    state_store.try_init_named("test_callback_unknown_provider")

  let result =
    vestibule_wisp.callback_phase_auth_result(
      req,
      registry.new(),
      "unknown",
      store,
    )
  assert result == Error(vestibule_wisp.UnknownProvider("unknown"))
}

pub fn callback_phase_auth_result_missing_session_cookie_test() -> Nil {
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
  let assert Ok(store) =
    state_store.try_init_named("test_callback_missing_session_cookie")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  let result =
    vestibule_wisp.callback_phase_auth_result(req, registry, "test", store)
  assert result
    == Error(vestibule_wisp.MissingOrInvalidSessionCookie(
      vestibule_wisp.CookieAbsent,
    ))
}

pub fn callback_phase_auth_result_tampered_cookie_reports_invalid_signature_test() -> Nil {
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie(
      "__Host-vestibule_session",
      "not-a-valid-signed-token",
      wisp.PlainText,
    )
  let assert Ok(store) =
    state_store.try_init_named("test_callback_tampered_session_cookie")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  let result =
    vestibule_wisp.callback_phase_auth_result(req, registry, "test", store)
  assert result
    == Error(vestibule_wisp.MissingOrInvalidSessionCookie(
      vestibule_wisp.CookieSignatureInvalid,
    ))
}

pub fn default_options_use_current_cookie_contract_test() -> Nil {
  let options = vestibule_wisp.default_options()
  assert vestibule_wisp.cookie_name(options) == "__Host-vestibule_session"
  assert vestibule_wisp.session_ttl_seconds(options) == 600
  assert vestibule_wisp.cookie_security(options) == vestibule_wisp.SecureOnly
}

pub fn cookie_name_is_unprefixed_when_insecure_test() -> Nil {
  let options =
    vestibule_wisp.default_options()
    |> vestibule_wisp.with_cookie_security(vestibule_wisp.AllowInsecure)
  assert vestibule_wisp.cookie_name(options) == "vestibule_session"
}

pub fn default_cookie_name_is_host_bound_test() -> Nil {
  let options = vestibule_wisp.default_options()
  assert vestibule_wisp.is_host_bound_cookie_name(vestibule_wisp.cookie_name(
    options,
  ))
}

pub fn with_cookie_name_applies_host_prefix_test() -> Nil {
  let options =
    vestibule_wisp.default_options()
    |> vestibule_wisp.with_cookie_name("custom_session")
  assert vestibule_wisp.cookie_name(options) == "__Host-custom_session"
}

pub fn with_cookie_name_does_not_double_prefix_test() -> Nil {
  let options =
    vestibule_wisp.default_options()
    |> vestibule_wisp.with_cookie_name("__Host-custom_session")
  assert vestibule_wisp.cookie_name(options) == "__Host-custom_session"
}

pub fn is_host_bound_cookie_name_rejects_non_prefixed_test() -> Nil {
  assert !vestibule_wisp.is_host_bound_cookie_name("vestibule_session")
}

pub fn is_host_bound_cookie_name_accepts_host_prefixed_test() -> Nil {
  assert vestibule_wisp.is_host_bound_cookie_name("__Host-custom_session")
}

pub fn request_phase_sets_host_bound_cookie_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_request_phase_host_bound_cookie")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())
  let req = simulate.request(http.Get, "/auth/test")

  let response =
    vestibule_wisp.request_phase(
      req,
      registry: registry,
      provider: "test",
      state_store: store,
      authorize_options: config.authorize_options(),
    )

  let set_cookie = case list.key_find(response.headers, "set-cookie") {
    Ok(value) -> value
    Error(_) -> panic as "expected a set-cookie header"
  }
  assert string.contains(set_cookie, "__Host-vestibule_session=")
  assert string.contains(set_cookie, "Secure")
  assert string.contains(set_cookie, "Path=/")
  assert !string.contains(set_cookie, "Domain=")
}

pub fn request_phase_over_plain_http_can_opt_out_of_host_binding_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_request_phase_insecure_cookie")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())
  let req = simulate.request(http.Get, "/auth/test") |> insecure_localhost

  let response =
    vestibule_wisp.request_phase_with_options(
      req,
      registry: registry,
      provider: "test",
      state_store: store,
      authorize_options: config.authorize_options(),
      middleware_options: vestibule_wisp.default_options()
        |> vestibule_wisp.with_cookie_security(vestibule_wisp.AllowInsecure),
    )

  let set_cookie = case list.key_find(response.headers, "set-cookie") {
    Ok(value) -> value
    Error(_) -> panic as "expected a set-cookie header"
  }
  // Wisp omits `Secure` for plain-HTTP localhost requests, and browsers reject
  // a `__Host-` cookie that is not `Secure` — so the name must not be
  // host-bound here or the session cookie is silently dropped.
  assert string.contains(set_cookie, "vestibule_session=")
  assert !string.contains(set_cookie, "__Host-")
  assert !string.contains(set_cookie, "Secure")
}

fn insecure_localhost(req: wisp.Request) -> wisp.Request {
  request.Request(..req, scheme: http.Http, host: "localhost")
}

pub fn request_phase_with_options_passes_authorize_options_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_request_phase_authorize_options")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(
      strategy: authorize_options_strategy(),
      config: test_config(),
    )
  let req = simulate.request(http.Get, "/auth/test")
  let assert Ok(authorize_options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "login")])

  let response =
    vestibule_wisp.request_phase_with_options(
      req,
      registry: registry,
      provider: "test",
      state_store: store,
      authorize_options: authorize_options,
      middleware_options: vestibule_wisp.default_options()
        |> vestibule_wisp.with_cookie_name("custom_session")
        |> vestibule_wisp.with_session_ttl_seconds(300),
    )

  let location = case list.key_find(response.headers, "location") {
    Ok(value) -> value
    Error(_) -> panic as "expected a location header"
  }
  assert string.contains(location, "prompt=login")

  let set_cookie = case list.key_find(response.headers, "set-cookie") {
    Ok(value) -> value
    Error(_) -> panic as "expected a set-cookie header"
  }
  assert string.contains(set_cookie, "__Host-custom_session=")
}

pub fn callback_phase_auth_result_with_options_uses_cookie_name_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_callback_custom_cookie_name")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  let result =
    vestibule_wisp.callback_phase_auth_result_with_options(
      req,
      registry,
      "test",
      store,
      vestibule_wisp.default_options()
        |> vestibule_wisp.with_cookie_name("custom_vestibule_session"),
    )
  assert result
    == Error(vestibule_wisp.MissingOrInvalidSessionCookie(
      vestibule_wisp.CookieAbsent,
    ))
}

pub fn callback_phase_auth_result_malformed_post_body_returns_invalid_params_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_callback_malformed_post_body")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Post, "/auth/test/callback?state=state&code=code")
    |> simulate.bit_array_body(<<255>>)
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  let result =
    vestibule_wisp.callback_phase_auth_result(req, registry, "test", store)
  assert result
    == Error(vestibule_wisp.InvalidCallbackParams(vestibule_wisp.BodyNotUtf8))
}

pub fn callback_phase_auth_result_missing_state_does_not_consume_session_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_callback_missing_state_reusable")
  let assert Ok(session_id) =
    state_store.try_store(
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
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  let missing_state_result =
    vestibule_wisp.callback_phase_auth_result(
      req_missing_state,
      registry,
      "test",
      store,
    )
  assert missing_state_result
    == Error(vestibule_wisp.AuthFailed(error.missing_callback_param("state")))

  let with_state_result =
    vestibule_wisp.callback_phase_auth_result(
      req_with_state,
      registry,
      "test",
      store,
    )
  assert with_state_result
    == Error(vestibule_wisp.AuthFailed(error.config(reason: "test")))
}

fn test_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: [],
    authorize_url: fn(_config, _options, _scopes, _state) {
      Ok("https://example.com")
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.config(reason: "test"))
    },
    fetch_user: fn(_config, _exchange) { Error(error.config(reason: "test")) },
  )
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.config(reason: "test"))
  })
}

fn leaky_error_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: [],
    authorize_url: fn(_config, _options, _scopes, _state) {
      Ok("https://example.com")
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.provider(
        code: "invalid_request",
        description: "provider-controlled phishing text secret-token",
        uri: option.None,
      ))
    },
    fetch_user: fn(_config, _exchange) { Error(error.config(reason: "test")) },
  )
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.config(reason: "test"))
  })
}

fn authorize_options_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: [],
    authorize_url: fn(_config, options, _scopes, _state) {
      case dict.get(config.extra_params(options), "prompt") {
        Ok(prompt) -> Ok("https://example.com?prompt=" <> prompt)
        Error(_) -> Ok("https://example.com")
      }
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.config(reason: "test"))
    },
    fetch_user: fn(_config, _exchange) { Error(error.config(reason: "test")) },
  )
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.config(reason: "test"))
  })
}

fn test_config() -> config.ClientConfig {
  config.new(
    client_id: "client_id",
    redirect_uri: "https://example.com/callback",
    auth: config.ClientSecret("client_secret"),
  )
}

pub fn callback_phase_default_error_response_does_not_render_provider_details_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_callback_generic_error_html")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(
      strategy: leaky_error_strategy(),
      config: test_config(),
    )

  let response =
    vestibule_wisp.callback_phase(
      req,
      registry: registry,
      provider: "test",
      state_store: store,
      on_success: fn(_auth) { wisp.html_response("success", 200) },
    )

  assert response.status == 400
  let body = case response.body {
    wisp.Text(body) -> body
    _ -> panic as "expected text response body"
  }
  assert !string.contains(body, "secret-token")
  assert !string.contains(body, "provider-controlled phishing text")
  assert string.contains(body, "Authentication failed")
}

pub fn callback_phase_auth_result_preserves_provider_error_details_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_callback_structured_error_details")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let req =
    simulate.request(http.Get, "/auth/test/callback?state=state&code=code")
    |> simulate.cookie("__Host-vestibule_session", session_id, wisp.Signed)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(
      strategy: leaky_error_strategy(),
      config: test_config(),
    )

  let result =
    vestibule_wisp.callback_phase_auth_result(req, registry, "test", store)
  assert result
    == Error(
      vestibule_wisp.AuthFailed(error.provider(
        code: "invalid_request",
        description: "provider-controlled phishing text secret-token",
        uri: option.None,
      )),
    )
}
