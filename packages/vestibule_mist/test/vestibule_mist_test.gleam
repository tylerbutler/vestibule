import gleam/dict
import gleam/http/request
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
import vestibule_mist
import vestibule_mist/signed_cookie

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// === signed_cookie ===

pub fn signed_cookie_round_trip_test() {
  let secret = test_secret()
  let token = signed_cookie.sign("session-id-123", secret)
  signed_cookie.verify(token, secret)
  |> expect.to_be_ok()
  |> expect.to_equal("session-id-123")
}

pub fn signed_cookie_verify_with_wrong_secret_fails_test() {
  let secret = test_secret()
  let other = <<"different-key-also-32-bytes-long":utf8>>
  let token = signed_cookie.sign("session-id-123", secret)
  signed_cookie.verify(token, other)
  |> expect.to_be_error()
}

pub fn signed_cookie_verify_with_tampered_token_fails_test() {
  let secret = test_secret()
  let token = signed_cookie.sign("session-id-123", secret)
  signed_cookie.verify(token <> "x", secret)
  |> expect.to_be_error()
}

pub fn signed_cookie_verify_malformed_token_fails_test() {
  signed_cookie.verify("not-a-valid-token", test_secret())
  |> expect.to_be_error()
}

// === new_options ===

pub fn new_options_uses_default_cookie_contract_test() {
  let secret = test_secret()
  vestibule_mist.new_options(secret)
  |> expect.to_equal(vestibule_mist.Options(
    secret_key_base: secret,
    cookie_name: "vestibule_session",
    session_ttl_seconds: 600,
    secure_cookie: True,
  ))
}

// === request_phase ===

pub fn request_phase_unknown_provider_returns_404_test() {
  let req = request.new() |> request.set_path("/auth/unknown")
  let store = state_store.init_named("test_mist_request_unknown_provider")

  let resp =
    vestibule_mist.request_phase(
      req,
      registry.new(),
      "unknown",
      store,
      test_options(),
    )

  resp.status |> expect.to_equal(404)
}

pub fn request_phase_success_sets_signed_cookie_and_redirects_test() {
  let req = request.new() |> request.set_path("/auth/test")
  let store = state_store.init_named("test_mist_request_success")
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  let resp =
    vestibule_mist.request_phase(req, reg, "test", store, test_options())

  resp.status |> expect.to_equal(302)
  let assert Ok(_location) = find_header(resp.headers, "location")
  let assert Ok(cookie_header) = find_header(resp.headers, "set-cookie")
  { string.contains(cookie_header, "vestibule_session=") }
  |> expect.to_be_true()
  { string.contains(cookie_header, "HttpOnly") } |> expect.to_be_true()
  { string.contains(cookie_header, "SameSite=Lax") } |> expect.to_be_true()
  { string.contains(cookie_header, "Path=/") } |> expect.to_be_true()
  { string.contains(cookie_header, "Secure") } |> expect.to_be_true()
}

pub fn request_phase_allows_secure_cookie_opt_out_test() {
  let req =
    request.new()
    |> request.set_path("/auth/test")
  let store = state_store.init_named("test_mist_request_secure_cookie_opt_out")
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())
  let options = vestibule_mist.Options(..test_options(), secure_cookie: False)

  let resp = vestibule_mist.request_phase(req, reg, "test", store, options)

  let assert Ok(cookie_header) = find_header(resp.headers, "set-cookie")
  { string.contains(cookie_header, "Secure") } |> expect.to_be_false()
}

// === callback_phase_auth_result_with_params ===

pub fn callback_unknown_provider_test() {
  let req = request.new()
  let store = state_store.init_named("test_mist_cb_unknown_provider")

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "s"), #("code", "c")]),
    registry.new(),
    "unknown",
    store,
    test_options(),
  )
  |> expect.to_equal(Error(vestibule_mist.UnknownProvider("unknown")))
}

pub fn callback_missing_session_cookie_test() {
  let req = request.new()
  let store = state_store.init_named("test_mist_cb_missing_cookie")
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "s"), #("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(Error(vestibule_mist.MissingOrInvalidSessionCookie))
}

pub fn callback_tampered_cookie_fails_as_missing_test() {
  let req =
    request.new()
    |> request.set_cookie("vestibule_session", "not-a-valid-signed-token")
  let store = state_store.init_named("test_mist_cb_tampered_cookie")
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "s"), #("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(Error(vestibule_mist.MissingOrInvalidSessionCookie))
}

pub fn callback_wrong_secret_fails_as_missing_test() {
  let store = state_store.init_named("test_mist_cb_wrong_secret")
  let session_id = state_store.store(store, "state", "verifier")
  let other_secret = <<"some-other-secret-key-base!!!!!!":utf8>>
  let token = signed_cookie.sign(session_id, other_secret)
  let req =
    request.new()
    |> request.set_cookie("vestibule_session", token)
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(Error(vestibule_mist.MissingOrInvalidSessionCookie))
}

pub fn callback_missing_state_does_not_consume_session_test() {
  let store = state_store.init_named("test_mist_cb_missing_state_reusable")
  let session_id = state_store.store(store, "state", "verifier")
  let token = signed_cookie.sign(session_id, test_secret())
  let req =
    request.new()
    |> request.set_cookie("vestibule_session", token)
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.AuthFailed(error.MissingCallbackParam("state"))),
  )

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.AuthFailed(error.ConfigError(reason: "test"))),
  )
}

pub fn callback_unknown_session_returns_expired_test() {
  let store = state_store.init_named("test_mist_cb_unknown_session")
  let token = signed_cookie.sign("nonexistent-session", test_secret())
  let req =
    request.new()
    |> request.set_cookie("vestibule_session", token)
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "s"), #("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(Error(vestibule_mist.SessionUnavailable))
}

pub fn callback_auth_result_preserves_provider_error_details_test() {
  let store = state_store.init_named("test_mist_cb_structured_error_details")
  let session_id = state_store.store(store, "state", "verifier")
  let token = signed_cookie.sign(session_id, test_secret())
  let req =
    request.new()
    |> request.set_cookie("vestibule_session", token)
  let reg =
    registry.new()
    |> registry.register(leaky_error_strategy(), test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(
      vestibule_mist.AuthFailed(error.ProviderError(
        code: "invalid_request",
        description: "provider-controlled phishing text secret-token",
        uri: option.None,
      )),
    ),
  )
}

pub fn callback_custom_cookie_name_is_honored_test() {
  let store = state_store.init_named("test_mist_cb_custom_cookie_name")
  let session_id = state_store.store(store, "state", "verifier")
  let token = signed_cookie.sign(session_id, test_secret())
  let req =
    request.new()
    |> request.set_cookie("custom_session", token)
  let reg =
    registry.new()
    |> registry.register(test_strategy(), test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    reg,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(Error(vestibule_mist.MissingOrInvalidSessionCookie))

  let custom_options =
    vestibule_mist.Options(..test_options(), cookie_name: "custom_session")

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    reg,
    "test",
    store,
    custom_options,
  )
  |> expect.to_equal(
    Error(vestibule_mist.AuthFailed(error.ConfigError(reason: "test"))),
  )
}

// === helpers ===

fn test_secret() -> BitArray {
  <<"vestibule_mist_test_secret_key_base!!":utf8>>
}

fn test_options() -> vestibule_mist.Options {
  vestibule_mist.new_options(test_secret())
}

fn test_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: [],
    authorize_url: fn(_config, _scopes, _state) { Ok("https://example.com") },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.ConfigError(reason: "test"))
    },
    refresh_token: fn(_config, _refresh_token) {
      Error(error.ConfigError(reason: "test"))
    },
    fetch_user: fn(_config, _exchange) {
      Error(error.ConfigError(reason: "test"))
    },
  )
}

fn leaky_error_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: [],
    authorize_url: fn(_config, _scopes, _state) { Ok("https://example.com") },
    exchange_code: fn(_config, _code, _code_verifier) {
      Error(error.ProviderError(
        code: "invalid_request",
        description: "provider-controlled phishing text secret-token",
        uri: option.None,
      ))
    },
    refresh_token: fn(_config, _refresh_token) {
      Error(error.ConfigError(reason: "test"))
    },
    fetch_user: fn(_config, _exchange) {
      Error(error.ConfigError(reason: "test"))
    },
  )
}

fn test_config() -> config.Config {
  config.new("client_id", "client_secret", "https://example.com/callback")
}

fn find_header(
  headers: List(#(String, String)),
  name: String,
) -> Result(String, Nil) {
  list.key_find(headers, name)
}
