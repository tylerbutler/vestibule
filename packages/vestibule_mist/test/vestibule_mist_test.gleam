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

pub fn signed_cookie_round_trip_test() -> Nil {
  let secret = test_secret()
  let token =
    signed_cookie.sign(payload: "session-id-123", secret_key_base: secret)
  signed_cookie.verify(token: token, secret_key_base: secret)
  |> expect.to_be_ok()
  |> expect.to_equal("session-id-123")
}

pub fn signed_cookie_verify_with_wrong_secret_fails_test() -> Nil {
  let secret = test_secret()
  let other = <<"different-key-also-32-bytes-long":utf8>>
  let token =
    signed_cookie.sign(payload: "session-id-123", secret_key_base: secret)
  let _ =
    signed_cookie.verify(token: token, secret_key_base: other)
    |> expect.to_be_error()
  Nil
}

pub fn signed_cookie_verify_with_tampered_token_fails_test() -> Nil {
  let secret = test_secret()
  let token =
    signed_cookie.sign(payload: "session-id-123", secret_key_base: secret)
  let _ =
    signed_cookie.verify(token: token <> "x", secret_key_base: secret)
    |> expect.to_be_error()
  Nil
}

pub fn signed_cookie_verify_malformed_token_fails_test() -> Nil {
  let _ =
    signed_cookie.verify(
      token: "not-a-valid-token",
      secret_key_base: test_secret(),
    )
    |> expect.to_be_error()
  Nil
}

// === options ===

pub fn new_options_uses_default_cookie_contract_test() -> Nil {
  let assert Ok(options) = vestibule_mist.new_options(test_secret())
  vestibule_mist.cookie_name(options)
  |> expect.to_equal("__Host-vestibule_session")
  vestibule_mist.session_ttl_seconds(options) |> expect.to_equal(600)
  vestibule_mist.cookie_security(options)
  |> expect.to_equal(vestibule_mist.SecureOnly)
}

pub fn with_cookie_name_applies_host_prefix_test() -> Nil {
  test_options()
  |> vestibule_mist.with_cookie_name("custom_session")
  |> vestibule_mist.cookie_name
  |> expect.to_equal("__Host-custom_session")
}

pub fn with_cookie_name_does_not_double_prefix_test() -> Nil {
  test_options()
  |> vestibule_mist.with_cookie_name("__Host-custom_session")
  |> vestibule_mist.cookie_name
  |> expect.to_equal("__Host-custom_session")
}

pub fn cookie_name_is_unprefixed_when_insecure_test() -> Nil {
  test_options()
  |> vestibule_mist.with_cookie_security(vestibule_mist.AllowInsecure)
  |> vestibule_mist.cookie_name
  |> expect.to_equal("vestibule_session")
}

// === request_phase ===

pub fn request_phase_unknown_provider_returns_404_test() -> Nil {
  let req = request.new() |> request.set_path("/auth/unknown")
  let assert Ok(store) =
    state_store.try_init_named("test_mist_request_unknown_provider")

  let resp =
    vestibule_mist.request_phase(
      req,
      registry.new(),
      "unknown",
      store,
      config.authorize_options(),
      test_options(),
    )

  resp.status |> expect.to_equal(404)
}

pub fn request_phase_success_sets_signed_cookie_and_redirects_test() -> Nil {
  let req = request.new() |> request.set_path("/auth/test")
  let assert Ok(store) = state_store.try_init_named("test_mist_request_success")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  let resp =
    vestibule_mist.request_phase(
      req,
      registry,
      "test",
      store,
      config.authorize_options(),
      test_options(),
    )

  resp.status |> expect.to_equal(302)
  let assert Ok(_location) = find_header(resp.headers, "location")
  let assert Ok(cookie_header) = find_header(resp.headers, "set-cookie")
  { string.contains(cookie_header, "__Host-vestibule_session=") }
  |> expect.to_be_true()
  { string.contains(cookie_header, "HttpOnly") } |> expect.to_be_true()
  { string.contains(cookie_header, "SameSite=Lax") } |> expect.to_be_true()
  { string.contains(cookie_header, "Path=/") } |> expect.to_be_true()
  { string.contains(cookie_header, "Secure") } |> expect.to_be_true()
}

pub fn request_phase_allows_secure_cookie_opt_out_test() -> Nil {
  let req =
    request.new()
    |> request.set_path("/auth/test")
  let assert Ok(store) =
    state_store.try_init_named("test_mist_request_secure_cookie_opt_out")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())
  let options =
    test_options()
    |> vestibule_mist.with_cookie_security(vestibule_mist.AllowInsecure)

  let resp =
    vestibule_mist.request_phase(
      req,
      registry,
      "test",
      store,
      config.authorize_options(),
      options,
    )

  let assert Ok(cookie_header) = find_header(resp.headers, "set-cookie")
  { string.contains(cookie_header, "vestibule_session=") }
  |> expect.to_be_true()
  { string.contains(cookie_header, "__Host-") } |> expect.to_be_false()
  { string.contains(cookie_header, "Secure") } |> expect.to_be_false()
}

pub fn request_phase_passes_authorize_options_test() -> Nil {
  let req = request.new() |> request.set_path("/auth/test")
  let assert Ok(store) =
    state_store.try_init_named("test_mist_request_authorize_options")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(
      strategy: authorize_options_strategy(),
      config: test_config(),
    )
  let assert Ok(authorize_options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "login")])

  let resp =
    vestibule_mist.request_phase(
      req,
      registry,
      "test",
      store,
      authorize_options,
      test_options(),
    )

  let assert Ok(location) = find_header(resp.headers, "location")
  { string.contains(location, "prompt=login") } |> expect.to_be_true()
}

// === callback_phase_auth_result_with_params ===

pub fn callback_unknown_provider_test() -> Nil {
  let req = request.new()
  let assert Ok(store) =
    state_store.try_init_named("test_mist_cb_unknown_provider")

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

pub fn callback_missing_session_cookie_test() -> Nil {
  let req = request.new()
  let assert Ok(store) =
    state_store.try_init_named("test_mist_cb_missing_cookie")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "s"), #("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.MissingOrInvalidSessionCookie(
      vestibule_mist.CookieAbsent,
    )),
  )
}

pub fn callback_tampered_cookie_reports_invalid_signature_test() -> Nil {
  let req =
    request.new()
    |> request.set_cookie(
      "__Host-vestibule_session",
      "not-a-valid-signed-token",
    )
  let assert Ok(store) =
    state_store.try_init_named("test_mist_cb_tampered_cookie")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "s"), #("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.MissingOrInvalidSessionCookie(
      vestibule_mist.CookieSignatureInvalid,
    )),
  )
}

pub fn callback_wrong_secret_reports_invalid_signature_test() -> Nil {
  let assert Ok(store) = state_store.try_init_named("test_mist_cb_wrong_secret")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      provider: "test",
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let other_secret = <<"some-other-secret-key-base!!!!!!":utf8>>
  let token =
    signed_cookie.sign(payload: session_id, secret_key_base: other_secret)
  let req =
    request.new()
    |> request.set_cookie("__Host-vestibule_session", token)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.MissingOrInvalidSessionCookie(
      vestibule_mist.CookieSignatureInvalid,
    )),
  )
}

pub fn callback_missing_state_does_not_consume_session_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_mist_cb_missing_state_reusable")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      provider: "test",
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let token =
    signed_cookie.sign(payload: session_id, secret_key_base: test_secret())
  let req =
    request.new()
    |> request.set_cookie("__Host-vestibule_session", token)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.AuthFailed(error.missing_callback_param("state"))),
  )

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.AuthFailed(error.config(reason: "test"))),
  )
}

pub fn callback_unknown_session_returns_expired_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_mist_cb_unknown_session")
  let token =
    signed_cookie.sign(
      payload: "nonexistent-session",
      secret_key_base: test_secret(),
    )
  let req =
    request.new()
    |> request.set_cookie("__Host-vestibule_session", token)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "s"), #("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(Error(vestibule_mist.SessionUnavailable))
}

pub fn callback_auth_result_preserves_provider_error_details_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_mist_cb_structured_error_details")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      provider: "test",
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let token =
    signed_cookie.sign(payload: session_id, secret_key_base: test_secret())
  let req =
    request.new()
    |> request.set_cookie("__Host-vestibule_session", token)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(
      strategy: leaky_error_strategy(),
      config: test_config(),
    )

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(
      vestibule_mist.AuthFailed(error.provider(
        code: "invalid_request",
        description: "provider-controlled phishing text secret-token",
        uri: option.None,
      )),
    ),
  )
}

pub fn callback_custom_cookie_name_is_honored_test() -> Nil {
  let assert Ok(store) =
    state_store.try_init_named("test_mist_cb_custom_cookie_name")
  let assert Ok(session_id) =
    state_store.try_store(
      store,
      provider: "test",
      state: "state",
      code_verifier: "verifier",
      nonce: option.None,
    )
  let token =
    signed_cookie.sign(payload: session_id, secret_key_base: test_secret())
  let req =
    request.new()
    |> request.set_cookie("__Host-custom_session", token)
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    registry,
    "test",
    store,
    test_options(),
  )
  |> expect.to_equal(
    Error(vestibule_mist.MissingOrInvalidSessionCookie(
      vestibule_mist.CookieAbsent,
    )),
  )

  let custom_options =
    test_options() |> vestibule_mist.with_cookie_name("custom_session")

  vestibule_mist.callback_phase_auth_result_with_params(
    req,
    dict.from_list([#("state", "state"), #("code", "c")]),
    registry,
    "test",
    store,
    custom_options,
  )
  |> expect.to_equal(
    Error(vestibule_mist.AuthFailed(error.config(reason: "test"))),
  )
}

// === helpers ===

fn test_secret() -> BitArray {
  <<"vestibule_mist_test_secret_key_base!!":utf8>>
}

fn test_options() -> vestibule_mist.Options {
  let assert Ok(options) = vestibule_mist.new_options(test_secret())
  options
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

fn find_header(
  headers: List(#(String, String)),
  name: String,
) -> Result(String, Nil) {
  list.key_find(headers, name)
}

// === secret_key_base minimum ===

pub fn new_options_rejects_short_secret_test() -> Nil {
  vestibule_mist.new_options(<<>>)
  |> expect.to_equal(
    Error(vestibule_mist.SecretKeyBaseTooShort(
      minimum_bytes: 32,
      actual_bytes: 0,
    )),
  )
  vestibule_mist.new_options(<<"0123456789abcdef0123456789abcde":utf8>>)
  |> expect.to_be_error()
  Nil
}

pub fn new_options_accepts_minimum_length_secret_test() -> Nil {
  let _ =
    vestibule_mist.new_options(<<"0123456789abcdef0123456789abcdef":utf8>>)
    |> expect.to_be_ok()
  Nil
}

// === SameSite ===

pub fn request_phase_cross_site_cookie_sets_same_site_none_and_secure_test() -> Nil {
  let req = request.new() |> request.set_path("/auth/test")
  let assert Ok(store) = state_store.try_init_named("test_mist_cross_site")
  let assert Ok(registry) =
    registry.new()
    |> registry.register(strategy: test_strategy(), config: test_config())

  let resp =
    vestibule_mist.request_phase(
      req,
      registry,
      "test",
      store,
      config.authorize_options(),
      test_options()
        |> vestibule_mist.with_cookie_security(vestibule_mist.AllowInsecure)
        |> vestibule_mist.with_same_site(vestibule_mist.CrossSite),
    )

  let assert Ok(cookie_header) = find_header(resp.headers, "set-cookie")
  { string.contains(cookie_header, "SameSite=None") } |> expect.to_be_true()
  // SameSite=None is only honoured by browsers with Secure, even when the
  // caller opted out of Secure for local development.
  { string.contains(cookie_header, "Secure") } |> expect.to_be_true()
}

pub fn same_site_defaults_to_lax_test() -> Nil {
  vestibule_mist.same_site(test_options())
  |> expect.to_equal(vestibule_mist.Lax)
}
