import gleam/bit_array
import gleam/dict
import gleam/dynamic
import gleam/dynamic/decode
import gleam/option.{None, Some}
import gleam/string
import startest
import startest/expect
import vestibule
import vestibule/auth
import vestibule/authorization_request
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/strategy.{type Strategy}
import vestibule/user_info

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// A fake strategy for testing the orchestrator
fn test_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: ["default_scope"],
    authorize_url: fn(_config, _options, scopes, state) {
      Ok(
        "https://test.com/auth?scope="
        <> string.join(scopes, " ")
        <> "&state="
        <> state,
      )
    },
    exchange_code: fn(_config, code, _code_verifier) {
      case code {
        "valid_code" ->
          Ok(
            strategy.exchange_result(
              credentials.new(
                token: "test_token",
                refresh_token: None,
                token_type: "bearer",
                expires_in: None,
                scopes: ["default_scope"],
              ),
            ),
          )
        _ -> Error(error.code_exchange(reason: "bad code"))
      }
    },
    fetch_user: fn(_client_config, exchange) {
      strategy.exchange_credentials(exchange)
      |> credentials.token()
      |> expect.to_equal("test_token")
      Ok(strategy.user_result(
        uid: "user123",
        info: user_info.new()
          |> user_info.with_name(Some("Test User"))
          |> user_info.with_email(Some("test@example.com")),
        extra: dict.from_list([
          #("raw_provider", dynamic.string("from-provider")),
        ]),
      ))
    },
  )
  |> strategy.with_refresh(fn(client_config, refresh_token) {
    Ok(
      credentials.new(
        token: "delegated:"
          <> refresh_token
          <> ":"
          <> config.client_id(client_config),
        refresh_token: Some("rotated_by_strategy"),
        token_type: "bearer",
        expires_in: Some(3600),
        scopes: ["delegated_scope"],
      ),
    )
  })
}

fn artifact_strategy() -> Strategy(e) {
  strategy.new(
    provider: "artifact",
    default_scopes: [],
    authorize_url: fn(_config, _options, _scopes, state) {
      Ok("https://test.com/auth?state=" <> state)
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Ok(strategy.exchange_result_with_artifacts(
        credentials.new(
          token: "artifact_token",
          refresh_token: None,
          token_type: "bearer",
          expires_in: None,
          scopes: [],
        ),
        dict.from_list([#("exchange_marker", dynamic.string("from-exchange"))]),
      ))
    },
    fetch_user: fn(_client_config, exchange) {
      let assert Ok(marker) =
        dict.get(strategy.exchange_artifacts(exchange), "exchange_marker")
      let assert Ok(decoded) = decode.run(marker, decode.string)
      Ok(strategy.user_result(
        uid: decoded,
        info: user_info.new(),
        extra: dict.new(),
      ))
    },
  )
  |> strategy.with_refresh(fn(_config, _refresh_token) {
    Error(error.config(reason: "refresh not implemented"))
  })
}

fn fragment_strategy() -> Strategy(e) {
  let base = test_strategy()
  strategy.new(
    provider: strategy.provider(base),
    default_scopes: strategy.default_scopes(base),
    authorize_url: fn(_config, _options, _scopes, state) {
      Ok(
        "https://test.com/auth?state="
        <> state
        <> "&existing=1#provider-fragment",
      )
    },
    exchange_code: fn(client_config, code, verifier) {
      strategy.exchange_code(
        base,
        config: client_config,
        code: code,
        code_verifier: verifier,
      )
    },
    fetch_user: fn(client_config, exchange) {
      strategy.fetch_user(base, config: client_config, exchange: exchange)
    },
  )
  |> strategy.with_refresh(fn(client_config, token) {
    strategy.refresh_token(base, config: client_config, refresh_token: token)
  })
}

pub fn create_authorization_request_returns_authorization_request_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(req) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(req)
  let state = authorization_request.state(req)
  let verifier = authorization_request.code_verifier(req)
  // URL should contain the state
  { string.contains(url, state) } |> expect.to_be_true()
  // State should be non-empty
  { string.length(state) >= 43 } |> expect.to_be_true()
  // Code verifier should be non-empty
  { string.length(verifier) >= 43 } |> expect.to_be_true()
  // URL should contain PKCE params
  { string.contains(url, "code_challenge=") } |> expect.to_be_true()
  { string.contains(url, "code_challenge_method=S256") } |> expect.to_be_true()
  // A plain OAuth2 strategy (uses_nonce: False) must not emit a nonce.
  { string.contains(url, "nonce=") } |> expect.to_be_false()
  { option.is_none(authorization_request.nonce(req)) } |> expect.to_be_true()
}

pub fn create_authorization_request_emits_nonce_for_oidc_strategy_test() -> Nil {
  let strategy = nonce_strategy(make_id_token("{\"sub\":\"user123\"}"))
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(req) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(req)
  // OIDC strategy emits a nonce in the URL and stores it for validation.
  { string.contains(url, "nonce=") } |> expect.to_be_true()
  let assert Some(value) = authorization_request.nonce(req)
  { string.contains(url, value) } |> expect.to_be_true()
  { string.length(value) >= 43 } |> expect.to_be_true()
}

pub fn create_authorization_request_appends_pkce_before_url_fragment_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(req) =
    vestibule.create_authorization_request(
      fragment_strategy(),
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(req)

  { string.contains(url, "&existing=1&code_challenge=") }
  |> expect.to_be_true()
  { string.contains(url, "code_challenge_method=S256#provider-fragment") }
  |> expect.to_be_true()
}

pub fn create_authorization_request_uses_config_scopes_when_present_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let options =
    config.authorize_options()
    |> config.with_scopes(["custom_scope"])
  let assert Ok(req) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: options,
    )
  let url = authorization_request.url(req)
  { string.contains(url, "custom_scope") } |> expect.to_be_true()
  { string.contains(url, "default_scope") } |> expect.to_be_false()
}

pub fn create_authorization_request_uses_default_scopes_when_config_empty_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(req) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(req)
  { string.contains(url, "default_scope") } |> expect.to_be_true()
}

pub fn handle_callback_succeeds_with_valid_params_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let state = "test_state_value"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: params,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let assert Ok(authed) = result
  auth.uid(authed) |> expect.to_equal("user123")
  auth.provider(authed) |> expect.to_equal("test")
  user_info.name(auth.info(authed)) |> expect.to_equal(Some("Test User"))
  credentials.token(auth.credentials(authed)) |> expect.to_equal("test_token")
}

pub fn handle_callback_populates_auth_extra_from_strategy_user_result_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let state = "test_state_value"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])

  let assert Ok(authed) =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: params,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let assert Ok(raw_provider) = dict.get(auth.extra(authed), "raw_provider")
  decode.run(raw_provider, decode.string)
  |> expect.to_equal(Ok("from-provider"))
}

pub fn handle_callback_passes_exchange_artifacts_to_fetch_user_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let state = "test_state_value"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])

  let assert Ok(authed) =
    vestibule.handle_callback(
      artifact_strategy(),
      config: client_config,
      callback_params: params,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )

  auth.uid(authed) |> expect.to_equal("from-exchange")
  credentials.token(auth.credentials(authed))
  |> expect.to_equal("artifact_token")
}

pub fn refresh_token_delegates_to_strategy_refresh_token_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "client-id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )

  vestibule.refresh_token(
    strategy,
    config: client_config,
    refresh_token: "refresh-123",
  )
  |> expect.to_equal(
    Ok(
      credentials.new(
        token: "delegated:refresh-123:client-id",
        refresh_token: Some("rotated_by_strategy"),
        token_type: "bearer",
        expires_in: Some(3600),
        scopes: ["delegated_scope"],
      ),
    ),
  )
}

pub fn handle_callback_fails_on_state_mismatch_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let params = dict.from_list([#("code", "valid_code"), #("state", "wrong")])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: params,
      expected_state: "expected",
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn missing_callback_state_is_structured_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let params = dict.from_list([#("code", "valid_code")])

  vestibule.handle_callback(
    strategy,
    config: client_config,
    callback_params: params,
    expected_state: "expected",
    code_verifier: "test_verifier",
    expected_nonce: None,
  )
  |> expect.to_equal(Error(error.missing_callback_param("state")))
}

pub fn handle_callback_fails_on_missing_code_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let state = "test_state"
  let params = dict.from_list([#("state", state)])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: params,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn missing_callback_code_is_structured_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let state = "test_state"
  let params = dict.from_list([#("state", state)])

  vestibule.handle_callback(
    strategy,
    config: client_config,
    callback_params: params,
    expected_state: state,
    code_verifier: "test_verifier",
    expected_nonce: None,
  )
  |> expect.to_equal(Error(error.missing_callback_param("code")))
}

pub fn logging_does_not_change_core_result_shapes_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(req) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let params =
    dict.from_list([
      #("code", "valid_code"),
      #("state", authorization_request.state(req)),
    ])

  let _ =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: params,
      expected_state: authorization_request.state(req),
      code_verifier: authorization_request.code_verifier(req),
      expected_nonce: None,
    )
    |> expect.to_be_ok()

  let _ =
    vestibule.refresh_token(
      strategy,
      config: client_config,
      refresh_token: "refresh-123",
    )
    |> expect.to_be_ok()
  Nil
}

// --- OIDC nonce validation ---

/// A strategy that uses the OIDC nonce and returns `id_token` in artifacts.
fn nonce_strategy(id_token: String) -> Strategy(e) {
  strategy.new(
    provider: "nonce-test",
    default_scopes: ["openid"],
    authorize_url: fn(_config, _options, _scopes, state) {
      Ok("https://test.com/auth?state=" <> state)
    },
    exchange_code: fn(_config, code, _code_verifier) {
      case code {
        "valid_code" ->
          Ok(strategy.exchange_result_with_artifacts(
            credentials.new(
              token: "test_token",
              refresh_token: None,
              token_type: "bearer",
              expires_in: None,
              scopes: ["openid"],
            ),
            id_token_artifacts(id_token),
          ))
        _ -> Error(error.code_exchange(reason: "bad code"))
      }
    },
    fetch_user: fn(_client_config, _exchange) {
      Ok(strategy.user_result(
        uid: "user123",
        info: user_info.new(),
        extra: dict.new(),
      ))
    },
  )
  |> strategy.with_nonce()
}

/// A nonce strategy whose exchange returns no `id_token` artifact.
fn nonce_strategy_without_id_token() -> Strategy(e) {
  strategy.new(
    provider: "nonce-test",
    default_scopes: ["openid"],
    authorize_url: fn(_config, _options, _scopes, state) {
      Ok("https://test.com/auth?state=" <> state)
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Ok(
        strategy.exchange_result(
          credentials.new(
            token: "test_token",
            refresh_token: None,
            token_type: "bearer",
            expires_in: None,
            scopes: ["openid"],
          ),
        ),
      )
    },
    fetch_user: fn(_client_config, _exchange) {
      Ok(strategy.user_result(
        uid: "user123",
        info: user_info.new(),
        extra: dict.new(),
      ))
    },
  )
  |> strategy.with_nonce()
}

fn id_token_artifacts(id_token: String) -> dict.Dict(String, dynamic.Dynamic) {
  dict.from_list([#("id_token", dynamic.string(id_token))])
}

/// Build a JWT-shaped id_token whose payload is the given JSON object.
/// The signature is not verified, so a placeholder segment is fine.
fn make_id_token(payload_json: String) -> String {
  let payload = bit_array.base64_url_encode(<<payload_json:utf8>>, False)
  "header." <> payload <> ".signature"
}

fn nonce_config() -> config.ClientConfig {
  config.new(
    client_id: "id",
    auth: config.ClientSecret("secret"),
    redirect_uri: "http://localhost/cb",
  )
}

fn nonce_params() -> dict.Dict(String, String) {
  dict.from_list([#("code", "valid_code"), #("state", "expected")])
}

pub fn handle_callback_accepts_matching_nonce_test() -> Nil {
  let id_token = make_id_token("{\"sub\":\"user123\",\"nonce\":\"the-nonce\"}")
  let strategy = nonce_strategy(id_token)
  let _ =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_params(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: Some("the-nonce"),
    )
    |> expect.to_be_ok()
  Nil
}

pub fn handle_callback_rejects_mismatched_nonce_test() -> Nil {
  let id_token =
    make_id_token("{\"sub\":\"user123\",\"nonce\":\"wrong-nonce\"}")
  let strategy = nonce_strategy(id_token)
  vestibule.handle_callback(
    strategy,
    config: nonce_config(),
    callback_params: nonce_params(),
    expected_state: "expected",
    code_verifier: "verifier",
    expected_nonce: Some("the-nonce"),
  )
  |> result_error_kind()
  |> expect.to_equal(Some(error.invalid_nonce()))
}

pub fn handle_callback_rejects_missing_nonce_claim_test() -> Nil {
  let id_token = make_id_token("{\"sub\":\"user123\"}")
  let strategy = nonce_strategy(id_token)
  vestibule.handle_callback(
    strategy,
    config: nonce_config(),
    callback_params: nonce_params(),
    expected_state: "expected",
    code_verifier: "verifier",
    expected_nonce: Some("the-nonce"),
  )
  |> result_error_kind()
  |> expect.to_equal(Some(error.invalid_nonce()))
}

pub fn handle_callback_rejects_missing_id_token_when_nonce_expected_test() -> Nil {
  let strategy = nonce_strategy_without_id_token()
  vestibule.handle_callback(
    strategy,
    config: nonce_config(),
    callback_params: nonce_params(),
    expected_state: "expected",
    code_verifier: "verifier",
    expected_nonce: Some("the-nonce"),
  )
  |> result_error_kind()
  |> expect.to_equal(Some(error.invalid_nonce()))
}

pub fn handle_callback_skips_nonce_for_plain_oauth_strategy_test() -> Nil {
  // uses_nonce: False strategy ignores any id_token nonce entirely.
  let strategy = test_strategy()
  let _ =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_params(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: None,
    )
    |> expect.to_be_ok()
  Nil
}

/// Reduce a callback result to just the error variant, dropping the success
/// payload (which contains a closure that cannot be structurally compared).
fn result_error_kind(
  result: Result(a, error.AuthError(e)),
) -> option.Option(error.AuthError(e)) {
  case result {
    Ok(_) -> None
    Error(err) -> Some(err)
  }
}

pub fn handle_callback_rejects_missing_expected_nonce_for_nonce_strategy_test() -> Nil {
  // A strategy that uses a nonce must never fall open when the caller has
  // no stored nonce to compare against; that would silently drop id_token
  // replay protection.
  let strategy = nonce_strategy(make_id_token("{\"nonce\":\"the-nonce\"}"))
  let result =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_params(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: None,
    )
  let assert Error(err) = result
  error.kind(err) |> expect.to_equal(error.InvalidNonceKind)
}
