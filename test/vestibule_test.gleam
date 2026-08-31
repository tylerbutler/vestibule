import gleam/bit_array
import gleam/dict
import gleam/dynamic
import gleam/dynamic/decode
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import vestibule
import vestibule/auth
import vestibule/authorization_request
import vestibule/config
import vestibule/credential
import vestibule/error
import vestibule/strategy.{type Strategy}
import vestibule/user_info

pub fn main() -> Nil {
  gleeunit.main()
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
              credential.new(
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
      assert credential.token(strategy.exchange_credentials(exchange))
        == "test_token"
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
      credential.new(
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
        credential.new(
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
  let assert Ok(authorization_request_value) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(authorization_request_value)
  let state = authorization_request.state(authorization_request_value)
  let verifier =
    authorization_request.code_verifier(authorization_request_value)
  // URL should contain the state
  assert string.contains(url, state)
  // State should be non-empty
  assert string.length(state) >= 43
  // Code verifier should be non-empty
  assert string.length(verifier) >= 43
  // URL should contain PKCE parameters
  assert string.contains(url, "code_challenge=")
  assert string.contains(url, "code_challenge_method=S256")
  // A plain OAuth2 strategy (uses_nonce: False) must not emit a nonce.
  assert !string.contains(url, "nonce=")
  assert option.is_none(authorization_request.nonce(authorization_request_value))
}

pub fn create_authorization_request_emits_nonce_for_oidc_strategy_test() -> Nil {
  let strategy = nonce_strategy(make_id_token("{\"sub\":\"user123\"}"))
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(authorization_request_value) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(authorization_request_value)
  // OIDC strategy emits a nonce in the URL and stores it for validation.
  assert string.contains(url, "nonce=")
  let assert Some(value) =
    authorization_request.nonce(authorization_request_value)
  assert string.contains(url, value)
  assert string.length(value) >= 43
}

pub fn create_authorization_request_appends_pkce_before_url_fragment_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(authorization_request_value) =
    vestibule.create_authorization_request(
      fragment_strategy(),
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(authorization_request_value)

  assert string.contains(url, "&existing=1&code_challenge=")
  assert string.contains(url, "code_challenge_method=S256#provider-fragment")
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
  let assert Ok(authorization_request_value) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: options,
    )
  let url = authorization_request.url(authorization_request_value)
  assert string.contains(url, "custom_scope")
  assert !string.contains(url, "default_scope")
}

pub fn create_authorization_request_uses_default_scopes_when_config_empty_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(authorization_request_value) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let url = authorization_request.url(authorization_request_value)
  assert string.contains(url, "default_scope")
}

pub fn handle_callback_succeeds_with_valid_parameters_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let state = "test_state_value"
  let parameters = dict.from_list([#("code", "valid_code"), #("state", state)])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let assert Ok(authed) = result
  assert auth.uid(authed) == "user123"
  assert auth.provider(authed) == "test"
  assert user_info.name(auth.info(authed)) == Some("Test User")
  assert credential.token(auth.credentials(authed)) == "test_token"
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
  let parameters = dict.from_list([#("code", "valid_code"), #("state", state)])

  let assert Ok(authed) =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let assert Ok(raw_provider) = dict.get(auth.extra(authed), "raw_provider")
  assert decode.run(raw_provider, decode.string) == Ok("from-provider")
}

pub fn handle_callback_passes_exchange_artifacts_to_fetch_user_test() -> Nil {
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let state = "test_state_value"
  let parameters = dict.from_list([#("code", "valid_code"), #("state", state)])

  let assert Ok(authed) =
    vestibule.handle_callback(
      artifact_strategy(),
      config: client_config,
      callback_params: parameters,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )

  assert auth.uid(authed) == "from-exchange"
  assert credential.token(auth.credentials(authed)) == "artifact_token"
}

pub fn refresh_token_delegates_to_strategy_refresh_token_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "client-id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )

  let refreshed =
    vestibule.refresh_token(
      strategy,
      config: client_config,
      refresh_token: "refresh-123",
    )
  assert refreshed
    == Ok(
      credential.new(
        token: "delegated:refresh-123:client-id",
        refresh_token: Some("rotated_by_strategy"),
        token_type: "bearer",
        expires_in: Some(3600),
        scopes: ["delegated_scope"],
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
  let parameters =
    dict.from_list([#("code", "valid_code"), #("state", "wrong")])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: "expected",
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let assert Error(_) = result
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
  let parameters = dict.from_list([#("code", "valid_code")])

  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: "expected",
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  assert result == Error(error.missing_callback_param("state"))
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
  let parameters = dict.from_list([#("state", state)])
  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  let assert Error(_) = result
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
  let parameters = dict.from_list([#("state", state)])

  let result =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: state,
      code_verifier: "test_verifier",
      expected_nonce: None,
    )
  assert result == Error(error.missing_callback_param("code"))
}

pub fn logging_does_not_change_core_result_shapes_test() -> Nil {
  let strategy = test_strategy()
  let client_config =
    config.new(
      client_id: "id",
      auth: config.ClientSecret("secret"),
      redirect_uri: "http://localhost/cb",
    )
  let assert Ok(authorization_request_value) =
    vestibule.create_authorization_request(
      strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let parameters =
    dict.from_list([
      #("code", "valid_code"),
      #("state", authorization_request.state(authorization_request_value)),
    ])

  let assert Ok(_) =
    vestibule.handle_callback(
      strategy,
      config: client_config,
      callback_params: parameters,
      expected_state: authorization_request.state(authorization_request_value),
      code_verifier: authorization_request.code_verifier(
        authorization_request_value,
      ),
      expected_nonce: None,
    )

  let assert Ok(_) =
    vestibule.refresh_token(
      strategy,
      config: client_config,
      refresh_token: "refresh-123",
    )
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
            credential.new(
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
          credential.new(
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

fn nonce_parameters() -> dict.Dict(String, String) {
  dict.from_list([#("code", "valid_code"), #("state", "expected")])
}

pub fn handle_callback_accepts_matching_nonce_test() -> Nil {
  let id_token = make_id_token("{\"sub\":\"user123\",\"nonce\":\"the-nonce\"}")
  let strategy = nonce_strategy(id_token)
  let assert Ok(_) =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_parameters(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: Some("the-nonce"),
    )
  Nil
}

pub fn handle_callback_rejects_mismatched_nonce_test() -> Nil {
  let id_token =
    make_id_token("{\"sub\":\"user123\",\"nonce\":\"wrong-nonce\"}")
  let strategy = nonce_strategy(id_token)
  let result =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_parameters(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: Some("the-nonce"),
    )
  assert result_error_kind(result) == Some(error.invalid_nonce())
}

pub fn handle_callback_rejects_missing_nonce_claim_test() -> Nil {
  let id_token = make_id_token("{\"sub\":\"user123\"}")
  let strategy = nonce_strategy(id_token)
  let result =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_parameters(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: Some("the-nonce"),
    )
  assert result_error_kind(result) == Some(error.invalid_nonce())
}

pub fn handle_callback_rejects_missing_id_token_when_nonce_expected_test() -> Nil {
  let strategy = nonce_strategy_without_id_token()
  let result =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_parameters(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: Some("the-nonce"),
    )
  assert result_error_kind(result) == Some(error.invalid_nonce())
}

pub fn handle_callback_skips_nonce_for_plain_oauth_strategy_test() -> Nil {
  // uses_nonce: False strategy ignores any id_token nonce entirely.
  let strategy = test_strategy()
  let assert Ok(_) =
    vestibule.handle_callback(
      strategy,
      config: nonce_config(),
      callback_params: nonce_parameters(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: None,
    )
  Nil
}

/// Reduce a callback result to just the error variant, dropping the success
/// payload (which contains a closure that cannot be structurally compared).
fn result_error_kind(
  result: Result(a, error.AuthError(e)),
) -> option.Option(error.AuthError(e)) {
  case result {
    Ok(_) -> None
    Error(auth_error) -> Some(auth_error)
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
      callback_params: nonce_parameters(),
      expected_state: "expected",
      code_verifier: "verifier",
      expected_nonce: None,
    )
  let assert Error(auth_error) = result
  error.kind(auth_error)
  |> fn(actual) {
    assert actual == error.InvalidNonceKind
  }
}
