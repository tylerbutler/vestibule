import gleam/dict
import gleam/dynamic
import gleam/dynamic/decode
import gleam/option.{None, Some}
import gleam/string
import startest
import startest/expect
import vestibule
import vestibule/authorization_request
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule/error
import vestibule/strategy.{type Strategy}
import vestibule/user_info.{UserInfo}

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// A fake strategy for testing the orchestrator
fn test_strategy() -> Strategy(e) {
  strategy.new(
    provider: "test",
    default_scopes: ["default_scope"],
    authorize_url: fn(_config, scopes, state) {
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
              Credentials(
                token: "test_token",
                refresh_token: None,
                token_type: "bearer",
                expires_in: None,
                scopes: ["default_scope"],
              ),
            ),
          )
        _ -> Error(error.CodeExchangeFailed(reason: "bad code"))
      }
    },
    refresh_token: fn(cfg, refresh_tok) {
      Ok(
        Credentials(
          token: "delegated:" <> refresh_tok <> ":" <> config.client_id(cfg),
          refresh_token: Some("rotated_by_strategy"),
          token_type: "bearer",
          expires_in: Some(3600),
          scopes: ["delegated_scope"],
        ),
      )
    },
    fetch_user: fn(_cfg, exchange) {
      strategy.exchange_credentials(exchange).token
      |> expect.to_equal("test_token")
      Ok(strategy.user_result(
        uid: "user123",
        info: UserInfo(
          name: Some("Test User"),
          email: Some("test@example.com"),
          nickname: None,
          image: None,
          description: None,
          urls: dict.new(),
        ),
        extra: dict.from_list([
          #("raw_provider", dynamic.string("from-provider")),
        ]),
      ))
    },
  )
}

fn artifact_strategy() -> Strategy(e) {
  strategy.new(
    provider: "artifact",
    default_scopes: [],
    authorize_url: fn(_config, _scopes, state) {
      Ok("https://test.com/auth?state=" <> state)
    },
    exchange_code: fn(_config, _code, _code_verifier) {
      Ok(strategy.exchange_result_with_artifacts(
        Credentials(
          token: "artifact_token",
          refresh_token: None,
          token_type: "bearer",
          expires_in: None,
          scopes: [],
        ),
        dict.from_list([
          #("exchange_marker", dynamic.string("from-exchange")),
        ]),
      ))
    },
    refresh_token: fn(_config, _refresh_tok) {
      Error(error.ConfigError(reason: "refresh not implemented"))
    },
    fetch_user: fn(_cfg, exchange) {
      let assert Ok(marker) =
        dict.get(strategy.exchange_artifacts(exchange), "exchange_marker")
      let assert Ok(decoded) = decode.run(marker, decode.string)
      Ok(strategy.user_result(
        uid: decoded,
        info: UserInfo(
          name: None,
          email: None,
          nickname: None,
          image: None,
          description: None,
          urls: dict.new(),
        ),
        extra: dict.new(),
      ))
    },
  )
}

fn fragment_strategy() -> Strategy(e) {
  let base = test_strategy()
  strategy.new(
    provider: strategy.provider(base),
    default_scopes: strategy.default_scopes(base),
    authorize_url: fn(_config, _scopes, state) {
      Ok(
        "https://test.com/auth?state="
        <> state
        <> "&existing=1#provider-fragment",
      )
    },
    exchange_code: fn(cfg, code, verifier) {
      strategy.exchange_code(base, cfg, code, verifier)
    },
    refresh_token: fn(cfg, tok) { strategy.refresh_token(base, cfg, tok) },
    fetch_user: fn(cfg, exchange) { strategy.fetch_user(base, cfg, exchange) },
  )
}

pub fn authorize_url_returns_authorization_request_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let assert Ok(req) = vestibule.authorize_url(strat, conf)
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
}

pub fn authorize_url_appends_pkce_before_url_fragment_test() {
  let conf = config.new("id", "secret", "http://localhost/cb")
  let assert Ok(req) = vestibule.authorize_url(fragment_strategy(), conf)
  let url = authorization_request.url(req)

  { string.contains(url, "&existing=1&code_challenge=") }
  |> expect.to_be_true()
  { string.contains(url, "code_challenge_method=S256#provider-fragment") }
  |> expect.to_be_true()
}

pub fn authorize_url_uses_config_scopes_when_present_test() {
  let strat = test_strategy()
  let conf =
    config.new("id", "secret", "http://localhost/cb")
    |> config.with_scopes(["custom_scope"])
  let assert Ok(req) = vestibule.authorize_url(strat, conf)
  let url = authorization_request.url(req)
  { string.contains(url, "custom_scope") } |> expect.to_be_true()
  { string.contains(url, "default_scope") } |> expect.to_be_false()
}

pub fn authorize_url_uses_default_scopes_when_config_empty_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let assert Ok(req) = vestibule.authorize_url(strat, conf)
  let url = authorization_request.url(req)
  { string.contains(url, "default_scope") } |> expect.to_be_true()
}

pub fn handle_callback_succeeds_with_valid_params_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state_value"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])
  let result =
    vestibule.handle_callback(strat, conf, params, state, "test_verifier")
  let assert Ok(auth) = result
  auth.uid |> expect.to_equal("user123")
  auth.provider |> expect.to_equal("test")
  auth.info.name |> expect.to_equal(Some("Test User"))
  auth.credentials.token |> expect.to_equal("test_token")
}

pub fn handle_callback_populates_auth_extra_from_strategy_user_result_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state_value"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])

  let assert Ok(auth) =
    vestibule.handle_callback(strat, conf, params, state, "test_verifier")
  let assert Ok(raw_provider) = dict.get(auth.extra, "raw_provider")
  decode.run(raw_provider, decode.string)
  |> expect.to_equal(Ok("from-provider"))
}

pub fn handle_callback_passes_exchange_artifacts_to_fetch_user_test() {
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state_value"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])

  let assert Ok(auth) =
    vestibule.handle_callback(
      artifact_strategy(),
      conf,
      params,
      state,
      "test_verifier",
    )

  auth.uid |> expect.to_equal("from-exchange")
  auth.credentials.token |> expect.to_equal("artifact_token")
}

pub fn refresh_token_delegates_to_strategy_refresh_token_test() {
  let strat = test_strategy()
  let conf = config.new("client-id", "secret", "http://localhost/cb")

  vestibule.refresh_token(strat, conf, "refresh-123")
  |> expect.to_equal(
    Ok(
      Credentials(
        token: "delegated:refresh-123:client-id",
        refresh_token: Some("rotated_by_strategy"),
        token_type: "bearer",
        expires_in: Some(3600),
        scopes: ["delegated_scope"],
      ),
    ),
  )
}

pub fn handle_callback_fails_on_state_mismatch_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let params = dict.from_list([#("code", "valid_code"), #("state", "wrong")])
  let result =
    vestibule.handle_callback(strat, conf, params, "expected", "test_verifier")
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn missing_callback_state_is_structured_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let params = dict.from_list([#("code", "valid_code")])

  vestibule.handle_callback(strat, conf, params, "expected", "test_verifier")
  |> expect.to_equal(Error(error.MissingCallbackParam("state")))
}

pub fn handle_callback_fails_on_missing_code_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state"
  let params = dict.from_list([#("state", state)])
  let result =
    vestibule.handle_callback(strat, conf, params, state, "test_verifier")
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn missing_callback_code_is_structured_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state"
  let params = dict.from_list([#("state", state)])

  vestibule.handle_callback(strat, conf, params, state, "test_verifier")
  |> expect.to_equal(Error(error.MissingCallbackParam("code")))
}
