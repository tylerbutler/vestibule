import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import startest
import startest/expect
import vestibule
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule/error
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info.{UserInfo}

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// A fake strategy for testing the orchestrator
fn test_strategy() -> Strategy {
  Strategy(
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
    exchange_code: fn(_config, code) {
      case code {
        "valid_code" ->
          Ok(
            Credentials(
              token: "test_token",
              refresh_token: None,
              token_type: "bearer",
              expires_at: None,
              scopes: ["default_scope"],
            ),
          )
        _ -> Error(error.CodeExchangeFailed(reason: "bad code"))
      }
    },
    fetch_user: fn(_creds) {
      Ok(#(
        "user123",
        UserInfo(
          name: Some("Test User"),
          email: Some("test@example.com"),
          nickname: None,
          image: None,
          description: None,
          urls: dict.new(),
        ),
      ))
    },
  )
}

pub fn authorize_url_returns_url_and_state_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let result = vestibule.authorize_url(strat, conf)
  let assert Ok(#(url, state)) = result
  // URL should contain the state
  { string.contains(url, state) } |> expect.to_be_true()
  // State should be non-empty
  { string.length(state) >= 43 } |> expect.to_be_true()
}

pub fn authorize_url_uses_config_scopes_when_present_test() {
  let strat = test_strategy()
  let conf =
    config.new("id", "secret", "http://localhost/cb")
    |> config.with_scopes(["custom_scope"])
  let assert Ok(#(url, _state)) = vestibule.authorize_url(strat, conf)
  { string.contains(url, "custom_scope") } |> expect.to_be_true()
  { string.contains(url, "default_scope") } |> expect.to_be_false()
}

pub fn authorize_url_uses_default_scopes_when_config_empty_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let assert Ok(#(url, _state)) = vestibule.authorize_url(strat, conf)
  { string.contains(url, "default_scope") } |> expect.to_be_true()
}

pub fn handle_callback_succeeds_with_valid_params_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state_value"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])
  let result = vestibule.handle_callback(strat, conf, params, state)
  let assert Ok(auth) = result
  auth.uid |> expect.to_equal("user123")
  auth.provider |> expect.to_equal("test")
  auth.info.name |> expect.to_equal(Some("Test User"))
  auth.credentials.token |> expect.to_equal("test_token")
}

pub fn handle_callback_fails_on_state_mismatch_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let params = dict.from_list([#("code", "valid_code"), #("state", "wrong")])
  let result = vestibule.handle_callback(strat, conf, params, "expected")
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn handle_callback_fails_on_missing_code_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state"
  let params = dict.from_list([#("state", state)])
  let result = vestibule.handle_callback(strat, conf, params, state)
  let _ = result |> expect.to_be_error()
  Nil
}
