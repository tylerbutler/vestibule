/// Vestibule — a strategy-based authentication library for Gleam.
///
/// Provides a consistent interface across OAuth2 identity providers
/// using a two-phase flow: redirect to provider, then handle callback.
import gleam/dict.{type Dict}
import gleam/result

import vestibule/auth.{type Auth, Auth}
import vestibule/config.{type Config}
import vestibule/error.{type AuthError}
import vestibule/state
import vestibule/strategy.{type Strategy}

/// Phase 1: Generate the authorization URL to redirect the user to.
///
/// Returns `#(url, state)` — the caller must store the state parameter
/// in their session for validation during the callback phase.
pub fn authorize_url(
  strategy: Strategy(e),
  config: Config,
) -> Result(#(String, String), AuthError(e)) {
  let csrf_state = state.generate()
  let scopes = case config.scopes {
    [] -> strategy.default_scopes
    custom -> custom
  }
  use url <- result.try(strategy.authorize_url(config, scopes, csrf_state))
  Ok(#(url, csrf_state))
}

/// Phase 2: Handle the OAuth callback from the provider.
///
/// Validates the state parameter, exchanges the authorization code
/// for credentials, and fetches normalized user information.
pub fn handle_callback(
  strategy: Strategy(e),
  config: Config,
  callback_params: Dict(String, String),
  expected_state: String,
) -> Result(Auth, AuthError(e)) {
  // Extract required parameters
  use received_state <- result.try(
    dict.get(callback_params, "state")
    |> result.replace_error(error.ConfigError(
      reason: "Missing state parameter in callback",
    )),
  )
  use code <- result.try(
    dict.get(callback_params, "code")
    |> result.replace_error(error.ConfigError(
      reason: "Missing code parameter in callback",
    )),
  )

  // Check for provider errors
  use _ <- result.try(case dict.get(callback_params, "error") {
    Ok(error_code) -> {
      let description =
        dict.get(callback_params, "error_description")
        |> result.unwrap("")
      Error(error.ProviderError(code: error_code, description: description))
    }
    Error(Nil) -> Ok(Nil)
  })

  // Validate state
  use _ <- result.try(state.validate(received_state, expected_state))

  // Exchange code for credentials
  use credentials <- result.try(strategy.exchange_code(config, code))

  // Fetch user info
  use #(uid, info) <- result.try(strategy.fetch_user(credentials))

  // Assemble the Auth result
  Ok(Auth(
    uid: uid,
    provider: strategy.provider,
    info: info,
    credentials: credentials,
    extra: dict.new(),
  ))
}
