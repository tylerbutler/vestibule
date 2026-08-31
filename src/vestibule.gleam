//// Vestibule — demo-ready OAuth sign-in for Gleam.
////
//// Provides a consistent interface across OAuth2 identity providers
//// using a two-phase flow: redirect to provider, then handle callback.
//// All flows use PKCE (Proof Key for Code Exchange).
////
//// **Warning:** vestibule has not been security audited and must not be
//// considered secure. It is intended for demos and prototypes that need
//// real OAuth flows — do not use it in production.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

import vestibule/auth.{type Auth}
import vestibule/authorization_request.{type AuthorizationRequest}
import vestibule/config.{type AuthorizeOptions, type ClientConfig}
import vestibule/credential.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/logger
import vestibule/nonce
import vestibule/pkce
import vestibule/state
import vestibule/strategy.{type Strategy}

/// Phase 1: Generate the authorization URL to redirect the user to.
///
/// Returns an `AuthorizationRequest` containing the URL, CSRF state,
/// and PKCE code verifier. The caller must store both the state and
/// code_verifier in their session for use during the callback phase.
///
/// PKCE parameters (`code_challenge` and `code_challenge_method=S256`)
/// are automatically appended to the authorization URL.
///
/// **State expiration:** This library generates the state token but does
/// not enforce expiration. If you need time-based expiration, store a
/// timestamp alongside the state when saving it to your session and
/// check it before calling `handle_callback`.
pub fn create_authorization_request(
  strategy: Strategy(e),
  config config: ClientConfig,
  options options: AuthorizeOptions,
) -> Result(AuthorizationRequest, AuthError(e)) {
  let provider = option.Some(strategy.provider(strategy))
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.authorization_request.start",
      phase: "request",
      outcome: "start",
      provider: provider,
      fields: [],
    ),
  )
  let csrf_state = state.generate()
  let code_verifier = pkce.generate_verifier()
  let code_challenge = pkce.compute_challenge(code_verifier)
  let maybe_nonce = case strategy.uses_nonce(strategy) {
    True -> option.Some(nonce.generate())
    False -> option.None
  }
  let scopes = case config.scopes(options) {
    [] -> strategy.default_scopes(strategy)
    custom -> custom
  }
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.authorization_request.scopes_resolved",
      phase: "request",
      outcome: "success",
      provider: provider,
      fields: [logger.int_field("scope_count", list.length(scopes))],
    ),
  )
  let outcome =
    strategy.build_authorize_url(
      strategy,
      config: config,
      options: options,
      scopes: scopes,
      state: csrf_state,
    )
    |> result.map(fn(base_url) {
      append_pkce_parameters(base_url, code_challenge)
    })
    |> result.map(fn(url) { append_nonce_parameter(url, maybe_nonce) })
    |> result.map(fn(url) {
      authorization_request.new(
        url: url,
        state: csrf_state,
        code_verifier: code_verifier,
        nonce: maybe_nonce,
      )
    })
  case outcome {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Info,
          event: "vestibule.authorization_request.success",
          phase: "request",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: failure_level(auth_error),
          event: "vestibule.authorization_request.failure",
          phase: "request",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
  }
  outcome
}

/// Phase 2: Handle the OAuth callback from the provider.
///
/// Validates the state parameter, exchanges the authorization code
/// for credentials (including the PKCE code verifier), validates the OIDC
/// `nonce` against the returned `id_token` (when the strategy uses one), and
/// fetches normalized user information.
///
/// `expected_nonce` is the OIDC nonce stored during the request phase, or
/// `None` for plain OAuth2 strategies. When the strategy uses a nonce,
/// `expected_nonce` must be `Some` and the `nonce` claim in the `id_token`
/// artifact must match it; a missing expected nonce, missing `id_token`,
/// missing claim, or mismatch all fail with an AuthError of kind
/// `InvalidNonceKind`. The check never falls open.
///
/// **Caller responsibilities:** This function checks that the callback
/// state matches `expected_state`, but does not enforce single-use or
/// expiration. Callers should delete the stored state after a successful
/// call to prevent replay attacks. The wisp middleware's `uset.take`
/// provides one-time-use semantics automatically. For time-based
/// expiration, check the timestamp you stored alongside the state
/// before calling this function.
pub fn handle_callback(
  strategy: Strategy(e),
  config config: ClientConfig,
  callback_params parameters: Dict(String, String),
  expected_state expected_state: String,
  code_verifier code_verifier: String,
  expected_nonce expected_nonce: option.Option(String),
) -> Result(Auth, AuthError(e)) {
  let provider = option.Some(strategy.provider(strategy))
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.callback.start",
      phase: "callback",
      outcome: "start",
      provider: provider,
      fields: [],
    ),
  )

  // Extract state (needed for CSRF validation)
  let state_result =
    dict.get(parameters, "state")
    |> result.replace_error(error.missing_callback_param("state"))
  case state_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.callback.state_received",
          phase: "callback",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
            logger.field("missing_param", "state"),
          ],
        ),
      )
  }
  use received_state <- result.try(state_result)

  // Validate state before surfacing any provider response details.
  let validate_result =
    state.validate(received: received_state, expected: expected_state)
  case validate_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.callback.state_valid",
          phase: "callback",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
  }
  use _ <- result.try(validate_result)

  // Check for provider errors before requiring code
  let provider_check = check_provider_error(parameters)
  case provider_check {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.callback.provider_error_checked",
          phase: "callback",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
  }
  use _ <- result.try(provider_check)

  // Extract authorization code
  let code_result =
    dict.get(parameters, "code")
    |> result.replace_error(error.missing_callback_param("code"))
  case code_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.callback.code_received",
          phase: "callback",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
            logger.field("missing_param", "code"),
          ],
        ),
      )
  }
  use code <- result.try(code_result)

  // Exchange code for credentials and provider-specific artifacts, passing the PKCE verifier
  let exchange_result =
    strategy.exchange_code(
      strategy,
      config: config,
      code: code,
      code_verifier: option.Some(code_verifier),
    )
  case exchange_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.callback.exchange.success",
          phase: "callback",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: failure_level(auth_error),
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
  }
  use exchange <- result.try(exchange_result)

  // Validate the OIDC nonce against the id_token (when one is expected).
  let nonce_result = validate_callback_nonce(strategy, exchange, expected_nonce)
  case nonce_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.callback.nonce_valid",
          phase: "callback",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
  }
  use _ <- result.try(nonce_result)

  // Fetch user info
  let user_result =
    strategy.fetch_user(strategy, config: config, exchange: exchange)
  case user_result {
    Ok(_) ->
      logger.emit(
        logger.new(
          level: logger.Debug,
          event: "vestibule.callback.user.success",
          phase: "callback",
          outcome: "success",
          provider: provider,
          fields: [],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: failure_level(auth_error),
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
  }
  use user <- result.try(user_result)

  // Assemble the Auth result
  let auth =
    auth.new(
      uid: strategy.user_result_uid(user),
      provider: strategy.provider(strategy),
      info: strategy.user_result_info(user),
      credentials: strategy.exchange_credentials(exchange),
      extra: strategy.user_result_extra(user),
    )
  logger.emit(
    logger.new(
      level: logger.Info,
      event: "vestibule.callback.success",
      phase: "callback",
      outcome: "success",
      provider: provider,
      fields: [],
    ),
  )
  Ok(auth)
}

/// Refresh an access token using a refresh token.
///
/// Delegates to the provider strategy so refresh semantics remain provider-owned.
pub fn refresh_token(
  strategy: Strategy(e),
  config config: ClientConfig,
  refresh_token refresh_token: String,
) -> Result(Credentials, AuthError(e)) {
  let provider = option.Some(strategy.provider(strategy))
  logger.emit(
    logger.new(
      level: logger.Debug,
      event: "vestibule.refresh.start",
      phase: "refresh",
      outcome: "start",
      provider: provider,
      fields: [],
    ),
  )
  let outcome =
    strategy.refresh_token(
      strategy,
      config: config,
      refresh_token: refresh_token,
    )
  case outcome {
    Ok(credentials) ->
      logger.emit(
        logger.new(
          level: logger.Info,
          event: "vestibule.refresh.success",
          phase: "refresh",
          outcome: "success",
          provider: provider,
          fields: [
            logger.bool_field(
              "has_refresh_token",
              option.is_some(credential.refresh_token(credentials)),
            ),
            logger.int_field(
              "scope_count",
              list.length(credential.scopes(credentials)),
            ),
          ],
        ),
      )
    Error(auth_error) ->
      logger.emit(
        logger.new(
          level: failure_level(auth_error),
          event: "vestibule.refresh.failure",
          phase: "refresh",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field(
              "error_category",
              logger.auth_error_category(auth_error),
            ),
          ],
        ),
      )
  }
  outcome
}

fn failure_level(auth_error: AuthError(e)) -> logger.Level {
  case error.kind(auth_error) {
    error.NetworkKind | error.HttpKind | error.DecodeKind | error.ConfigKind ->
      logger.Error
    error.StateMismatchKind
    | error.InvalidNonceKind
    | error.MissingCallbackParamKind
    | error.CodeExchangeKind
    | error.UserInfoKind
    | error.ProviderKind
    | error.RefreshUnsupportedKind
    | error.CustomKind
    | error.OtherKind -> logger.Warning
  }
}

/// Check callback parameters for a provider error response.
fn check_provider_error(
  parameters: Dict(String, String),
) -> Result(Nil, AuthError(e)) {
  case dict.get(parameters, "error") {
    Ok(error_code) -> {
      let description =
        dict.get(parameters, "error_description")
        |> result.unwrap("")
      let uri = dict.get(parameters, "error_uri") |> option.from_result()
      Error(error.provider(code: error_code, description: description, uri: uri))
    }
    Error(Nil) -> Ok(Nil)
  }
}

/// Append PKCE code_challenge and code_challenge_method to an authorization URL.
fn append_pkce_parameters(url: String, code_challenge: String) -> String {
  merge_query(
    url,
    uri.query_to_string([
      #("code_challenge", code_challenge),
      #("code_challenge_method", "S256"),
    ]),
  )
}

/// Append the OIDC `nonce` parameter to an authorization URL when present.
fn append_nonce_parameter(url: String, nonce: option.Option(String)) -> String {
  case nonce {
    option.Some(value) ->
      merge_query(url, uri.query_to_string([#("nonce", value)]))
    option.None -> url
  }
}

/// Merge an additional query string into a URL, preserving any existing query.
fn merge_query(url: String, extra: String) -> String {
  case uri.parse(url) {
    Ok(parsed) -> {
      let query = case parsed.query {
        option.Some(existing) -> existing <> "&" <> extra
        option.None -> extra
      }
      uri.to_string(uri.Uri(..parsed, query: option.Some(query)))
    }
    Error(_) -> append_raw_query(url, extra)
  }
}

fn append_raw_query(url: String, query: String) -> String {
  let separator = case string.contains(url, "?") {
    True -> "&"
    False -> "?"
  }
  url <> separator <> query
}

/// Validate the OIDC `nonce` claim in the exchange's `id_token` artifact
/// against the expected value stored during the request phase.
///
/// A no-op for plain OAuth2 strategies (`uses_nonce: False`). For a strategy
/// that uses a nonce, a missing expected nonce, a missing `id_token`
/// artifact, a missing `nonce` claim, or a mismatch all fail with an
/// AuthError of kind `InvalidNonceKind` — the check never falls open just
/// because the caller had nothing stored to compare against.
fn validate_callback_nonce(
  strategy: Strategy(e),
  exchange: strategy.ExchangeResult,
  expected_nonce: option.Option(String),
) -> Result(Nil, AuthError(e)) {
  case strategy.uses_nonce(strategy), expected_nonce {
    True, option.Some(expected) -> {
      use id_token <- result.try(extract_id_token(exchange))
      use claimed <- result.try(read_nonce_claim(id_token))
      nonce.validate(received: claimed, expected: expected)
    }
    True, option.None -> Error(error.invalid_nonce())
    False, option.Some(_) | False, option.None -> Ok(Nil)
  }
}

/// Read the raw `id_token` artifact string from an exchange result.
fn extract_id_token(
  exchange: strategy.ExchangeResult,
) -> Result(String, AuthError(e)) {
  case dict.get(strategy.exchange_artifacts(exchange), "id_token") {
    Ok(dynamic_value) ->
      decode.run(dynamic_value, decode.string)
      |> result.replace_error(error.invalid_nonce())
    Error(Nil) -> Error(error.invalid_nonce())
  }
}

/// Decode a JWT payload (no signature check) and read its `nonce` claim.
///
/// The id_token arrives over the TLS-protected token endpoint, so the payload
/// is decoded without verifying the signature solely to compare the `nonce`.
fn read_nonce_claim(id_token: String) -> Result(String, AuthError(e)) {
  use payload <- result.try(decode_jwt_payload(id_token))
  let decoder = {
    use nonce <- decode.optional_field(
      "nonce",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(nonce)
  }
  case json.parse(payload, decoder) {
    Ok(option.Some(value)) -> Ok(value)
    Ok(option.None) -> Error(error.invalid_nonce())
    Error(_) -> Error(error.invalid_nonce())
  }
}

fn decode_jwt_payload(id_token: String) -> Result(String, AuthError(e)) {
  case string.split(id_token, ".") {
    [_header, payload, ..] ->
      case bit_array.base64_url_decode(payload) {
        Ok(bits) ->
          case bit_array.to_string(bits) {
            Ok(json_payload) -> Ok(json_payload)
            Error(_) -> Error(error.invalid_nonce())
          }
        Error(_) -> Error(error.invalid_nonce())
      }
    _ -> Error(error.invalid_nonce())
  }
}
