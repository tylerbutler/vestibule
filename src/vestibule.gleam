//// Vestibule — a strategy-based authentication library for Gleam.
////
//// Provides a consistent interface across OAuth2 identity providers
//// using a two-phase flow: redirect to provider, then handle callback.
//// All flows use PKCE (Proof Key for Code Exchange) for enhanced security.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/uri

import vestibule/auth.{type Auth, Auth}
import vestibule/authorization_request.{type AuthorizationRequest}
import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
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
  strat: Strategy(e),
  cfg cfg: Config,
) -> Result(AuthorizationRequest, AuthError(e)) {
  let provider = option.Some(strategy.provider(strat))
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
  let maybe_nonce = case strategy.uses_nonce(strat) {
    True -> option.Some(nonce.generate())
    False -> option.None
  }
  let scopes = case config.scopes(cfg) {
    [] -> strategy.default_scopes(strat)
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
      strat,
      cfg: cfg,
      scopes: scopes,
      state: csrf_state,
    )
    |> result.map(fn(base_url) { append_pkce_params(base_url, code_challenge) })
    |> result.map(fn(url) { append_nonce_param(url, maybe_nonce) })
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: failure_level(err),
          event: "vestibule.authorization_request.failure",
          phase: "request",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
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
/// `None` for plain OAuth2 strategies. When the strategy uses a nonce and an
/// expected value is present, the `nonce` claim in the `id_token` artifact must
/// match or the callback fails with `InvalidNonce`.
///
/// **Caller responsibilities:** This function checks that the callback
/// state matches `expected_state`, but does not enforce single-use or
/// expiration. Callers should delete the stored state after a successful
/// call to prevent replay attacks. The wisp middleware's `uset.take`
/// provides one-time-use semantics automatically. For time-based
/// expiration, check the timestamp you stored alongside the state
/// before calling this function.
pub fn handle_callback(
  strat: Strategy(e),
  cfg cfg: Config,
  callback_params callback_params: Dict(String, String),
  expected_state expected_state: String,
  code_verifier code_verifier: String,
  expected_nonce expected_nonce: option.Option(String),
) -> Result(Auth, AuthError(e)) {
  let provider = option.Some(strategy.provider(strat))
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
    dict.get(callback_params, "state")
    |> result.replace_error(error.MissingCallbackParam("state"))
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
  }
  use _ <- result.try(validate_result)

  // Check for provider errors before requiring code
  let provider_check = check_provider_error(callback_params)
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
  }
  use _ <- result.try(provider_check)

  // Extract authorization code
  let code_result =
    dict.get(callback_params, "code")
    |> result.replace_error(error.MissingCallbackParam("code"))
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
            logger.field("missing_param", "code"),
          ],
        ),
      )
  }
  use code <- result.try(code_result)

  // Exchange code for credentials and provider-specific artifacts, passing the PKCE verifier
  let exchange_result =
    strategy.exchange_code(
      strat,
      cfg: cfg,
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: failure_level(err),
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
  }
  use exchange <- result.try(exchange_result)

  // Validate the OIDC nonce against the id_token (when one is expected).
  let nonce_result = validate_callback_nonce(strat, exchange, expected_nonce)
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: logger.Warning,
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
  }
  use _ <- result.try(nonce_result)

  // Fetch user info
  let user_result = strategy.fetch_user(strat, cfg: cfg, exchange: exchange)
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
    Error(err) ->
      logger.emit(
        logger.new(
          level: failure_level(err),
          event: "vestibule.callback.failure",
          phase: "callback",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
  }
  use user <- result.try(user_result)

  // Assemble the Auth result
  let auth =
    Auth(
      uid: strategy.user_result_uid(user),
      provider: strategy.provider(strat),
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
  strat: Strategy(e),
  cfg cfg: Config,
  refresh_tok refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  let provider = option.Some(strategy.provider(strat))
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
    strategy.refresh_token(strat, cfg: cfg, refresh_tok: refresh_tok)
  case outcome {
    Ok(creds) ->
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
              option.is_some(credentials.refresh_token(creds)),
            ),
            logger.int_field(
              "scope_count",
              list.length(credentials.scopes(creds)),
            ),
          ],
        ),
      )
    Error(err) ->
      logger.emit(
        logger.new(
          level: failure_level(err),
          event: "vestibule.refresh.failure",
          phase: "refresh",
          outcome: "failure",
          provider: provider,
          fields: [
            logger.field("error_category", logger.auth_error_category(err)),
          ],
        ),
      )
  }
  outcome
}

fn failure_level(err: AuthError(e)) -> logger.Level {
  case err {
    error.NetworkError(_)
    | error.HttpError(_, _)
    | error.DecodeError(_, _)
    | error.ConfigError(_) -> logger.Error
    error.StateMismatch
    | error.InvalidNonce
    | error.MissingCallbackParam(_)
    | error.CodeExchangeFailed(_)
    | error.UserInfoFailed(_)
    | error.ProviderError(_, _, _)
    | error.Custom(_) -> logger.Warning
  }
}

/// Check callback params for a provider error response.
fn check_provider_error(
  params: Dict(String, String),
) -> Result(Nil, AuthError(e)) {
  case dict.get(params, "error") {
    Ok(error_code) -> {
      let description =
        dict.get(params, "error_description")
        |> result.unwrap("")
      let uri = dict.get(params, "error_uri") |> option.from_result()
      Error(error.ProviderError(
        code: error_code,
        description: description,
        uri: uri,
      ))
    }
    Error(Nil) -> Ok(Nil)
  }
}

/// Append PKCE code_challenge and code_challenge_method to an authorization URL.
fn append_pkce_params(url: String, code_challenge: String) -> String {
  merge_query(
    url,
    uri.query_to_string([
      #("code_challenge", code_challenge),
      #("code_challenge_method", "S256"),
    ]),
  )
}

/// Append the OIDC `nonce` parameter to an authorization URL when present.
fn append_nonce_param(url: String, nonce: option.Option(String)) -> String {
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
/// A no-op for plain OAuth2 strategies (`uses_nonce: False`) or when no nonce
/// was stored. When a nonce is expected, a missing `id_token` artifact, a
/// missing `nonce` claim, or a mismatch all fail with `InvalidNonce`.
fn validate_callback_nonce(
  strat: Strategy(e),
  exchange: strategy.ExchangeResult,
  expected_nonce: option.Option(String),
) -> Result(Nil, AuthError(e)) {
  case strategy.uses_nonce(strat), expected_nonce {
    True, option.Some(expected) -> {
      use id_token <- result.try(extract_id_token(exchange))
      use claimed <- result.try(read_nonce_claim(id_token))
      nonce.validate(received: claimed, expected: expected)
    }
    _, _ -> Ok(Nil)
  }
}

/// Read the raw `id_token` artifact string from an exchange result.
fn extract_id_token(
  exchange: strategy.ExchangeResult,
) -> Result(String, AuthError(e)) {
  case dict.get(strategy.exchange_artifacts(exchange), "id_token") {
    Ok(dyn) ->
      decode.run(dyn, decode.string)
      |> result.replace_error(error.InvalidNonce)
    Error(Nil) -> Error(error.InvalidNonce)
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
    Ok(option.None) -> Error(error.InvalidNonce)
    Error(_) -> Error(error.InvalidNonce)
  }
}

fn decode_jwt_payload(id_token: String) -> Result(String, AuthError(e)) {
  case string.split(id_token, ".") {
    [_header, payload, ..] ->
      case bit_array.base64_url_decode(payload) {
        Ok(bits) ->
          case bit_array.to_string(bits) {
            Ok(json_payload) -> Ok(json_payload)
            Error(_) -> Error(error.InvalidNonce)
          }
        Error(_) -> Error(error.InvalidNonce)
      }
    _ -> Error(error.InvalidNonce)
  }
}
