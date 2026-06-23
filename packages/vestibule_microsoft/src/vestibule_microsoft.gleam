//// Microsoft Identity Platform (v2.0) strategy.
////
//// Requests `User.Read` by default. Tokens are exchanged against
//// `/oauth2/v2.0/token`; user info comes from Microsoft Graph `/me`.
////
//// ## Tenant isolation
////
//// `strategy()` uses the `/common` authority, which accepts personal Microsoft
//// accounts and work/school accounts from **any** Microsoft Entra tenant that
//// can consent to the app. It does **not** restrict logins to one organization
//// and performs no tenant validation — use it only for explicitly multi-tenant
//// apps.
////
//// For single-organization apps use `strategy_for_tenant(tenant_id)`. It targets
//// the tenant-specific authority endpoints and additionally verifies the `tid`
//// (tenant id) claim in the returned OpenID Connect ID token, failing
//// authentication when the token was issued by a different tenant.

import gleam/bit_array
import gleam/dict
import gleam/dynamic
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

import gleam/http/request
import gleam/httpc

import glow_auth
import glow_auth/authorize_uri
import glow_auth/token_request
import glow_auth/uri/uri_builder

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/logger
import vestibule/provider_support
import vestibule/strategy.{type Strategy, type UserResult}
import vestibule/user_info.{type UserInfo}

/// Create a Microsoft authentication strategy using the `/common` authority.
///
/// **Security warning:** `/common` accepts personal Microsoft accounts and
/// work/school accounts from any Microsoft Entra tenant that can consent to the
/// app, and this strategy performs **no** tenant validation. Use it only for
/// explicitly multi-tenant apps. For single-organization apps, use
/// `strategy_for_tenant` so logins are restricted to one tenant and the tenant
/// is verified against the ID token.
pub fn strategy() -> Strategy(e) {
  build_strategy("common", None)
}

/// Create a Microsoft authentication strategy locked to a single tenant.
///
/// `tenant_id` must be the tenant's directory (tenant) **GUID**, e.g.
/// `"72f988bf-86f1-41af-91ab-2d7cd011db47"`. The strategy uses the
/// tenant-specific authority endpoints
/// (`https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/...`) so
/// Microsoft itself only issues tokens for that tenant, and additionally
/// requests the `openid` scope and verifies that the `tid` claim in the
/// returned ID token equals `tenant_id` (case-insensitive). Authentication
/// fails if the ID token is missing or was issued by a different tenant.
///
/// Pass the tenant GUID rather than a verified domain (e.g.
/// `contoso.onmicrosoft.com`): the `tid` claim is always a GUID, so domain
/// values cannot be matched and would reject otherwise-valid logins.
pub fn strategy_for_tenant(tenant_id: String) -> Strategy(e) {
  build_strategy(tenant_id, Some(tenant_id))
}

fn build_strategy(
  authority: String,
  expected_tenant: Option(String),
) -> Strategy(e) {
  // Tenant-locked strategies need an ID token (`openid` scope) to read `tid`.
  let default_scopes = case expected_tenant {
    Some(_) -> ["openid", "User.Read"]
    None -> ["User.Read"]
  }
  strategy.new(
    provider: "microsoft",
    default_scopes: default_scopes,
    authorize_url: fn(cfg, scopes, state) {
      do_authorize_url(authority, cfg, scopes, state)
    },
    exchange_code: fn(cfg, code, code_verifier) {
      do_exchange_code(authority, cfg, code, code_verifier)
    },
    refresh_token: fn(cfg, refresh_tok) {
      do_refresh_token(authority, cfg, refresh_tok)
    },
    fetch_user: fn(cfg, exchange) {
      do_fetch_user(expected_tenant, cfg, exchange)
    },
  )
}

fn authority_base(authority: String) -> String {
  "https://login.microsoftonline.com/" <> authority <> "/oauth2/v2.0"
}

/// Parse Microsoft token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  do_parse_token_response(body, "token")
}

fn do_parse_token_response(
  body: String,
  endpoint: String,
) -> Result(Credentials, AuthError(e)) {
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(separator: " "),
    )
  case result {
    Ok(creds) -> {
      logger.new(
        level: logger.Debug,
        event: "vestibule.provider.token_parse.success",
        phase: "provider_request",
        outcome: "success",
        provider: Some("microsoft"),
        fields: [
          logger.field("endpoint", endpoint),
          logger.bool_field(
            "has_refresh_token",
            option.is_some(credentials.refresh_token(creds)),
          ),
          logger.int_field(
            "scope_count",
            list.length(credentials.scopes(creds)),
          ),
        ],
      )
      |> logger.emit()
      Ok(creds)
    }
    Error(err) -> {
      logger.new(
        level: logger.Warning,
        event: "vestibule.provider.token_parse.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: Some("microsoft"),
        fields: [
          logger.field("endpoint", endpoint),
          logger.field("error_category", logger.auth_error_category(err)),
        ],
      )
      |> logger.emit()
      Error(err)
    }
  }
}

/// Parse Microsoft Graph /me response JSON.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let decoder = {
    use id <- decode.field("id", decode.string)
    use display_name <- decode.optional_field(
      "displayName",
      None,
      decode.optional(decode.string),
    )
    use mail <- decode.optional_field(
      "mail",
      None,
      decode.optional(decode.string),
    )
    use upn <- decode.field("userPrincipalName", decode.string)
    use job_title <- decode.optional_field(
      "jobTitle",
      None,
      decode.optional(decode.string),
    )
    let email = mail
    decode.success(#(
      id,
      user_info.UserInfo(
        name: display_name,
        email: email,
        nickname: Some(upn),
        image: None,
        description: job_title,
        urls: dict.new(),
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(err) ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse Microsoft user response: "
        <> string.inspect(err),
      ))
  }
}

fn do_authorize_url(
  authority: String,
  cfg: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  use site <- result.try(
    uri.parse(authority_base(authority))
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse Microsoft OAuth base URL")
    }),
  )
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(cfg)),
  )
  let client =
    glow_auth.Client(
      id: config.client_id(cfg),
      secret: config.client_secret(cfg),
      site: site,
    )
  let url =
    authorize_uri.build(
      client,
      uri_builder.RelativePath("/authorize"),
      redirect,
    )
    |> authorize_uri.set_scope(string.join(scopes, " "))
    |> authorize_uri.set_state(state)
    |> authorize_uri.to_code_authorization_uri()
    |> uri.to_string()
    |> provider_support.append_query_params(
      dict.to_list(config.extra_params(cfg)),
    )
  Ok(url)
}

fn do_exchange_code(
  authority: String,
  cfg: Config,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use site <- result.try(
    uri.parse(authority_base(authority))
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse Microsoft OAuth base URL")
    }),
  )
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(cfg)),
  )
  let client =
    glow_auth.Client(
      id: config.client_id(cfg),
      secret: config.client_secret(cfg),
      site: site,
    )
  let req =
    token_request.authorization_code(
      client,
      uri_builder.RelativePath("/token"),
      code,
      redirect,
    )
    |> request.set_header("accept", "application/json")
  let req = strategy.append_code_verifier(req, code_verifier)
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: Some("microsoft"),
    fields: [logger.field("endpoint", "token")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(
        provider_support.check_response_status_for_endpoint(
          response,
          provider_name: "microsoft",
          endpoint: "token",
        ),
      )
      parse_exchange_result(body)
    }
    Error(_) -> {
      logger.new(
        level: logger.Error,
        event: "vestibule.provider.request.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: Some("microsoft"),
        fields: [
          logger.field("endpoint", "token"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.NetworkError(
        reason: "Failed to connect to Microsoft token endpoint",
      ))
    }
  }
}

/// Parse a Microsoft token response into an exchange result, capturing the
/// OpenID Connect `id_token` (when present) as a provider-specific artifact so
/// tenant-locked strategies can verify the `tid` claim.
fn parse_exchange_result(
  body: String,
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use creds <- result.try(parse_token_response(body))
  Ok(strategy.exchange_result_with_artifacts(
    creds,
    id_token_artifacts(parse_id_token(body)),
  ))
}

fn parse_id_token(body: String) -> Option(String) {
  let decoder = {
    use id_token <- decode.optional_field(
      "id_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(id_token)
  }
  case json.parse(body, decoder) {
    Ok(id_token) -> id_token
    Error(_) -> None
  }
}

fn id_token_artifacts(
  id_token: Option(String),
) -> dict.Dict(String, dynamic.Dynamic) {
  case id_token {
    Some(token) -> dict.from_list([#("id_token", dynamic.string(token))])
    None -> dict.new()
  }
}

fn do_refresh_token(
  authority: String,
  cfg: Config,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  use site <- result.try(
    uri.parse(authority_base(authority))
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse Microsoft OAuth base URL")
    }),
  )
  let client =
    glow_auth.Client(
      id: config.client_id(cfg),
      secret: config.client_secret(cfg),
      site: site,
    )
  let req =
    token_request.refresh(
      client,
      uri_builder.RelativePath("/token"),
      refresh_tok,
    )
    |> request.set_header("accept", "application/json")

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: Some("microsoft"),
    fields: [logger.field("endpoint", "refresh")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(
        provider_support.check_response_status_for_endpoint(
          response,
          provider_name: "microsoft",
          endpoint: "refresh",
        ),
      )
      do_parse_token_response(body, "refresh")
    }
    Error(_) -> {
      logger.new(
        level: logger.Error,
        event: "vestibule.provider.request.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: Some("microsoft"),
        fields: [
          logger.field("endpoint", "refresh"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.NetworkError(
        reason: "Failed to connect to Microsoft token endpoint",
      ))
    }
  }
}

fn do_fetch_user(
  expected_tenant: Option(String),
  _cfg: Config,
  exchange: strategy.ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  use _ <- result.try(enforce_tenant(expected_tenant, exchange))
  use auth_header <- result.try(
    strategy.authorization_header(strategy.exchange_credentials(exchange)),
  )
  use #(uid, info) <- result.try(provider_support.fetch_json_with_auth(
    "https://graph.microsoft.com/v1.0/me",
    auth_header,
    parse_user_response,
    "Microsoft Graph",
  ))
  Ok(strategy.user_result(uid: uid, info: info, extra: dict.new()))
}

/// Enforce that the exchange's ID token was issued by the configured tenant.
///
/// Returns `Ok` immediately for multi-tenant (`/common`) strategies. For
/// tenant-locked strategies, requires an `id_token` artifact and verifies its
/// `tid` claim against the configured tenant, failing closed when the token is
/// absent or belongs to a different tenant.
fn enforce_tenant(
  expected_tenant: Option(String),
  exchange: strategy.ExchangeResult,
) -> Result(Nil, AuthError(e)) {
  case expected_tenant {
    None -> Ok(Nil)
    Some(tenant) -> {
      use id_token <- result.try(exchange_id_token(exchange))
      use _ <- result.try(verify_tenant(
        expected_tenant: tenant,
        id_token: id_token,
      ))
      Ok(Nil)
    }
  }
}

fn exchange_id_token(
  exchange: strategy.ExchangeResult,
) -> Result(String, AuthError(e)) {
  let artifacts = strategy.exchange_artifacts(exchange)
  case dict.get(artifacts, "id_token") {
    Ok(value) ->
      case decode.run(value, decode.string) {
        Ok(token) -> Ok(token)
        Error(_) ->
          Error(error.UserInfoFailed(
            reason: "Microsoft tenant enforcement requires an ID token, but the token response did not include one. Ensure the `openid` scope is requested.",
          ))
      }
    Error(_) ->
      Error(error.UserInfoFailed(
        reason: "Microsoft tenant enforcement requires an ID token, but the token response did not include one. Ensure the `openid` scope is requested.",
      ))
  }
}

/// Verify that a Microsoft OpenID Connect ID token was issued by the expected
/// tenant.
///
/// Reads the `tid` (tenant id) claim from the ID token payload and compares it,
/// case-insensitively, against `expected_tenant`. Returns the token's `tid` on
/// success, or an `AuthError` when the claim is missing, malformed, or belongs
/// to a different tenant.
///
/// The ID token is delivered to the client over the back-channel directly from
/// Microsoft's token endpoint over TLS, so its payload is trusted without a
/// separate JWKS signature check (OpenID Connect Core 1.0, section 3.1.3.7).
pub fn verify_tenant(
  expected_tenant expected_tenant: String,
  id_token id_token: String,
) -> Result(String, AuthError(e)) {
  use tid <- result.try(id_token_tenant(id_token))
  case string.lowercase(tid) == string.lowercase(expected_tenant) {
    True -> Ok(tid)
    False ->
      Error(error.UserInfoFailed(
        reason: "Microsoft tenant mismatch: ID token was issued by tenant "
        <> tid
        <> " but this strategy is locked to tenant "
        <> expected_tenant,
      ))
  }
}

/// Extract the `tid` (tenant id) claim from a Microsoft ID token's payload.
///
/// Decodes the JWT payload segment (base64url) and reads the `tid` claim. Does
/// not verify the JWT signature — see `verify_tenant` for the trust rationale.
pub fn id_token_tenant(id_token: String) -> Result(String, AuthError(e)) {
  use payload <- result.try(decode_jwt_payload(id_token))
  let decoder = {
    use tid <- decode.optional_field(
      "tid",
      None,
      decode.optional(decode.string),
    )
    decode.success(tid)
  }
  case json.parse(payload, decoder) {
    Ok(Some(tid)) -> Ok(tid)
    Ok(None) ->
      Error(error.UserInfoFailed(
        reason: "Microsoft ID token is missing the `tid` (tenant id) claim",
      ))
    Error(_) ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse Microsoft ID token payload",
      ))
  }
}

fn decode_jwt_payload(id_token: String) -> Result(String, AuthError(e)) {
  case string.split(id_token, ".") {
    [_header, payload, ..] ->
      case bit_array.base64_url_decode(payload) {
        Ok(bits) ->
          case bit_array.to_string(bits) {
            Ok(json_payload) -> Ok(json_payload)
            Error(_) ->
              Error(error.UserInfoFailed(
                reason: "Microsoft ID token payload is not valid UTF-8",
              ))
          }
        Error(_) ->
          Error(error.UserInfoFailed(
            reason: "Microsoft ID token payload is not valid base64url",
          ))
      }
    _ ->
      Error(error.UserInfoFailed(
        reason: "Malformed Microsoft ID token: expected a JWT with a payload segment",
      ))
  }
}
