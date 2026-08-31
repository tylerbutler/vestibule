//// Microsoft Identity Platform (v2.0) strategy.
////
//// Requests `openid User.Read` by default. Tokens are exchanged against
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
import gleam/bool
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
import gleam/http/response
import gleam/httpc

import glow_auth
import glow_auth/authorize_uri
import glow_auth/token_request
import glow_auth/uri/uri_builder

import vestibule/config.{type AuthorizeOptions, type ClientConfig}
import vestibule/credential.{type Credentials}
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
  strategy.new(
    provider: "microsoft",
    default_scopes: ["openid", "User.Read"],
    authorize_url: fn(client_configuration, options, scopes, state) {
      do_authorize_url(authority, client_configuration, options, scopes, state)
    },
    exchange_code: fn(client_configuration, code, code_verifier) {
      do_exchange_code(authority, client_configuration, code, code_verifier)
    },
    fetch_user: fn(client_configuration, exchange) {
      do_fetch_user(expected_tenant, client_configuration, exchange)
    },
  )
  |> strategy.with_nonce()
  |> strategy.with_refresh(fn(client_configuration, refresh_token) {
    do_refresh_token(authority, client_configuration, refresh_token)
  })
}

fn authority_base(authority: String) -> String {
  "https://login.microsoftonline.com/" <> authority <> "/oauth2/v2.0"
}

/// Parse Microsoft token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_oauth_token_response(
    body,
    provider_support.RequiredScope(separator: " "),
  )
}

/// Build a Microsoft authorization-code token request without sending it.
///
/// Use `"common"` for the multi-tenant endpoint or pass a tenant GUID to
/// match `strategy_for_tenant`.
pub fn build_authorization_code_request(
  authority: String,
  client_configuration: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(request.Request(String), AuthError(e)) {
  use site <- result.try(
    uri.parse(authority_base(authority))
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Microsoft OAuth base URL")
    }),
  )
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(
      client_configuration,
    )),
  )
  use client_secret <- result.try(config.client_secret(client_configuration))
  let client =
    glow_auth.Client(
      id: config.client_id(client_configuration),
      secret: client_secret,
      site: site,
    )
  let token_http_request =
    token_request.authorization_code(
      client,
      uri_builder.RelativePath("/token"),
      code,
      redirect,
    )
    |> request.set_header("accept", "application/json")
  Ok(strategy.append_code_verifier(token_http_request, code_verifier))
}

/// Parse Microsoft's authorization-code HTTP response without performing I/O.
pub fn parse_authorization_code_response(
  http_response: response.Response(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use body <- result.try(provider_support.check_response_status(http_response))
  parse_exchange_result(body)
}

/// Build a Microsoft refresh-token request without sending it.
///
/// Use the same `authority` value as the authorization-code request.
pub fn build_refresh_token_request(
  authority: String,
  client_configuration: ClientConfig,
  refresh_token: String,
) -> Result(request.Request(String), AuthError(e)) {
  use site <- result.try(
    uri.parse(authority_base(authority))
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Microsoft OAuth base URL")
    }),
  )
  use client_secret <- result.try(config.client_secret(client_configuration))
  let client =
    glow_auth.Client(
      id: config.client_id(client_configuration),
      secret: client_secret,
      site: site,
    )
  Ok(
    token_request.refresh(
      client,
      uri_builder.RelativePath("/token"),
      refresh_token,
    )
    |> request.set_header("accept", "application/json"),
  )
}

/// Parse Microsoft's refresh-token HTTP response without performing I/O.
pub fn parse_refresh_token_response(
  http_response: response.Response(String),
) -> Result(Credentials, AuthError(e)) {
  use body <- result.try(provider_support.check_response_status(http_response))
  parse_token_response(body)
}

/// Parse Microsoft Graph /me response JSON.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let decoder = {
    use user_id <- decode.field("id", decode.string)
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
    use user_principal_name <- decode.field("userPrincipalName", decode.string)
    use job_title <- decode.optional_field(
      "jobTitle",
      None,
      decode.optional(decode.string),
    )
    let email = mail
    decode.success(#(
      user_id,
      user_info.new()
        |> user_info.with_name(display_name)
        |> user_info.with_email(email)
        |> user_info.with_nickname(Some(user_principal_name))
        |> user_info.with_description(job_title),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(parse_error) ->
      Error(error.user_info(
        reason: "Failed to parse Microsoft user response: "
        <> string.inspect(parse_error),
      ))
  }
}

/// Build the Microsoft Graph `/me` request without sending it.
pub fn build_user_info_request(
  oauth_credentials: Credentials,
) -> Result(request.Request(String), AuthError(e)) {
  use authorization_header <- result.try(strategy.authorization_header(
    oauth_credentials,
  ))
  provider_support.build_json_request_with_auth(
    "https://graph.microsoft.com/v1.0/me",
    authorization_header,
    "Microsoft Graph",
  )
}

/// Parse a Microsoft Graph `/me` HTTP response without performing I/O.
pub fn parse_user_info_response(
  http_response: response.Response(String),
) -> Result(#(String, UserInfo), AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_user_response)
}

fn do_authorize_url(
  authority: String,
  client_configuration: ClientConfig,
  options: AuthorizeOptions,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  use site <- result.try(
    uri.parse(authority_base(authority))
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Microsoft OAuth base URL")
    }),
  )
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(
      client_configuration,
    )),
  )
  let client =
    glow_auth.Client(
      id: config.client_id(client_configuration),
      secret: "",
      site: site,
    )
  let scopes = scopes_with_openid(scopes)
  let authorize_url =
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
      dict.to_list(config.extra_params(options)),
    )
  Ok(authorize_url)
}

fn scopes_with_openid(scopes: List(String)) -> List(String) {
  use <- bool.guard(when: list.contains(scopes, "openid"), return: scopes)
  ["openid", ..scopes]
}

fn do_exchange_code(
  authority: String,
  client_configuration: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use token_http_request <- result.try(build_authorization_code_request(
    authority,
    client_configuration,
    code,
    code_verifier,
  ))
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: Some("microsoft"),
    fields: [logger.field("endpoint", "token")],
  )
  |> logger.emit()
  case httpc.send(token_http_request) {
    Ok(response) -> parse_authorization_code_response(response)
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
      Error(error.network(
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
  use oauth_credentials <- result.try(parse_token_response(body))
  Ok(strategy.exchange_result_with_artifacts(
    oauth_credentials,
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
  client_configuration: ClientConfig,
  refresh_token: String,
) -> Result(Credentials, AuthError(e)) {
  use refresh_http_request <- result.try(build_refresh_token_request(
    authority,
    client_configuration,
    refresh_token,
  ))

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: Some("microsoft"),
    fields: [logger.field("endpoint", "refresh")],
  )
  |> logger.emit()
  case httpc.send(refresh_http_request) {
    Ok(response) -> parse_refresh_token_response(response)
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
      Error(error.network(
        reason: "Failed to connect to Microsoft token endpoint",
      ))
    }
  }
}

fn do_fetch_user(
  expected_tenant: Option(String),
  _client_configuration: ClientConfig,
  exchange: strategy.ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  use _ <- result.try(enforce_tenant(expected_tenant, exchange))
  use user_info_request <- result.try(
    build_user_info_request(strategy.exchange_credentials(exchange)),
  )
  use user_info_response <- result.try(
    httpc.send(user_info_request)
    |> result.replace_error(error.network(
      reason: "Failed to connect to Microsoft Graph",
    )),
  )
  use #(user_id, user_information) <- result.try(parse_user_info_response(
    user_info_response,
  ))
  Ok(strategy.user_result(
    uid: user_id,
    info: user_information,
    extra: dict.new(),
  ))
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
    Some(tenant_id) -> {
      use id_token <- result.try(exchange_id_token(exchange))
      use _ <- result.try(verify_tenant(
        expected_tenant: tenant_id,
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
          Error(error.user_info(
            reason: "Microsoft tenant enforcement requires an ID token, but the token response did not include one. Ensure the `openid` scope is requested.",
          ))
      }
    Error(_) ->
      Error(error.user_info(
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
  use tenant_id <- result.try(id_token_tenant(id_token))
  case string.lowercase(tenant_id) == string.lowercase(expected_tenant) {
    True -> Ok(tenant_id)
    False ->
      Error(error.user_info(
        reason: "Microsoft tenant mismatch: ID token was issued by tenant "
        <> tenant_id
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
    use tenant_id <- decode.optional_field(
      "tid",
      None,
      decode.optional(decode.string),
    )
    decode.success(tenant_id)
  }
  case json.parse(payload, decoder) {
    Ok(Some(tenant_id)) -> Ok(tenant_id)
    Ok(None) ->
      Error(error.user_info(
        reason: "Microsoft ID token is missing the `tid` (tenant id) claim",
      ))
    Error(_) ->
      Error(error.user_info(
        reason: "Failed to parse Microsoft ID token payload",
      ))
  }
}

fn decode_jwt_payload(id_token: String) -> Result(String, AuthError(e)) {
  case string.split(id_token, ".") {
    [_jwt_header, payload, ..] ->
      case bit_array.base64_url_decode(payload) {
        Ok(bits) ->
          case bit_array.to_string(bits) {
            Ok(json_payload) -> Ok(json_payload)
            Error(_) ->
              Error(error.user_info(
                reason: "Microsoft ID token payload is not valid UTF-8",
              ))
          }
        Error(_) ->
          Error(error.user_info(
            reason: "Microsoft ID token payload is not valid base64url",
          ))
      }
    _ ->
      Error(error.user_info(
        reason: "Malformed Microsoft ID token: expected a JWT with a payload segment",
      ))
  }
}
