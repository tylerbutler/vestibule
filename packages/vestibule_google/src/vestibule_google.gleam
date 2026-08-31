//// Google OAuth 2.0 / OIDC strategy.
////
//// Uses Google's discovery document to build authorize/token/userinfo
//// endpoints, requests `openid email profile` by default, and validates
//// `email_verified` before populating the user's email (`user_info.email`).

import gleam/dict
import gleam/dynamic
import gleam/dynamic/decode
import gleam/json
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
import vestibule/user_info

/// Create a Google authentication strategy.
///
/// This strategy does not enforce a Google Workspace hosted domain. If the
/// userinfo response includes an `hd` claim it is surfaced under the `"hd"`
/// key of `UserResult`'s `extra` dict, but no domain restriction is applied.
/// To restrict sign-in to a single Workspace domain, use
/// `strategy_for_hosted_domain`.
pub fn strategy() -> Strategy(e) {
  strategy.new(
    provider: "google",
    default_scopes: ["openid", "profile", "email"],
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: fn(_client_config, exchange) {
      fetch_user_enforcing(exchange, None)
    },
  )
  |> strategy.with_nonce()
  |> strategy.with_refresh(do_refresh_token)
}

/// Create a Google strategy that enforces a Workspace hosted domain.
///
/// Authentication fails unless Google's userinfo response carries an `hd`
/// (hosted-domain) claim exactly matching `hosted_domain`. A missing or
/// mismatched `hd` yields `error.user_info`. The validated domain is
/// surfaced under the `"hd"` key of `UserResult`'s `extra` dict.
///
/// `hosted_domain` is also added to the authorization URL as an account-picker
/// hint, but that hint is advisory only — enforcement happens server-side when
/// the userinfo response is validated. Setting `hd` via
/// `config.authorize_options() |> config.with_extra_params([#("hd", ...)])` is purely a UI hint and must not
/// be relied on for authorization.
pub fn strategy_for_hosted_domain(hosted_domain: String) -> Strategy(e) {
  strategy.new(
    provider: "google",
    default_scopes: ["openid", "profile", "email"],
    authorize_url: fn(client_config, options, scopes, state) {
      do_authorize_url_with_hosted_domain(
        client_config,
        options,
        scopes,
        state,
        Some(hosted_domain),
      )
    },
    exchange_code: do_exchange_code,
    fetch_user: fn(_client_config, exchange) {
      fetch_user_enforcing(exchange, Some(hosted_domain))
    },
  )
  |> strategy.with_nonce()
  |> strategy.with_refresh(do_refresh_token)
}

/// Parse Google token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  do_parse_token_response(body, provider_support.RequiredScope(separator: " "))
}

/// Build Google's authorization-code token request without sending it.
pub fn build_authorization_code_request(
  client_config: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(request.Request(String), AuthError(e)) {
  use site <- result.try(
    uri.parse("https://oauth2.googleapis.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Google OAuth base URL")
    }),
  )
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(client_config)),
  )
  use client_secret <- result.try(config.client_secret(client_config))
  let client =
    glow_auth.Client(
      id: config.client_id(client_config),
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

/// Parse Google's authorization-code HTTP response without performing I/O.
pub fn parse_authorization_code_response(
  http_response: response.Response(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use body <- result.try(provider_support.check_response_status(http_response))
  use oauth_credentials <- result.try(parse_token_response(body))
  Ok(strategy.exchange_result_with_artifacts(
    oauth_credentials,
    id_token_artifacts(body),
  ))
}

/// Build Google's refresh-token request without sending it.
pub fn build_refresh_token_request(
  client_config: ClientConfig,
  refresh_token: String,
) -> Result(request.Request(String), AuthError(e)) {
  use site <- result.try(
    uri.parse("https://oauth2.googleapis.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Google OAuth base URL")
    }),
  )
  use client_secret <- result.try(config.client_secret(client_config))
  let client =
    glow_auth.Client(
      id: config.client_id(client_config),
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

/// Parse Google's refresh-token HTTP response without performing I/O.
pub fn parse_refresh_token_response(
  http_response: response.Response(String),
) -> Result(Credentials, AuthError(e)) {
  use body <- result.try(provider_support.check_response_status(http_response))
  do_parse_token_response(body, provider_support.OptionalScope(separator: " "))
}

fn do_parse_token_response(
  body: String,
  scope_parsing: provider_support.ScopeParsing,
) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_oauth_token_response(body, scope_parsing)
}

/// Build exchange artifacts carrying the OIDC `id_token` when present, so the
/// core can validate the `nonce` claim on callback.
fn id_token_artifacts(body: String) -> dict.Dict(String, dynamic.Dynamic) {
  case parse_id_token(body) {
    Some(token) -> dict.from_list([#("id_token", dynamic.string(token))])
    None -> dict.new()
  }
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

/// Parse Google /oauth2/v3/userinfo response JSON.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
  parse_user_response_with_hosted_domain(body)
  |> result.map(fn(parsed) {
    let #(user_id, user, _hosted_domain) = parsed
    #(user_id, user)
  })
}

/// Parse Google userinfo JSON, also extracting the optional `hd`
/// (hosted-domain) claim used for Workspace domain enforcement.
///
/// The third tuple element is the raw `hd` claim, or `None` when the account
/// is a consumer (gmail.com) account or Google omits the claim.
pub fn parse_user_response_with_hosted_domain(
  body: String,
) -> Result(#(String, user_info.UserInfo, Option(String)), AuthError(e)) {
  let decoder = {
    use subject <- decode.field("sub", decode.string)
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    use picture <- decode.optional_field(
      "picture",
      None,
      decode.optional(decode.string),
    )
    use email <- decode.optional_field(
      "email",
      None,
      decode.optional(decode.string),
    )
    use email_verified <- decode.optional_field(
      "email_verified",
      None,
      decode.optional(decode.bool),
    )
    use hosted_domain <- decode.optional_field(
      "hd",
      None,
      decode.optional(decode.string),
    )
    let verified_email = case email, email_verified {
      Some(email_address), Some(True) -> Some(email_address)
      Some(_email_address), Some(False) -> None
      Some(_email_address), None -> None
      None, Some(True) -> None
      None, Some(False) -> None
      None, None -> None
    }
    decode.success(#(
      subject,
      user_info.new()
        |> user_info.with_name(name)
        |> user_info.with_email(verified_email)
        |> user_info.with_nickname(email)
        |> user_info.with_image(picture),
      hosted_domain,
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(decode_error) ->
      Error(error.user_info(
        reason: "Failed to parse Google user response: "
        <> string.inspect(decode_error),
      ))
  }
}

/// Build Google's userinfo request without sending it.
pub fn build_user_info_request(
  oauth_credentials: Credentials,
) -> Result(request.Request(String), AuthError(e)) {
  use authorization_header <- result.try(strategy.authorization_header(
    oauth_credentials,
  ))
  provider_support.build_json_request_with_auth(
    "https://www.googleapis.com/oauth2/v3/userinfo",
    authorization_header,
    "Google userinfo",
  )
}

/// Parse Google's userinfo HTTP response without performing I/O.
pub fn parse_user_info_response(
  http_response: response.Response(String),
) -> Result(#(String, user_info.UserInfo, Option(String)), AuthError(e)) {
  provider_support.parse_json_response(
    http_response,
    parse_user_response_with_hosted_domain,
  )
}

/// Validate the returned hosted-domain claim against the required domain.
///
/// When `required` is `None` the returned claim (if any) passes through
/// unchanged. When a domain is required, the claim must be present and match
/// exactly, otherwise authentication fails with `error.user_info`. This
/// is the enforcement primitive behind `strategy_for_hosted_domain`.
pub fn validate_hosted_domain(
  required required: Option(String),
  returned returned: Option(String),
) -> Result(Option(String), AuthError(e)) {
  case required, returned {
    None, Some(actual) -> Ok(Some(actual))
    None, None -> Ok(None)
    Some(expected), Some(actual) ->
      case expected == actual {
        True -> Ok(Some(actual))
        False ->
          Error(error.user_info(
            reason: "Google hosted domain mismatch: expected \""
            <> expected
            <> "\" but the account belongs to \""
            <> actual
            <> "\"",
          ))
      }
    Some(expected), None ->
      Error(error.user_info(
        reason: "Google did not return a hosted domain (hd) claim; cannot enforce hosted-domain restriction to \""
        <> expected
        <> "\"",
      ))
  }
}

fn do_authorize_url(
  client_config: ClientConfig,
  options: AuthorizeOptions,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  do_authorize_url_with_hosted_domain(
    client_config,
    options,
    scopes,
    state,
    None,
  )
}

fn do_authorize_url_with_hosted_domain(
  client_config: ClientConfig,
  options: AuthorizeOptions,
  scopes: List(String),
  state: String,
  hosted_domain: Option(String),
) -> Result(String, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://accounts.google.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Google OAuth base URL")
    }),
  )
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(client_config)),
  )
  let client =
    glow_auth.Client(
      id: config.client_id(client_config),
      secret: "",
      site: site,
    )
  let extra_parameters = case hosted_domain {
    Some(domain) -> [
      #("hd", domain),
      ..dict.to_list(config.extra_params(options))
    ]
    None -> dict.to_list(config.extra_params(options))
  }
  let url =
    authorize_uri.build(
      client,
      uri_builder.RelativePath("/o/oauth2/v2/auth"),
      redirect,
    )
    |> authorize_uri.set_scope(string.join(scopes, " "))
    |> authorize_uri.set_state(state)
    |> authorize_uri.to_code_authorization_uri()
    |> uri.to_string()
    |> provider_support.append_query_params(extra_parameters)
  Ok(url)
}

fn do_exchange_code(
  client_config: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use token_http_request <- result.try(build_authorization_code_request(
    client_config,
    code,
    code_verifier,
  ))
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: Some("google"),
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
        provider: Some("google"),
        fields: [
          logger.field("endpoint", "token"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.network(reason: "Failed to connect to Google token endpoint"))
    }
  }
}

fn do_refresh_token(
  client_config: ClientConfig,
  refresh_token: String,
) -> Result(Credentials, AuthError(e)) {
  use refresh_http_request <- result.try(build_refresh_token_request(
    client_config,
    refresh_token,
  ))

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: Some("google"),
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
        provider: Some("google"),
        fields: [
          logger.field("endpoint", "refresh"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.network(reason: "Failed to connect to Google token endpoint"))
    }
  }
}

fn fetch_user_enforcing(
  exchange: strategy.ExchangeResult,
  required_hosted_domain: Option(String),
) -> Result(UserResult, AuthError(e)) {
  let oauth_credentials = strategy.exchange_credentials(exchange)
  use user_info_request <- result.try(build_user_info_request(oauth_credentials))
  use user_info_response <- result.try(
    httpc.send(user_info_request)
    |> result.replace_error(error.network(
      reason: "Failed to connect to Google userinfo API",
    )),
  )
  use #(user_id, user, returned_hosted_domain) <- result.try(
    parse_user_info_response(user_info_response),
  )
  use validated_hosted_domain <- result.try(validate_hosted_domain(
    required: required_hosted_domain,
    returned: returned_hosted_domain,
  ))
  let extra = case validated_hosted_domain {
    Some(domain) -> dict.from_list([#("hd", dynamic.string(domain))])
    None -> dict.new()
  }
  Ok(strategy.user_result(uid: user_id, info: user, extra: extra))
}
