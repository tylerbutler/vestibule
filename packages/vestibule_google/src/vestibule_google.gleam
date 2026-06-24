//// Google OAuth 2.0 / OIDC strategy.
////
//// Uses Google's discovery document to build authorize/token/userinfo
//// endpoints, requests `openid email profile` by default, and validates
//// `email_verified` before populating the user's email (`user_info.email`).

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

import vestibule/config.{type AuthorizeOptions, type ClientConfig}
import vestibule/credentials.{type Credentials}
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
  strategy.new(provider: "google", default_scopes: [
    "openid",
    "profile",
    "email",
  ])
  |> strategy.with_nonce()
  |> strategy.with_authorize_url(do_authorize_url)
  |> strategy.with_exchange_code(do_exchange_code)
  |> strategy.with_refresh(do_refresh_token)
  |> strategy.with_fetch_user(fn(_cfg, exchange) {
    fetch_user_enforcing(exchange, None)
  })
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
  strategy.new(provider: "google", default_scopes: [
    "openid",
    "profile",
    "email",
  ])
  |> strategy.with_nonce()
  |> strategy.with_authorize_url(fn(cfg, options, scopes, state) {
    do_authorize_url_with_hd(cfg, options, scopes, state, Some(hosted_domain))
  })
  |> strategy.with_exchange_code(do_exchange_code)
  |> strategy.with_refresh(do_refresh_token)
  |> strategy.with_fetch_user(fn(_cfg, exchange) {
    fetch_user_enforcing(exchange, Some(hosted_domain))
  })
}

/// Parse Google token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  do_parse_token_response(
    body,
    provider_support.RequiredScope(separator: " "),
    "token",
  )
}

fn do_parse_token_response(
  body: String,
  scope_parsing: provider_support.ScopeParsing,
  endpoint: String,
) -> Result(Credentials, AuthError(e)) {
  let result = provider_support.parse_oauth_token_response(body, scope_parsing)
  case result {
    Ok(creds) -> {
      logger.new(
        level: logger.Debug,
        event: "vestibule.provider.token_parse.success",
        phase: "provider_request",
        outcome: "success",
        provider: Some("google"),
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
        provider: Some("google"),
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
  parse_user_response_with_hd(body)
  |> result.map(fn(parsed) {
    let #(uid, info, _hd) = parsed
    #(uid, info)
  })
}

/// Parse Google userinfo JSON, also extracting the optional `hd`
/// (hosted-domain) claim used for Workspace domain enforcement.
///
/// The third tuple element is the raw `hd` claim, or `None` when the account
/// is a consumer (gmail.com) account or Google omits the claim.
pub fn parse_user_response_with_hd(
  body: String,
) -> Result(#(String, user_info.UserInfo, Option(String)), AuthError(e)) {
  let decoder = {
    use sub <- decode.field("sub", decode.string)
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
    use hd <- decode.optional_field("hd", None, decode.optional(decode.string))
    let verified_email = case email, email_verified {
      Some(addr), Some(True) -> Some(addr)
      _, _ -> None
    }
    decode.success(#(
      sub,
      user_info.new()
        |> user_info.with_name(name)
        |> user_info.with_email(verified_email)
        |> user_info.with_nickname(email)
        |> user_info.with_image(picture),
      hd,
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(err) ->
      Error(error.user_info(
        reason: "Failed to parse Google user response: " <> string.inspect(err),
      ))
  }
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
    None, _ -> Ok(returned)
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
  cfg: ClientConfig,
  options: AuthorizeOptions,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  do_authorize_url_with_hd(cfg, options, scopes, state, None)
}

fn do_authorize_url_with_hd(
  cfg: ClientConfig,
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
    provider_support.parse_redirect_uri(config.redirect_uri(cfg)),
  )
  let client =
    glow_auth.Client(id: config.client_id(cfg), secret: "", site: site)
  let extra_params = case hosted_domain {
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
    |> provider_support.append_query_params(extra_params)
  Ok(url)
}

fn do_exchange_code(
  cfg: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://oauth2.googleapis.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Google OAuth base URL")
    }),
  )
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(cfg)),
  )
  use client_secret <- result.try(config.client_secret(cfg))
  let client =
    glow_auth.Client(
      id: config.client_id(cfg),
      secret: client_secret,
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
    provider: Some("google"),
    fields: [logger.field("endpoint", "token")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(
        provider_support.check_response_status_for_endpoint(
          response,
          provider_name: "google",
          endpoint: "token",
        ),
      )
      parse_token_response(body)
      |> result.map(fn(creds) {
        strategy.exchange_result_with_artifacts(creds, id_token_artifacts(body))
      })
    }
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
  cfg: ClientConfig,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://oauth2.googleapis.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse Google OAuth base URL")
    }),
  )
  use client_secret <- result.try(config.client_secret(cfg))
  let client =
    glow_auth.Client(
      id: config.client_id(cfg),
      secret: client_secret,
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
    provider: Some("google"),
    fields: [logger.field("endpoint", "refresh")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(
        provider_support.check_response_status_for_endpoint(
          response,
          provider_name: "google",
          endpoint: "refresh",
        ),
      )
      do_parse_token_response(
        body,
        provider_support.OptionalScope(separator: " "),
        "refresh",
      )
    }
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
  required_hd: Option(String),
) -> Result(UserResult, AuthError(e)) {
  use auth_header <- result.try(
    strategy.authorization_header(strategy.exchange_credentials(exchange)),
  )
  use #(uid, info, returned_hd) <- result.try(
    provider_support.fetch_json_with_auth(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      auth_header,
      parse_user_response_with_hd,
      "Google userinfo",
    ),
  )
  use validated_hd <- result.try(validate_hosted_domain(
    required: required_hd,
    returned: returned_hd,
  ))
  let extra = case validated_hd {
    Some(domain) -> dict.from_list([#("hd", dynamic.string(domain))])
    None -> dict.new()
  }
  Ok(strategy.user_result(uid: uid, info: info, extra: extra))
}
