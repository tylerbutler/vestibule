import gleam/dict
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None}
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

/// Create a GitHub authentication strategy.
pub fn strategy() -> Strategy(e) {
  strategy.new(
    provider: "github",
    default_scopes: ["user:email"],
    uses_nonce: False,
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    refresh_token: do_refresh_token,
    fetch_user: do_fetch_user,
  )
}

/// Parse a GitHub token exchange response into Credentials.
/// Supported parsing helper for GitHub strategy integrations.
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
      provider_support.RequiredScope(separator: ","),
    )
  case result {
    Ok(creds) -> {
      logger.new(
        level: logger.Debug,
        event: "vestibule.provider.token_parse.success",
        phase: "provider_request",
        outcome: "success",
        provider: option.Some("github"),
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
        provider: option.Some("github"),
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

/// Parse a GitHub /user API response into a uid and UserInfo.
/// Supported parsing helper for GitHub strategy integrations.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let decoder = {
    use id <- decode.field("id", decode.int)
    use login <- decode.field("login", decode.string)
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    use avatar_url <- decode.optional_field(
      "avatar_url",
      None,
      decode.optional(decode.string),
    )
    use bio <- decode.optional_field(
      "bio",
      None,
      decode.optional(decode.string),
    )
    use html_url <- decode.optional_field(
      "html_url",
      None,
      decode.optional(decode.string),
    )
    let urls = case html_url {
      option.Some(url) -> dict.from_list([#("html_url", url)])
      None -> dict.new()
    }
    decode.success(#(
      int.to_string(id),
      user_info.new()
        |> user_info.with_name(name)
        |> user_info.with_nickname(option.Some(login))
        |> user_info.with_image(avatar_url)
        |> user_info.with_description(bio)
        |> user_info.with_urls(urls),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(err) ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse GitHub user response: " <> string.inspect(err),
      ))
  }
}

/// Parse the primary verified email from GitHub /user/emails response.
/// Supported parsing helper for GitHub strategy integrations.
pub fn parse_primary_email(body: String) -> Option(String) {
  let email_decoder = {
    use email <- decode.field("email", decode.string)
    use primary <- decode.field("primary", decode.bool)
    use verified <- decode.field("verified", decode.bool)
    decode.success(#(email, primary, verified))
  }
  let list_decoder = decode.list(email_decoder)
  case json.parse(body, list_decoder) {
    Ok(emails) ->
      emails
      |> list.find(fn(e) {
        let #(_, primary, verified) = e
        primary && verified
      })
      |> option.from_result()
      |> option.map(fn(e) {
        let #(email, _, _) = e
        email
      })
    _ -> None
  }
}

fn do_authorize_url(
  cfg: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://github.com")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse GitHub OAuth base URL")
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
      uri_builder.RelativePath("/login/oauth/authorize"),
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
  cfg: Config,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://github.com")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse GitHub OAuth base URL")
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
      uri_builder.RelativePath("/login/oauth/access_token"),
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
    provider: option.Some("github"),
    fields: [logger.field("endpoint", "token")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(
        provider_support.check_response_status_for_endpoint(
          response,
          provider_name: "github",
          endpoint: "token",
        ),
      )
      parse_token_response(body)
      |> result.map(strategy.exchange_result)
    }
    Error(_) -> {
      logger.new(
        level: logger.Error,
        event: "vestibule.provider.request.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: option.Some("github"),
        fields: [
          logger.field("endpoint", "token"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.NetworkError(
        reason: "Failed to connect to GitHub token endpoint",
      ))
    }
  }
}

fn do_refresh_token(
  cfg: Config,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://github.com")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse GitHub OAuth base URL")
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
      uri_builder.RelativePath("/login/oauth/access_token"),
      refresh_tok,
    )
    |> request.set_header("accept", "application/json")

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("github"),
    fields: [logger.field("endpoint", "refresh")],
  )
  |> logger.emit()
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(
        provider_support.check_response_status_for_endpoint(
          response,
          provider_name: "github",
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
        provider: option.Some("github"),
        fields: [
          logger.field("endpoint", "refresh"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.NetworkError(
        reason: "Failed to connect to GitHub token endpoint",
      ))
    }
  }
}

fn do_fetch_user(
  _cfg: Config,
  exchange: strategy.ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  let creds = strategy.exchange_credentials(exchange)
  // Validate token type
  use auth_header <- result.try(strategy.authorization_header(creds))

  // Fetch user profile
  use user_req <- result.try(
    request.to("https://api.github.com/user")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse GitHub user URL")
    }),
  )
  let user_req =
    user_req
    |> request.set_header("authorization", auth_header)
    |> request.set_header("accept", "application/json")
    |> request.set_header("user-agent", "vestibule-gleam")

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("github"),
    fields: [logger.field("endpoint", "user_info")],
  )
  |> logger.emit()
  use resp <- result.try(case httpc.send(user_req) {
    Ok(r) -> Ok(r)
    Error(_) -> {
      logger.new(
        level: logger.Error,
        event: "vestibule.provider.request.failure",
        phase: "provider_request",
        outcome: "failure",
        provider: option.Some("github"),
        fields: [
          logger.field("endpoint", "user_info"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.NetworkError(reason: "Failed to fetch GitHub user info"))
    }
  })
  use user_body <- result.try(
    provider_support.check_response_status_for_endpoint(
      resp,
      provider_name: "github",
      endpoint: "user_info",
    ),
  )
  use #(uid, info) <- result.try(parse_user_response(user_body))

  // Fetch verified primary email (best-effort — don't fail if this errors)
  let email = case request.to("https://api.github.com/user/emails") {
    Ok(email_req) -> {
      let email_req =
        email_req
        |> request.set_header("authorization", auth_header)
        |> request.set_header("accept", "application/json")
        |> request.set_header("user-agent", "vestibule-gleam")
      logger.new(
        level: logger.Debug,
        event: "vestibule.provider.request.start",
        phase: "provider_request",
        outcome: "start",
        provider: option.Some("github"),
        fields: [logger.field("endpoint", "user_email")],
      )
      |> logger.emit()
      case httpc.send(email_req) {
        Ok(response) ->
          provider_support.check_response_status_for_endpoint(
            response,
            provider_name: "github",
            endpoint: "user_email",
          )
          |> result.map(parse_primary_email)
          |> result.unwrap(None)
        Error(_) -> {
          logger.new(
            level: logger.Error,
            event: "vestibule.provider.request.failure",
            phase: "provider_request",
            outcome: "failure",
            provider: option.Some("github"),
            fields: [
              logger.field("endpoint", "user_email"),
              logger.field("error_category", "network_error"),
            ],
          )
          |> logger.emit()
          None
        }
      }
    }
    Error(_) -> None
  }

  let final_info = case email {
    option.Some(_) -> user_info.with_email(info, email)
    None -> info
  }

  Ok(strategy.user_result(uid: uid, info: final_info, extra: dict.new()))
}
