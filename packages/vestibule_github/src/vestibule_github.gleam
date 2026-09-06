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

/// Create a GitHub authentication strategy.
pub fn strategy() -> Strategy(e) {
  strategy.new(
    provider: "github",
    default_scopes: ["user:email"],
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
  |> strategy.with_refresh(do_refresh_token)
}

/// Parse a GitHub token exchange response into Credentials.
/// Supported parsing helper for GitHub strategy integrations.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  use oauth_credentials <- result.try(
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(separator: ","),
    ),
  )
  use _ <- result.try(require_bearer_token(oauth_credentials))
  use _ <- result.try(require_email_scope(oauth_credentials))
  Ok(oauth_credentials)
}

/// Build GitHub's authorization-code token request without sending it.
pub fn build_authorization_code_request(
  client_configuration: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(request.Request(String), AuthError(e)) {
  use site <- result.try(
    uri.parse("https://github.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse GitHub OAuth base URL")
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
      uri_builder.RelativePath("/login/oauth/access_token"),
      code,
      redirect,
    )
    |> request.set_header("accept", "application/json")
  Ok(strategy.append_code_verifier(token_http_request, code_verifier))
}

/// Parse GitHub's authorization-code HTTP response without performing I/O.
pub fn parse_authorization_code_response(
  http_response: response.Response(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_token_response)
  |> result.map(strategy.exchange_result)
}

/// Build GitHub's refresh-token request without sending it.
pub fn build_refresh_token_request(
  client_configuration: ClientConfig,
  refresh_token: String,
) -> Result(request.Request(String), AuthError(e)) {
  use site <- result.try(
    uri.parse("https://github.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse GitHub OAuth base URL")
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
      uri_builder.RelativePath("/login/oauth/access_token"),
      refresh_token,
    )
    |> request.set_header("accept", "application/json"),
  )
}

/// Parse GitHub's refresh-token HTTP response without performing I/O.
pub fn parse_refresh_token_response(
  http_response: response.Response(String),
) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_json_response(http_response, fn(body) {
    use oauth_credentials <- result.try(
      provider_support.parse_oauth_token_response(
        body,
        provider_support.OptionalScope(separator: ","),
      ),
    )
    use _ <- result.try(require_bearer_token(oauth_credentials))
    Ok(oauth_credentials)
  })
}

/// Parse a GitHub /user API response into a user ID and UserInfo.
/// Supported parsing helper for GitHub strategy integrations.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let decoder = {
    use user_id <- decode.field("id", decode.int)
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
    use biography <- decode.optional_field(
      "bio",
      None,
      decode.optional(decode.string),
    )
    use profile_url <- decode.optional_field(
      "html_url",
      None,
      decode.optional(decode.string),
    )
    let profile_urls = case profile_url {
      option.Some(profile_url) -> dict.from_list([#("html_url", profile_url)])
      None -> dict.new()
    }
    decode.success(#(
      int.to_string(user_id),
      user_info.new()
        |> user_info.with_name(name)
        |> user_info.with_nickname(option.Some(login))
        |> user_info.with_image(avatar_url)
        |> user_info.with_description(biography)
        |> user_info.with_urls(profile_urls),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(parse_error) ->
      Error(error.user_info(
        reason: "Failed to parse GitHub user response: "
        <> string.inspect(parse_error),
      ))
  }
}

/// Parse the primary verified email from GitHub /user/emails response.
/// Supported parsing helper for GitHub strategy integrations.
///
/// Returns `Ok(None)` when no primary verified email exists, and an error
/// when the response body cannot be parsed.
pub fn parse_primary_email(
  body: String,
) -> Result(Option(String), AuthError(e)) {
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
      |> list.find(fn(entry) {
        let #(_, primary, verified) = entry
        primary && verified
      })
      |> option.from_result()
      |> option.map(fn(entry) {
        let #(email, _, _) = entry
        email
      })
      |> Ok
    Error(parse_error) ->
      Error(error.user_info(
        reason: "Failed to parse GitHub emails response: "
        <> string.inspect(parse_error),
      ))
  }
}

/// Build GitHub's `/user` request without sending it.
pub fn build_user_info_request(
  oauth_credentials: Credentials,
) -> Result(request.Request(String), AuthError(e)) {
  build_api_request("https://api.github.com/user", oauth_credentials)
}

/// Parse GitHub's `/user` HTTP response without performing I/O.
pub fn parse_user_info_response(
  http_response: response.Response(String),
) -> Result(#(String, UserInfo), AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_user_response)
}

/// Build GitHub's `/user/emails` request without sending it.
pub fn build_user_email_request(
  oauth_credentials: Credentials,
) -> Result(request.Request(String), AuthError(e)) {
  build_api_request("https://api.github.com/user/emails", oauth_credentials)
}

/// Parse GitHub's `/user/emails` HTTP response without performing I/O.
pub fn parse_user_email_response(
  http_response: response.Response(String),
) -> Result(Option(String), AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_primary_email)
}

/// Validate the GitHub callback's user and email responses.
///
/// The numeric `/user` id establishes identity. The email is included only
/// when `/user/emails` returns a primary, verified address; otherwise the
/// callback fails closed.
pub fn parse_callback_user_responses(
  user_response: response.Response(String),
  email_response: response.Response(String),
) -> Result(UserResult, AuthError(e)) {
  use #(user_id, user_information) <- result.try(parse_user_info_response(
    user_response,
  ))
  use email <- result.try(parse_user_email_response(email_response))
  use verified_email <- result.try(case email {
    option.Some(email) -> Ok(email)
    None ->
      Error(error.user_info(
        reason: "GitHub did not return a primary verified email address",
      ))
  })
  Ok(strategy.user_result(
    uid: user_id,
    info: user_info.with_email(user_information, option.Some(verified_email)),
    extra: dict.new(),
  ))
}

fn require_bearer_token(
  oauth_credentials: Credentials,
) -> Result(Nil, AuthError(e)) {
  case string.lowercase(credential.token_type(oauth_credentials)) {
    "bearer" -> Ok(Nil)
    _ ->
      Error(error.code_exchange(
        reason: "GitHub token response must use the Bearer token type",
      ))
  }
}

fn require_email_scope(
  oauth_credentials: Credentials,
) -> Result(Nil, AuthError(e)) {
  let scopes = credential.scopes(oauth_credentials)
  case list.contains(scopes, "user:email") || list.contains(scopes, "user") {
    True -> Ok(Nil)
    False ->
      Error(error.code_exchange(
        reason: "GitHub did not grant the user:email scope",
      ))
  }
}

fn build_api_request(
  url: String,
  oauth_credentials: Credentials,
) -> Result(request.Request(String), AuthError(e)) {
  use authorization_header <- result.try(strategy.authorization_header(
    oauth_credentials,
  ))
  use http_request <- result.try(provider_support.build_json_request_with_auth(
    url,
    authorization_header,
    "GitHub",
  ))
  Ok(request.set_header(http_request, "user-agent", "vestibule-gleam"))
}

fn do_authorize_url(
  client_configuration: ClientConfig,
  options: AuthorizeOptions,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://github.com")
    |> result.map_error(fn(_) {
      error.config(reason: "Failed to parse GitHub OAuth base URL")
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
  let authorization_url =
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
      dict.to_list(config.extra_params(options)),
    )
  Ok(authorization_url)
}

fn do_exchange_code(
  client_configuration: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  use token_http_request <- result.try(build_authorization_code_request(
    client_configuration,
    code,
    code_verifier,
  ))

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("github"),
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
        provider: option.Some("github"),
        fields: [
          logger.field("endpoint", "token"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.network(reason: "Failed to connect to GitHub token endpoint"))
    }
  }
}

fn do_refresh_token(
  client_configuration: ClientConfig,
  refresh_token: String,
) -> Result(Credentials, AuthError(e)) {
  use refresh_http_request <- result.try(build_refresh_token_request(
    client_configuration,
    refresh_token,
  ))

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("github"),
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
        provider: option.Some("github"),
        fields: [
          logger.field("endpoint", "refresh"),
          logger.field("error_category", "network_error"),
        ],
      )
      |> logger.emit()
      Error(error.network(reason: "Failed to connect to GitHub token endpoint"))
    }
  }
}

fn do_fetch_user(
  _client_configuration: ClientConfig,
  exchange: strategy.ExchangeResult,
) -> Result(UserResult, AuthError(e)) {
  let oauth_credentials = strategy.exchange_credentials(exchange)
  use user_request <- result.try(build_user_info_request(oauth_credentials))

  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("github"),
    fields: [logger.field("endpoint", "user_info")],
  )
  |> logger.emit()
  use response <- result.try(case httpc.send(user_request) {
    Ok(response) -> Ok(response)
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
      Error(error.network(reason: "Failed to fetch GitHub user info"))
    }
  })
  use email_request <- result.try(build_user_email_request(oauth_credentials))
  logger.new(
    level: logger.Debug,
    event: "vestibule.provider.request.start",
    phase: "provider_request",
    outcome: "start",
    provider: option.Some("github"),
    fields: [logger.field("endpoint", "user_email")],
  )
  |> logger.emit()
  use email_response <- result.try(
    httpc.send(email_request)
    |> result.replace_error(error.network(
      reason: "Failed to fetch GitHub verified email",
    )),
  )
  parse_callback_user_responses(response, email_response)
}
