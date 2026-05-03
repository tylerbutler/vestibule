import gleam/dict
import gleam/dynamic/decode
import gleam/json
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
import vestibule/provider_support
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info.{type UserInfo}

/// Create a Microsoft authentication strategy using /common tenant.
pub fn strategy() -> Strategy(e) {
  Strategy(
    provider: "microsoft",
    default_scopes: ["User.Read"],
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
}

/// Parse Microsoft token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_oauth_token_response(
    body,
    provider_support.RequiredScope(separator: " "),
  )
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
  cfg: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://login.microsoftonline.com/common/oauth2/v2.0")
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
  cfg: Config,
  code: String,
  code_verifier: Option(String),
) -> Result(Credentials, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://login.microsoftonline.com/common/oauth2/v2.0")
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
  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(provider_support.check_response_status(response))
      parse_token_response(body)
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Microsoft token endpoint",
      ))
  }
}

fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError(e)) {
  use auth_header <- result.try(strategy.authorization_header(creds))
  provider_support.fetch_json_with_auth(
    "https://graph.microsoft.com/v1.0/me",
    auth_header,
    parse_user_response,
    "Microsoft Graph",
  )
}
