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
import vestibule/strategy.{type Strategy, type UserResult, Strategy, UserResult}
import vestibule/user_info

/// Create a Google authentication strategy.
pub fn strategy() -> Strategy(e) {
  Strategy(
    provider: "google",
    default_scopes: ["openid", "profile", "email"],
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    refresh_token: do_refresh_token,
    fetch_user: do_fetch_user,
  )
}

/// Parse Google token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_oauth_token_response(
    body,
    provider_support.RequiredScope(separator: " "),
  )
}

/// Parse Google /oauth2/v3/userinfo response JSON.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
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
    let verified_email = case email, email_verified {
      Some(addr), Some(True) -> Some(addr)
      _, _ -> None
    }
    decode.success(#(
      sub,
      user_info.UserInfo(
        name: name,
        email: verified_email,
        nickname: email,
        image: picture,
        description: None,
        urls: dict.new(),
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(err) ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse Google user response: " <> string.inspect(err),
      ))
  }
}

fn do_authorize_url(
  cfg: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://accounts.google.com")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse Google OAuth base URL")
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
      uri_builder.RelativePath("/o/oauth2/v2/auth"),
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
    uri.parse("https://oauth2.googleapis.com")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse Google OAuth base URL")
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
        reason: "Failed to connect to Google token endpoint",
      ))
  }
}

fn do_refresh_token(
  cfg: Config,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  use site <- result.try(
    uri.parse("https://oauth2.googleapis.com")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse Google OAuth base URL")
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

  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(provider_support.check_response_status(response))
      provider_support.parse_oauth_token_response(
        body,
        provider_support.OptionalScope(" "),
      )
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Google token endpoint",
      ))
  }
}

fn do_fetch_user(
  _cfg: Config,
  creds: Credentials,
) -> Result(UserResult, AuthError(e)) {
  use auth_header <- result.try(strategy.authorization_header(creds))
  use #(uid, info) <- result.try(provider_support.fetch_json_with_auth(
    "https://www.googleapis.com/oauth2/v3/userinfo",
    auth_header,
    parse_user_response,
    "Google userinfo",
  ))
  Ok(UserResult(uid: uid, info: info, extra: dict.new()))
}
