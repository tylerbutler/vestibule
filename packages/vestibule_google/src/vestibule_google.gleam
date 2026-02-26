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
import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info

/// Create a Google authentication strategy.
pub fn strategy() -> Strategy(e) {
  Strategy(
    provider: "google",
    default_scopes: ["openid", "profile", "email"],
    token_url: "https://oauth2.googleapis.com/token",
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
}

/// Parse Google token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.optional_field(
      "error_description",
      "",
      decode.string,
    )
    decode.success(#(error_code, description))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description)) ->
      Error(error.ProviderError(code: code, description: description))
    _ -> parse_success_token(body)
  }
}

fn parse_success_token(body: String) -> Result(Credentials, AuthError(e)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use scope <- decode.field("scope", decode.string)
    use expires_in <- decode.optional_field(
      "expires_in",
      None,
      decode.optional(decode.int),
    )
    use refresh_token <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(Credentials(
      token: access_token,
      refresh_token: refresh_token,
      token_type: token_type,
      expires_at: expires_in,
      scopes: string.split(scope, " "),
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse Google token response",
      ))
  }
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
    _ ->
      Error(error.UserInfoFailed(reason: "Failed to parse Google user response"))
  }
}

fn do_authorize_url(
  config: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://accounts.google.com")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
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
  Ok(url)
}

fn do_exchange_code(
  config: Config,
  code: String,
  code_verifier: Option(String),
) -> Result(Credentials, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://oauth2.googleapis.com")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
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
      use body <- result.try(error.check_http_status(
        response.status,
        response.body,
      ))
      parse_token_response(body)
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Google token endpoint",
      ))
  }
}

fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, user_info.UserInfo), AuthError(e)) {
  let assert Ok(user_req) =
    request.to("https://www.googleapis.com/oauth2/v3/userinfo")
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
  case httpc.send(user_req) {
    Ok(response) -> {
      use body <- result.try(error.check_http_status(
        response.status,
        response.body,
      ))
      parse_user_response(body)
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Google userinfo API",
      ))
  }
}
