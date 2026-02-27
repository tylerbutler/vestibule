import gleam/bit_array
import gleam/crypto
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
  // Try error response first
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.field("error_description", decode.string)
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
        reason: "Failed to parse Microsoft token response",
      ))
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
    let image = case email {
      Some(addr) -> Some(gravatar_url(addr))
      None -> None
    }
    decode.success(#(
      id,
      user_info.UserInfo(
        name: display_name,
        email: email,
        nickname: Some(upn),
        image: image,
        description: job_title,
        urls: dict.new(),
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    _ ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse Microsoft user response",
      ))
  }
}

fn do_authorize_url(
  config: Config,
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
    uri.parse(config.redirect_uri)
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Invalid redirect URI: " <> config.redirect_uri)
    }),
  )
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
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
  Ok(url)
}

fn do_exchange_code(
  config: Config,
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
    uri.parse(config.redirect_uri)
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Invalid redirect URI: " <> config.redirect_uri)
    }),
  )
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
    Ok(response) -> parse_token_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Microsoft token endpoint",
      ))
  }
}

fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError(e)) {
  use user_req <- result.try(
    request.to("https://graph.microsoft.com/v1.0/me")
    |> result.map_error(fn(_) {
      error.ConfigError(reason: "Failed to parse Microsoft Graph user URL")
    }),
  )
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
  case httpc.send(user_req) {
    Ok(response) -> parse_user_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Microsoft Graph API",
      ))
  }
}

fn gravatar_url(email: String) -> String {
  let hash =
    email
    |> string.lowercase
    |> string.trim
    |> fn(e) { <<e:utf8>> }
    |> crypto.hash(crypto.Sha256, _)
    |> bit_array.base16_encode
    |> string.lowercase
  "https://www.gravatar.com/avatar/" <> hash <> "?d=identicon"
}
