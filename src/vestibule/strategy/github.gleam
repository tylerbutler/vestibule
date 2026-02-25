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
import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info.{type UserInfo}

/// Create a GitHub authentication strategy.
pub fn strategy() -> Strategy(e) {
  Strategy(
    provider: "github",
    default_scopes: ["user:email"],
    token_url: "https://github.com/login/oauth/access_token",
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
}

/// Parse a GitHub token exchange response into Credentials.
/// Exported for testing.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  // First check if it's an error response
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
    decode.success(Credentials(
      token: access_token,
      refresh_token: None,
      token_type: token_type,
      expires_at: None,
      scopes: string.split(scope, ","),
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(reason: "Failed to parse token response"))
  }
}

/// Parse a GitHub /user API response into a uid and UserInfo.
/// Exported for testing.
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
      user_info.UserInfo(
        name: name,
        email: None,
        nickname: option.Some(login),
        image: avatar_url,
        description: bio,
        urls: urls,
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    _ ->
      Error(error.UserInfoFailed(reason: "Failed to parse GitHub user response"))
  }
}

/// Parse the primary verified email from GitHub /user/emails response.
/// Exported for testing.
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
  config: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://github.com")
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
      uri_builder.RelativePath("/login/oauth/authorize"),
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
  let assert Ok(site) = uri.parse("https://github.com")
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
      uri_builder.RelativePath("/login/oauth/access_token"),
      code,
      redirect,
    )
    |> request.set_header("accept", "application/json")
  let req = append_code_verifier(req, code_verifier)

  case httpc.send(req) {
    Ok(response) -> parse_token_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to GitHub token endpoint",
      ))
  }
}

fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError(e)) {
  // Fetch user profile
  let assert Ok(user_req) = request.to("https://api.github.com/user")
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
    |> request.set_header("user-agent", "vestibule-gleam")

  let user_response = case httpc.send(user_req) {
    Ok(resp) -> Ok(resp)
    Error(_) ->
      Error(error.NetworkError(reason: "Failed to fetch GitHub user info"))
  }

  use resp <- result.try(user_response)
  use #(uid, info) <- result.try(parse_user_response(resp.body))

  // Fetch verified primary email (best-effort — don't fail if this errors)
  let assert Ok(email_req) = request.to("https://api.github.com/user/emails")
  let email_req =
    email_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
    |> request.set_header("user-agent", "vestibule-gleam")

  let email = case httpc.send(email_req) {
    Ok(response) -> parse_primary_email(response.body)
    Error(_) -> None
  }

  let final_info = case email {
    option.Some(_) -> user_info.UserInfo(..info, email: email)
    None -> info
  }

  Ok(#(uid, final_info))
}

/// Append code_verifier to the form-encoded request body when present.
fn append_code_verifier(
  req: request.Request(String),
  code_verifier: Option(String),
) -> request.Request(String) {
  case code_verifier {
    option.Some(verifier) -> {
      let body = case req.body {
        "" -> "code_verifier=" <> uri.percent_encode(verifier)
        existing ->
          existing <> "&code_verifier=" <> uri.percent_encode(verifier)
      }
      request.set_body(req, body)
    }
    None -> req
  }
}
