/// IndieAuth token exchange and response parsing.
///
/// Handles the token exchange step of the IndieAuth flow where
/// the authorization code is exchanged for an access token and
/// the user's canonical profile URL.
import gleam/dict
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/httpc
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/internal/http as internal_http
import vestibule/strategy
import vestibule/user_info.{type UserInfo}

/// Profile information from an IndieAuth token response.
pub type IndieAuthProfile {
  IndieAuthProfile(
    /// The canonical user profile URL.
    me: String,
    /// Optional profile name.
    name: Option(String),
    /// Optional profile URL (may differ from `me`).
    url: Option(String),
    /// Optional profile photo URL.
    photo: Option(String),
    /// Optional email address.
    email: Option(String),
  )
}

/// Exchange an authorization code for credentials at the token endpoint.
///
/// IndieAuth uses public client semantics — no `client_secret` is sent.
/// The `client_id` is the application's URL.
pub fn exchange_code(
  token_endpoint: String,
  client_id: String,
  redirect_uri: String,
  code: String,
  code_verifier: Option(String),
) -> Result(Credentials, AuthError(e)) {
  let body =
    uri.query_to_string([
      #("grant_type", "authorization_code"),
      #("code", code),
      #("client_id", client_id),
      #("redirect_uri", redirect_uri),
    ])

  use req <- result.try(
    request.to(token_endpoint)
    |> result.replace_error(error.ConfigError(
      reason: "Invalid token endpoint URL: " <> token_endpoint,
    )),
  )

  let req =
    req
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_header("accept", "application/json")
    |> request.set_body(body)

  // Append PKCE code verifier if present
  let req = strategy.append_code_verifier(req, code_verifier)

  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(internal_http.check_response_status(response))
      parse_token_response(body)
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to IndieAuth token endpoint: "
        <> token_endpoint,
      ))
  }
}

/// Parse an IndieAuth token response into Credentials.
///
/// IndieAuth token responses include:
/// - `access_token` (required)
/// - `token_type` (required, typically "Bearer")
/// - `me` (required, canonical user URL)
/// - `scope` (required)
/// - `profile` (optional, object with name/url/photo/email)
/// - `expires_in` (optional)
/// - `refresh_token` (optional)
///
/// Exported for testing.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  // Check for error response first
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
    _ -> parse_token_success(body)
  }
}

fn parse_token_success(body: String) -> Result(Credentials, AuthError(e)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use scope <- decode.optional_field("scope", "", decode.string)
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
    let scopes = case scope {
      "" -> []
      s -> string.split(s, " ")
    }
    decode.success(Credentials(
      token: access_token,
      refresh_token: refresh_token,
      token_type: token_type,
      expires_at: expires_in,
      scopes: scopes,
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    Error(err) ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse IndieAuth token response: "
        <> string.inspect(err),
      ))
  }
}

/// Parse the `me` and `profile` from an IndieAuth token response.
///
/// Exported for testing.
pub fn parse_profile_from_token_response(
  body: String,
) -> Result(IndieAuthProfile, AuthError(e)) {
  let profile_decoder = {
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    use url <- decode.optional_field(
      "url",
      None,
      decode.optional(decode.string),
    )
    use photo <- decode.optional_field(
      "photo",
      None,
      decode.optional(decode.string),
    )
    use email <- decode.optional_field(
      "email",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(name, url, photo, email))
  }

  let decoder = {
    use me <- decode.field("me", decode.string)
    use profile <- decode.optional_field(
      "profile",
      None,
      decode.optional(profile_decoder),
    )
    let #(name, url, photo, email) = case profile {
      Some(#(n, u, p, e)) -> #(n, u, p, e)
      None -> #(None, None, None, None)
    }
    decode.success(IndieAuthProfile(
      me: me,
      name: name,
      url: url,
      photo: photo,
      email: email,
    ))
  }

  case json.parse(body, decoder) {
    Ok(profile) -> Ok(profile)
    Error(err) ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse IndieAuth profile: " <> string.inspect(err),
      ))
  }
}

/// Fetch user info from the IndieAuth userinfo endpoint.
pub fn fetch_userinfo(
  userinfo_url: String,
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError(e)) {
  use auth_header <- result.try(strategy.authorization_header(creds))

  use req <- result.try(
    request.to(userinfo_url)
    |> result.replace_error(error.ConfigError(
      reason: "Invalid userinfo endpoint URL: " <> userinfo_url,
    )),
  )

  let req =
    req
    |> request.set_header("authorization", auth_header)
    |> request.set_header("accept", "application/json")

  case httpc.send(req) {
    Ok(response) -> {
      use body <- result.try(internal_http.check_response_status(response))
      parse_userinfo_response(body)
    }
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to fetch IndieAuth userinfo: " <> userinfo_url,
      ))
  }
}

/// Parse a userinfo endpoint response.
/// Exported for testing.
pub fn parse_userinfo_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let decoder = {
    use me <- decode.field("me", decode.string)
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    use url <- decode.optional_field(
      "url",
      None,
      decode.optional(decode.string),
    )
    use photo <- decode.optional_field(
      "photo",
      None,
      decode.optional(decode.string),
    )
    use email <- decode.optional_field(
      "email",
      None,
      decode.optional(decode.string),
    )
    let urls = case url {
      Some(u) -> dict.from_list([#("url", u)])
      None -> dict.from_list([#("url", me)])
    }
    decode.success(#(
      me,
      user_info.UserInfo(
        name: name,
        email: email,
        nickname: None,
        image: photo,
        description: None,
        urls: urls,
      ),
    ))
  }

  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(err) ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse IndieAuth userinfo response: "
        <> string.inspect(err),
      ))
  }
}
