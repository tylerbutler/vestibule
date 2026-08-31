//// IndieAuth token exchange and response parsing.
////
//// Handles the token exchange step of the IndieAuth flow where
//// the authorization code is exchanged for an access token and
//// the user's canonical profile URL.

import gleam/dict
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

import vestibule/credential.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/provider_support
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
///
/// Returns the credentials together with the profile the server asserted
/// (whose `me` is required). The caller must confirm that `me` before
/// treating it as the user's identity — see `vestibule_indieauth/profile`.
pub fn exchange_code(
  token_endpoint: String,
  client_id: String,
  redirect_uri: String,
  code: String,
  code_verifier: Option(String),
) -> Result(#(Credentials, IndieAuthProfile), AuthError(e)) {
  use http_request <- result.try(build_authorization_code_request(
    token_endpoint,
    client_id,
    redirect_uri,
    code,
    code_verifier,
  ))

  case provider_support.send_public(http_request) {
    Ok(response) -> parse_authorization_code_response(response)
    Error(send_error) -> Error(send_error)
  }
}

/// Build an IndieAuth authorization-code request without sending it.
///
/// The returned request is opaque and can only be sent with
/// `provider_support.send_public`, which performs DNS validation and address
/// pinning immediately before connecting.
pub fn build_authorization_code_request(
  token_endpoint: String,
  client_id: String,
  redirect_uri: String,
  code: String,
  code_verifier: Option(String),
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use _ <- result.try(provider_support.require_public_https_format(
    token_endpoint,
  ))
  let body =
    uri.query_to_string([
      #("grant_type", "authorization_code"),
      #("code", code),
      #("client_id", client_id),
      #("redirect_uri", redirect_uri),
    ])

  use http_request <- result.try(
    request.to(token_endpoint)
    |> result.replace_error(error.config(
      reason: "Invalid token endpoint URL: " <> token_endpoint,
    )),
  )

  let http_request =
    http_request
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_header("accept", "application/json")
    |> request.set_body(body)

  strategy.append_code_verifier(http_request, code_verifier)
  |> provider_support.secure_request_with_limit(provider_support.TokenResponse)
}

/// Parse an IndieAuth authorization-code HTTP response without performing I/O.
pub fn parse_authorization_code_response(
  http_response: response.Response(String),
) -> Result(#(Credentials, IndieAuthProfile), AuthError(e)) {
  use body <- result.try(provider_support.check_response_status(http_response))
  use oauth_credentials <- result.try(parse_token_response(body))
  use profile <- result.try(parse_profile_from_token_response(body))
  Ok(#(oauth_credentials, profile))
}

/// Exchange a refresh token for fresh credentials at the token endpoint.
///
/// IndieAuth uses public client semantics — no `client_secret` is sent.
/// The `client_id` is the application's URL.
pub fn refresh(
  token_endpoint: String,
  client_id: String,
  refresh_token: String,
) -> Result(Credentials, AuthError(e)) {
  use http_request <- result.try(build_refresh_token_request(
    token_endpoint,
    client_id,
    refresh_token,
  ))

  case provider_support.send_public(http_request) {
    Ok(response) -> parse_refresh_token_response(response)
    Error(send_error) -> Error(send_error)
  }
}

/// Build an IndieAuth refresh-token request without sending it.
///
/// The returned request is opaque and must be sent with
/// `provider_support.send_public`.
pub fn build_refresh_token_request(
  token_endpoint: String,
  client_id: String,
  refresh_token: String,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use _ <- result.try(provider_support.require_public_https_format(
    token_endpoint,
  ))
  let body =
    uri.query_to_string([
      #("grant_type", "refresh_token"),
      #("refresh_token", refresh_token),
      #("client_id", client_id),
    ])

  use http_request <- result.try(
    request.to(token_endpoint)
    |> result.replace_error(error.config(
      reason: "Invalid token endpoint URL: " <> token_endpoint,
    )),
  )

  let http_request =
    http_request
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_header("accept", "application/json")
    |> request.set_body(body)
  provider_support.secure_request_with_limit(
    http_request,
    provider_support.TokenResponse,
  )
}

/// Parse an IndieAuth refresh-token HTTP response without performing I/O.
pub fn parse_refresh_token_response(
  http_response: response.Response(String),
) -> Result(Credentials, AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_token_response)
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
      Error(error.provider(code: code, description: description, uri: None))
    Error(_) -> parse_token_success(body)
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
      scope -> string.split(scope, " ")
    }
    decode.success(credential.new(
      token: access_token,
      refresh_token: refresh_token,
      token_type: token_type,
      expires_in: expires_in,
      scopes: scopes,
    ))
  }
  case json.parse(body, decoder) {
    Ok(oauth_credentials) -> Ok(oauth_credentials)
    Error(parse_error) ->
      Error(error.code_exchange(
        reason: "Failed to parse IndieAuth token response: "
        <> string.inspect(parse_error),
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
      Some(#(name, url, photo, email)) -> #(name, url, photo, email)
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
    Error(parse_error) ->
      Error(error.user_info(
        reason: "Failed to parse IndieAuth profile: "
        <> string.inspect(parse_error),
      ))
  }
}

/// Fetch user info from the IndieAuth userinfo endpoint.
pub fn fetch_userinfo(
  userinfo_url: String,
  oauth_credentials: Credentials,
) -> Result(#(String, UserInfo), AuthError(e)) {
  use http_request <- result.try(build_user_info_request(
    userinfo_url,
    oauth_credentials,
  ))

  case provider_support.send_public(http_request) {
    Ok(response) -> parse_user_info_response(response)
    Error(send_error) -> Error(send_error)
  }
}

/// Build an IndieAuth userinfo request without sending it.
///
/// The returned request is opaque and must be sent with
/// `provider_support.send_public`.
pub fn build_user_info_request(
  userinfo_url: String,
  oauth_credentials: Credentials,
) -> Result(provider_support.SecureRequest, AuthError(e)) {
  use _ <- result.try(provider_support.require_public_https_format(userinfo_url))
  use authorization_header <- result.try(strategy.authorization_header(
    oauth_credentials,
  ))

  use http_request <- result.try(
    request.to(userinfo_url)
    |> result.replace_error(error.config(
      reason: "Invalid userinfo endpoint URL: " <> userinfo_url,
    )),
  )

  let http_request =
    http_request
    |> request.set_header("authorization", authorization_header)
    |> request.set_header("accept", "application/json")
  provider_support.secure_request_with_limit(
    http_request,
    provider_support.UserInfoResponse,
  )
}

/// Parse an IndieAuth userinfo HTTP response without performing I/O.
pub fn parse_user_info_response(
  http_response: response.Response(String),
) -> Result(#(String, UserInfo), AuthError(e)) {
  provider_support.parse_json_response(http_response, parse_userinfo_response)
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
      Some(profile_url) -> dict.from_list([#("url", profile_url)])
      None -> dict.from_list([#("url", me)])
    }
    decode.success(#(
      me,
      user_info.new()
        |> user_info.with_name(name)
        |> user_info.with_email(email)
        |> user_info.with_image(photo)
        |> user_info.with_urls(urls),
    ))
  }

  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    Error(parse_error) ->
      Error(error.user_info(
        reason: "Failed to parse IndieAuth userinfo response: "
        <> string.inspect(parse_error),
      ))
  }
}
