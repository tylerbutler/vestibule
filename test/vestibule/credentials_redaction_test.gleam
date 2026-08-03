//// Security regression tests for issue #59: inspect/debug output of
//// `Credentials` (and an `Auth` that contains one) must never reveal raw
//// access or refresh token values.

import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import startest/expect
import vestibule/auth
import vestibule/credentials
import vestibule/user_info

const access_token = "ACCESS-TOKEN-SECRET-7f3a"

const refresh_secret = "REFRESH-TOKEN-SECRET-9b21"

fn sample_credentials() -> credentials.Credentials {
  credentials.new(
    token: access_token,
    refresh_token: Some(refresh_secret),
    token_type: "Bearer",
    expires_in: Some(3600),
    scopes: ["email", "profile"],
  )
}

pub fn inspect_credentials_does_not_leak_tokens_test() -> Nil {
  let rendered = string.inspect(sample_credentials())

  string.contains(rendered, access_token) |> expect.to_be_false()
  string.contains(rendered, refresh_secret) |> expect.to_be_false()
}

pub fn inspect_auth_does_not_leak_tokens_test() -> Nil {
  let result =
    auth.new(
      uid: "user-123",
      provider: "github",
      info: user_info.new(),
      credentials: sample_credentials(),
      extra: dict.new(),
    )

  let rendered = string.inspect(result)

  string.contains(rendered, access_token) |> expect.to_be_false()
  string.contains(rendered, refresh_secret) |> expect.to_be_false()
}

pub fn accessors_still_expose_raw_tokens_test() -> Nil {
  let oauth_credentials = sample_credentials()

  credentials.token(oauth_credentials) |> expect.to_equal(access_token)
  credentials.refresh_token(oauth_credentials)
  |> expect.to_equal(Some(refresh_secret))
}

pub fn credentials_without_refresh_token_inspects_cleanly_test() -> Nil {
  let oauth_credentials =
    credentials.new(
      token: access_token,
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: [],
    )

  string.inspect(oauth_credentials)
  |> string.contains(access_token)
  |> expect.to_be_false()

  credentials.refresh_token(oauth_credentials) |> expect.to_equal(None)
}
