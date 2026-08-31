//// Security regression tests for issue #59: inspect/debug output of
//// `Credentials` (and an `Auth` that contains one) must never reveal raw
//// access or refresh token values.

import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import vestibule/auth
import vestibule/credential
import vestibule/user_info

const access_token = "ACCESS-TOKEN-SECRET-7f3a"

const refresh_secret = "REFRESH-TOKEN-SECRET-9b21"

fn sample_credentials() -> credential.Credentials {
  credential.new(
    token: access_token,
    refresh_token: Some(refresh_secret),
    token_type: "Bearer",
    expires_in: Some(3600),
    scopes: ["email", "profile"],
  )
}

pub fn inspect_credentials_does_not_leak_tokens_test() -> Nil {
  let rendered = string.inspect(sample_credentials())

  assert !string.contains(rendered, access_token)
  assert !string.contains(rendered, refresh_secret)
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

  assert !string.contains(rendered, access_token)
  assert !string.contains(rendered, refresh_secret)
}

pub fn accessors_still_expose_raw_tokens_test() -> Nil {
  let oauth_credentials = sample_credentials()

  assert credential.token(oauth_credentials) == access_token
  assert credential.refresh_token(oauth_credentials) == Some(refresh_secret)
}

pub fn credentials_without_refresh_token_inspects_cleanly_test() -> Nil {
  let oauth_credentials =
    credential.new(
      token: access_token,
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: [],
    )

  assert !string.contains(string.inspect(oauth_credentials), access_token)

  assert credential.refresh_token(oauth_credentials) == None
}
