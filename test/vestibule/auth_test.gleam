import gleam/dict
import gleam/dynamic
import gleam/option.{None, Some}
import startest/expect
import vestibule/auth
import vestibule/credentials
import vestibule/user_info

fn sample_info() -> user_info.UserInfo {
  user_info.new()
  |> user_info.with_name(Some("Test User"))
  |> user_info.with_email(Some("test@example.com"))
}

fn sample_credentials() -> credentials.Credentials {
  credentials.new(
    token: "access-token",
    refresh_token: None,
    token_type: "Bearer",
    expires_in: Some(3600),
    scopes: ["profile"],
  )
}

pub fn auth_accessors_return_constructed_fields_test() {
  let extras = dict.from_list([#("raw_provider", dynamic.string("github"))])
  let result =
    auth.new(
      uid: "user-123",
      provider: "github",
      info: sample_info(),
      credentials: sample_credentials(),
      extra: extras,
    )

  auth.uid(result) |> expect.to_equal("user-123")
  auth.provider(result) |> expect.to_equal("github")
  auth.info(result) |> expect.to_equal(sample_info())
  auth.credentials(result) |> expect.to_equal(sample_credentials())
  auth.extra(result) |> expect.to_equal(extras)
}
