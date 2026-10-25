import gleam/option
import gleam/string
import vestibule/authorization_request
import vestibule/config
import vestibule/credential
import vestibule/secret_key

pub fn crash_report_formatting_hides_wrapped_secrets_test() -> Nil {
  let client_secret = "CLIENT-SECRET-7f3a"
  let state = "STATE-SECRET-9b21"
  let verifier = "VERIFIER-SECRET-4c82"
  let access_token = "ACCESS-TOKEN-2d17"
  let refresh_token = "REFRESH-TOKEN-6e05"
  let cookie_key = "COOKIE-KEY-8a44"
  let values = #(
    config.new(
      client_id: "client",
      redirect_uri: "https://example.com/callback",
      auth: config.client_secret_auth(client_secret),
    ),
    authorization_request.new(
      url: "https://example.com/authorize",
      state: state,
      code_verifier: verifier,
      nonce: option.None,
    ),
    credential.new(
      token: access_token,
      refresh_token: option.Some(refresh_token),
      token_type: "Bearer",
      expires_in: option.None,
      scopes: [],
    ),
    secret_key.from_bit_array(<<cookie_key:utf8>>),
  )
  let rendered = format_crash_report(values)

  assert !string.contains(rendered, client_secret)
  assert !string.contains(rendered, state)
  assert !string.contains(rendered, verifier)
  assert !string.contains(rendered, access_token)
  assert !string.contains(rendered, refresh_token)
  assert !string.contains(rendered, cookie_key)
}

@external(erlang, "vestibule_secret_test_ffi", "format_crash_report")
fn format_crash_report(value: a) -> String
