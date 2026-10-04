import gleam/list
import gleam/option
import gleeunit
import vestibule/error

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn every_auth_error_has_recovery_metadata_test() -> Nil {
  let errors = [
    error.state_mismatch(),
    error.invalid_nonce(),
    error.missing_callback_param("code"),
    error.code_exchange(reason: "secret provider text"),
    error.user_info(reason: "secret provider text"),
    error.provider(
      code: "access_denied",
      description: "<script>provider text</script>",
      uri: option.Some("https://evil.example/"),
    ),
    error.http(599, "raw provider body"),
    error.decode("token", "raw provider body"),
    error.network("internal address"),
    error.config(reason: "client_secret"),
    error.refresh_unsupported(),
    error.custom("provider payload"),
  ]

  errors
  |> list.each(fn(auth_error) {
    let recovery = error.recovery(auth_error)
    assert error.recovery_code(recovery) != ""
    assert error.recovery_http_status(recovery) >= 400
    assert error.recovery_http_status(recovery) < 600
    assert error.recovery_summary(recovery) != ""
  })
}

pub fn recovery_distinguishes_retry_restart_and_application_action_test() -> Nil {
  assert error.network("timeout")
    |> error.recovery
    |> error.recovery_action
    == error.RetryOperation
  assert error.state_mismatch()
    |> error.recovery
    |> error.recovery_action
    == error.RestartAuthorization
  assert error.config(reason: "bad secret")
    |> error.recovery
    |> error.recovery_action
    == error.ContactApplication
}

pub fn provider_controlled_text_never_reaches_recovery_metadata_test() -> Nil {
  let malicious = "<script>steal()</script> secret-token https://evil.example"
  let recovery =
    error.provider(
      code: malicious,
      description: malicious,
      uri: option.Some(malicious),
    )
    |> error.recovery

  assert error.recovery_code(recovery) == "provider_error"
  assert error.recovery_summary(recovery)
    == "The provider did not complete sign-in. Start sign-in again."
}
