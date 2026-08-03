import gleam/list
import gleam/option.{None, Some}
import startest/expect
import vestibule/error
import vestibule/logger

pub fn event_builder_includes_required_fields_test() -> Nil {
  let event =
    logger.new(
      level: logger.Debug,
      event: "vestibule.callback.start",
      phase: "callback",
      outcome: "start",
      provider: Some("github"),
      fields: [logger.field("transport", "wisp")],
    )

  logger.level(event) |> expect.to_equal(logger.Debug)
  logger.fields(event)
  |> expect.to_equal([
    #("event", "vestibule.callback.start"),
    #("phase", "callback"),
    #("outcome", "start"),
    #("provider", "github"),
    #("transport", "wisp"),
  ])
}

pub fn event_builder_omits_absent_provider_test() -> Nil {
  let event =
    logger.new(
      level: logger.Info,
      event: "vestibule.request.success",
      phase: "request",
      outcome: "success",
      provider: None,
      fields: [],
    )

  logger.fields(event)
  |> list.key_find("provider")
  |> expect.to_equal(Error(Nil))
}

pub fn auth_error_category_is_stable_and_redacted_test() -> Nil {
  logger.auth_error_category(error.provider(
    code: "invalid_grant",
    description: "secret-bearing provider text",
    uri: Some("https://provider.example/error"),
  ))
  |> expect.to_equal("provider_error")

  logger.auth_error_category(error.network(reason: "connect failed"))
  |> expect.to_equal("network_error")
}

pub fn redaction_guard_rejects_sensitive_field_names_test() -> Nil {
  logger.safe_fields([
    logger.field("provider", "github"),
    logger.field("access_token", "secret-access-token"),
    logger.field("refresh_token", "secret-refresh-token"),
    logger.field("id_token", "secret-id-token"),
    logger.field("code_verifier", "secret-verifier"),
    logger.field("session_id", "secret-session"),
    logger.field("status", "500"),
  ])
  |> expect.to_equal([
    #("provider", "github"),
    #("status", "500"),
  ])
}

pub fn redaction_preserves_code_field_but_strips_authorization_code_test() -> Nil {
  logger.safe_fields([
    logger.field("code", "invalid_grant"),
    logger.field("authorization_code", "secret-auth-code"),
  ])
  |> expect.to_equal([#("code", "invalid_grant")])
}

pub fn canonical_fields_survive_when_caller_supplies_sensitive_keys_test() -> Nil {
  let event =
    logger.new(
      level: logger.Info,
      event: "vestibule.callback.success",
      phase: "callback",
      outcome: "success",
      provider: Some("github"),
      fields: [
        logger.field("access_token", "should-be-stripped"),
        logger.field("transport", "wisp"),
      ],
    )

  let result = logger.fields(event)
  result
  |> list.key_find("event")
  |> expect.to_equal(Ok("vestibule.callback.success"))
  result |> list.key_find("phase") |> expect.to_equal(Ok("callback"))
  result |> list.key_find("outcome") |> expect.to_equal(Ok("success"))
  result |> list.key_find("provider") |> expect.to_equal(Ok("github"))
  result |> list.key_find("access_token") |> expect.to_equal(Error(Nil))
  result |> list.key_find("transport") |> expect.to_equal(Ok("wisp"))
}

pub fn reserved_fields_cannot_be_overridden_by_caller_test() -> Nil {
  let event =
    logger.new(
      level: logger.Info,
      event: "vestibule.callback.success",
      phase: "callback",
      outcome: "success",
      provider: Some("github"),
      fields: [
        logger.field("event", "override"),
        logger.field("provider", "evil"),
        logger.field("transport", "wisp"),
      ],
    )

  logger.fields(event)
  |> expect.to_equal([
    #("event", "vestibule.callback.success"),
    #("phase", "callback"),
    #("outcome", "success"),
    #("provider", "github"),
    #("transport", "wisp"),
  ])
}
