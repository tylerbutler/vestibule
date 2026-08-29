import gleam/list
import gleam/option.{None, Some}
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

  assert logger.level(event) == logger.Debug
  assert logger.fields(event)
    == [
      #("event", "vestibule.callback.start"),
      #("phase", "callback"),
      #("outcome", "start"),
      #("provider", "github"),
      #("transport", "wisp"),
    ]
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

  assert list.key_find(logger.fields(event), "provider") == Error(Nil)
}

pub fn auth_error_category_is_stable_and_redacted_test() -> Nil {
  assert logger.auth_error_category(error.provider(
      code: "invalid_grant",
      description: "secret-bearing provider text",
      uri: Some("https://provider.example/error"),
    ))
    == "provider_error"

  assert logger.auth_error_category(error.network(reason: "connect failed"))
    == "network_error"
}

pub fn redaction_guard_rejects_sensitive_field_names_test() -> Nil {
  assert logger.safe_fields([
      logger.field("provider", "github"),
      logger.field("access_token", "secret-access-token"),
      logger.field("refresh_token", "secret-refresh-token"),
      logger.field("id_token", "secret-id-token"),
      logger.field("code_verifier", "secret-verifier"),
      logger.field("session_id", "secret-session"),
      logger.field("status", "500"),
    ])
    == [
      #("provider", "github"),
      #("status", "500"),
    ]
}

pub fn redaction_preserves_code_field_but_strips_authorization_code_test() -> Nil {
  assert logger.safe_fields([
      logger.field("code", "invalid_grant"),
      logger.field("authorization_code", "secret-auth-code"),
    ])
    == [#("code", "invalid_grant")]
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
  assert list.key_find(result, "event") == Ok("vestibule.callback.success")
  assert list.key_find(result, "phase") == Ok("callback")
  assert list.key_find(result, "outcome") == Ok("success")
  assert list.key_find(result, "provider") == Ok("github")
  assert list.key_find(result, "access_token") == Error(Nil)
  assert list.key_find(result, "transport") == Ok("wisp")
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

  assert logger.fields(event)
    == [
      #("event", "vestibule.callback.success"),
      #("phase", "callback"),
      #("outcome", "success"),
      #("provider", "github"),
      #("transport", "wisp"),
    ]
}
