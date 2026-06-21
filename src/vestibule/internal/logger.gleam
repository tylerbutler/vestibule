import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import vestibule/error.{type AuthError}

pub type Level {
  Debug
  Info
  Warning
  Error
}

pub opaque type Event {
  Event(level: Level, fields: List(#(String, String)))
}

pub fn new(
  level level: Level,
  event event_name: String,
  phase phase: String,
  outcome outcome: String,
  provider provider: Option(String),
  fields fields: List(#(String, String)),
) -> Event {
  let required = [
    #("event", event_name),
    #("phase", phase),
    #("outcome", outcome),
  ]
  let provider_fields = case provider {
    Some(name) -> [#("provider", name)]
    None -> []
  }
  let safe_caller_fields =
    list.filter(fields, fn(f) {
      let #(key, _) = f
      !list.contains(reserved_field_names, key)
    })
  Event(
    level: level,
    fields: safe_fields(
      list.flatten([required, provider_fields, safe_caller_fields]),
    ),
  )
}

pub fn field(key: String, value: String) -> #(String, String) {
  #(key, value)
}

pub fn int_field(key: String, value: Int) -> #(String, String) {
  #(key, int.to_string(value))
}

pub fn bool_field(key: String, value: Bool) -> #(String, String) {
  #(key, bool.to_string(value))
}

pub fn level(event: Event) -> Level {
  event.level
}

pub fn fields(event: Event) -> List(#(String, String)) {
  event.fields
}

pub fn emit(event: Event) -> Nil {
  do_log(level_name(event.level), event.fields)
}

pub fn auth_error_category(err: AuthError(e)) -> String {
  case err {
    error.StateMismatch -> "state_mismatch"
    error.MissingCallbackParam(_) -> "missing_callback_param"
    error.CodeExchangeFailed(_) -> "code_exchange_failed"
    error.UserInfoFailed(_) -> "user_info_failed"
    error.ProviderError(_, _, _) -> "provider_error"
    error.HttpError(_, _) -> "http_error"
    error.DecodeError(_, _) -> "decode_error"
    error.NetworkError(_) -> "network_error"
    error.ConfigError(_) -> "config_error"
    error.Custom(_) -> "custom_error"
  }
}

pub fn safe_fields(fields: List(#(String, String))) -> List(#(String, String)) {
  list.filter(fields, fn(field) {
    let #(key, _) = field
    !list.contains(sensitive_field_names, key)
  })
}

fn level_name(level: Level) -> String {
  case level {
    Debug -> "debug"
    Info -> "info"
    Warning -> "warning"
    Error -> "error"
  }
}

const reserved_field_names = ["event", "phase", "outcome", "provider"]

const sensitive_field_names = [
  "access_token",
  "refresh_token",
  "client_secret",
  "authorization_code",
  "code_verifier",
  "callback_params",
  "session_id",
  "cookie",
  "cookie_value",
  "response_body",
  "signed_payload",
]

@external(erlang, "vestibule_logger_ffi", "log")
fn do_log(level: String, fields: List(#(String, String))) -> Nil
