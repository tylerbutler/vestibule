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
  let sanitized_caller_fields =
    fields
    |> list.filter(fn(f) {
      let #(key, _) = f
      !list.contains(reserved_field_names, key)
    })
    |> safe_fields
  Event(
    level: level,
    fields: list.flatten([required, provider_fields, sanitized_caller_fields]),
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
  case error.kind(err) {
    error.StateMismatchKind -> "state_mismatch"
    error.InvalidNonceKind -> "invalid_nonce"
    error.MissingCallbackParamKind -> "missing_callback_param"
    error.CodeExchangeKind -> "code_exchange_failed"
    error.UserInfoKind -> "user_info_failed"
    error.ProviderKind -> "provider_error"
    error.HttpKind -> "http_error"
    error.DecodeKind -> "decode_error"
    error.NetworkKind -> "network_error"
    error.ConfigKind -> "config_error"
    error.RefreshUnsupportedKind -> "refresh_unsupported"
    error.CustomKind -> "custom_error"
    error.OtherKind -> "other_error"
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
  "id_token",
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
