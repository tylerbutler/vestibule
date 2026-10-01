import gleam/option.{None, Some}
import gleam/string
import vestibule/error

const echoed_secret = "ACCESS-TOKEN-SECRET-7f3a"

pub fn provider_error_discards_provider_controlled_fields_test() -> Nil {
  let auth_error =
    error.provider(
      code: echoed_secret,
      description: echoed_secret,
      uri: Some("https://provider.example/" <> echoed_secret),
    )
  let assert Some(provider_error) = error.provider_error(auth_error)

  assert error.provider_code(provider_error) == "provider_error"
  assert error.provider_description(provider_error)
    == "Provider rejected the request"
  assert error.provider_uri(provider_error) == None
  assert !string.contains(error.message(auth_error), echoed_secret)
}

pub fn provider_error_preserves_known_code_only_test() -> Nil {
  let auth_error =
    error.provider(
      code: "invalid_grant",
      description: echoed_secret,
      uri: Some("https://provider.example/" <> echoed_secret),
    )
  let assert Some(provider_error) = error.provider_error(auth_error)

  assert error.provider_code(provider_error) == "invalid_grant"
  assert error.provider_description(provider_error)
    == "Provider rejected the request"
  assert error.provider_uri(provider_error) == None
}
