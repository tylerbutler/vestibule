import gleam/string
import vestibule/secret_key

const key_material = "COOKIE-SIGNING-KEY-SECRET-7f3a"

pub fn inspection_does_not_expose_cookie_signing_key_test() -> Nil {
  let key = secret_key.from_bit_array(<<key_material:utf8>>)

  assert !string.contains(string.inspect(key), key_material)
}

pub fn erlang_formatting_does_not_expose_cookie_signing_key_test() -> Nil {
  let key = secret_key.from_bit_array(<<key_material:utf8>>)

  assert !string.contains(erlang_term(key), key_material)
}

@external(erlang, "vestibule_secret_test_ffi", "format_term")
fn erlang_term(value: a) -> String
