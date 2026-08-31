import vestibule/error
import vestibule/nonce

pub fn generate_produces_nonempty_string_test() -> Nil {
  let value = nonce.generate()
  assert value != ""
}

pub fn generate_produces_unique_values_test() -> Nil {
  let first_nonce = nonce.generate()
  let second_nonce = nonce.generate()
  assert first_nonce != second_nonce
}

pub fn validate_accepts_matching_values_test() -> Nil {
  let value = nonce.generate()
  assert nonce.validate(received: value, expected: value) == Ok(Nil)
}

pub fn validate_rejects_mismatched_values_test() -> Nil {
  assert nonce.validate(received: "received-nonce", expected: "expected-nonce")
    == Error(error.invalid_nonce())
}

pub fn validate_rejects_blank_received_test() -> Nil {
  assert nonce.validate(received: "  ", expected: "expected-nonce")
    == Error(error.invalid_nonce())
}

pub fn validate_rejects_blank_expected_test() -> Nil {
  assert nonce.validate(received: "received-nonce", expected: "")
    == Error(error.invalid_nonce())
}
