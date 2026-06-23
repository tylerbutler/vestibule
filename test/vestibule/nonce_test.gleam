import startest/expect

import vestibule/error
import vestibule/nonce

pub fn generate_produces_nonempty_string_test() {
  let value = nonce.generate()
  { value != "" } |> expect.to_be_true()
}

pub fn generate_produces_unique_values_test() {
  let a = nonce.generate()
  let b = nonce.generate()
  { a != b } |> expect.to_be_true()
}

pub fn validate_accepts_matching_values_test() {
  let value = nonce.generate()
  nonce.validate(received: value, expected: value)
  |> expect.to_equal(Ok(Nil))
}

pub fn validate_rejects_mismatched_values_test() {
  nonce.validate(received: "received-nonce", expected: "expected-nonce")
  |> expect.to_equal(Error(error.invalid_nonce()))
}

pub fn validate_rejects_blank_received_test() {
  nonce.validate(received: "  ", expected: "expected-nonce")
  |> expect.to_equal(Error(error.invalid_nonce()))
}

pub fn validate_rejects_blank_expected_test() {
  nonce.validate(received: "received-nonce", expected: "")
  |> expect.to_equal(Error(error.invalid_nonce()))
}
