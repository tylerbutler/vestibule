import gleam/string
import startest/expect
import vestibule/error
import vestibule/state

pub fn generate_produces_nonempty_string_test() {
  let s = state.generate()
  { string.length(s) >= 43 } |> expect.to_be_true()
}

pub fn generate_produces_unique_values_test() {
  let a = state.generate()
  let b = state.generate()
  { a != b } |> expect.to_be_true()
}

pub fn validate_accepts_matching_state_test() {
  let s = state.generate()
  state.validate(s, s)
  |> expect.to_be_ok()
}

pub fn validate_rejects_mismatched_state_test() {
  state.validate("abc123", "def456")
  |> expect.to_equal(Error(error.StateMismatch))
}

pub fn validate_rejects_empty_state_test() {
  state.validate("", "some-state")
  |> expect.to_equal(Error(error.StateMismatch))
}
