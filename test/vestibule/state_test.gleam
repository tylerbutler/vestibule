import gleam/string
import startest/expect
import vestibule/error
import vestibule/state

pub fn generate_produces_nonempty_string_test() -> Nil {
  let s = state.generate()
  { string.length(s) >= 43 } |> expect.to_be_true()
}

pub fn generate_produces_unique_values_test() -> Nil {
  let a = state.generate()
  let b = state.generate()
  { a != b } |> expect.to_be_true()
}

pub fn validate_accepts_matching_state_test() -> Nil {
  let s = state.generate()
  state.validate(received: s, expected: s)
  |> expect.to_be_ok()
}

pub fn validate_rejects_mismatched_state_test() -> Nil {
  state.validate(received: "abc123", expected: "def456")
  |> expect.to_equal(Error(error.state_mismatch()))
}

pub fn validate_rejects_empty_state_test() -> Nil {
  state.validate(received: "", expected: "some-state")
  |> expect.to_equal(Error(error.state_mismatch()))
}

pub fn validate_rejects_whitespace_only_state_test() -> Nil {
  state.validate(received: "   ", expected: "   ")
  |> expect.to_equal(Error(error.state_mismatch()))
}
