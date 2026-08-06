import gleam/string
import vestibule/error
import vestibule/state

pub fn generate_produces_nonempty_string_test() -> Nil {
  let s = state.generate()
  assert string.length(s) >= 43
}

pub fn generate_produces_unique_values_test() -> Nil {
  let a = state.generate()
  let b = state.generate()
  assert a != b
}

pub fn validate_accepts_matching_state_test() -> Nil {
  let s = state.generate()
  let assert Ok(_) = state.validate(received: s, expected: s)
  Nil
}

pub fn validate_rejects_mismatched_state_test() -> Nil {
  assert state.validate(received: "abc123", expected: "def456")
    == Error(error.state_mismatch())
}

pub fn validate_rejects_empty_state_test() -> Nil {
  assert state.validate(received: "", expected: "some-state")
    == Error(error.state_mismatch())
}

pub fn validate_rejects_whitespace_only_state_test() -> Nil {
  assert state.validate(received: "   ", expected: "   ")
    == Error(error.state_mismatch())
}
