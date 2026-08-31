import gleam/string
import vestibule/error
import vestibule/state

pub fn generate_produces_nonempty_string_test() -> Nil {
  let state_value = state.generate()
  assert string.length(state_value) >= 43
}

pub fn generate_produces_unique_values_test() -> Nil {
  let first_state = state.generate()
  let second_state = state.generate()
  assert first_state != second_state
}

pub fn validate_accepts_matching_state_test() -> Nil {
  let state_value = state.generate()
  let assert Ok(_) =
    state.validate(received: state_value, expected: state_value)
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
