import gleam/string
import gleeunit/should
import vestibule/error
import vestibule/state

pub fn generate_produces_nonempty_string_test() {
  let s = state.generate()
  { string.length(s) >= 43 } |> should.be_true()
}

pub fn generate_produces_unique_values_test() {
  let a = state.generate()
  let b = state.generate()
  { a != b } |> should.be_true()
}

pub fn validate_accepts_matching_state_test() {
  let s = state.generate()
  state.validate(s, s)
  |> should.be_ok()
}

pub fn validate_rejects_mismatched_state_test() {
  state.validate("abc123", "def456")
  |> should.equal(Error(error.StateMismatch))
}

pub fn validate_rejects_empty_state_test() {
  state.validate("", "some-state")
  |> should.equal(Error(error.StateMismatch))
}
