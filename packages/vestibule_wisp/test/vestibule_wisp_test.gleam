import startest
import startest/expect
import vestibule_wisp/state_store

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn store_and_retrieve_state_and_verifier_test() {
  let table = state_store.init_named("test_store_retrieve")
  let state = "test-csrf-state-value"
  let verifier = "test-pkce-code-verifier"
  let session_id = state_store.store(table, state, verifier)
  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}

pub fn retrieve_deletes_after_use_test() {
  let table = state_store.init_named("test_delete_after_use")
  let session_id = state_store.store(table, "one-time-state", "one-time-verifier")
  let _ = state_store.retrieve(table, session_id)
  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
}

pub fn retrieve_unknown_returns_error_test() {
  let table = state_store.init_named("test_unknown_returns_error")
  state_store.retrieve(table, "nonexistent-session-id")
  |> expect.to_be_error()
}
