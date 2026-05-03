import gleam/string
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
  let session_id =
    state_store.store(table, "one-time-state", "one-time-verifier")
  let _ = state_store.retrieve(table, session_id)
  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
}

pub fn retrieve_unknown_returns_error_test() {
  let table = state_store.init_named("test_unknown_returns_error")
  state_store.retrieve(table, "nonexistent-session-id")
  |> expect.to_be_error()
}

pub fn try_init_named_returns_error_for_duplicate_table_test() {
  let name = "vestibule_wisp_duplicate_test"
  let assert Ok(_) = state_store.try_init_named(name)
  let result = state_store.try_init_named(name)
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn try_store_returns_session_id_and_retrievable_value_test() {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_wisp_try_store_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) = state_store.try_store(table, state, verifier)

  { string.length(session_id) > 0 } |> expect.to_be_true()
  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}
