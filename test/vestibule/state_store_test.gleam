import gleam/string
import startest/expect
import vestibule/state_store

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

pub fn consume_deletes_after_use_test() {
  let table = state_store.init_named("test_consume_delete_after_use")
  let session_id =
    state_store.store(table, "one-time-state", "one-time-verifier")
  state_store.consume(table, session_id)
  |> expect.to_be_ok()
  state_store.consume(table, session_id)
  |> expect.to_be_error()
}

pub fn retrieve_unknown_returns_error_test() {
  let table = state_store.init_named("test_unknown_returns_error")
  state_store.retrieve(table, "nonexistent-session-id")
  |> expect.to_be_error()
}

pub fn try_init_named_returns_error_for_duplicate_table_test() {
  let name = "vestibule_duplicate_test"
  let assert Ok(_) = state_store.try_init_named(name)
  let result = state_store.try_init_named(name)
  result |> expect.to_equal(Error(state_store.TableAlreadyExists))
}

pub fn state_store_survives_creator_process_exit_test() {
  state_store_survives_creator_process_exit()
  |> expect.to_be_true()
}

pub fn try_store_returns_session_id_and_retrievable_value_test() {
  let assert Ok(table) = state_store.try_init_named("vestibule_try_store_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) = state_store.try_store(table, state, verifier)

  { string.length(session_id) > 0 } |> expect.to_be_true()
  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}

pub fn try_store_with_ttl_stores_retrievable_value_test() {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_try_store_ttl_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) =
    state_store.try_store_with_ttl(table, state, verifier, 600)

  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}

pub fn retrieve_consumes_expired_session_test() {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_expired_session_test")
  let assert Ok(session_id) =
    state_store.try_store_with_ttl(table, "state", "verifier", 0)

  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
}

pub fn storing_new_session_removes_expired_sessions_test() {
  let name = "vestibule_cleanup_expired_session_test"
  let assert Ok(table) = state_store.try_init_named(name)
  let assert Ok(_) =
    state_store.try_store_with_ttl(table, "expired-state", "verifier", 0)

  count_store_entries(name) |> expect.to_equal(1)

  let assert Ok(_) =
    state_store.try_store_with_ttl(table, "fresh-state", "verifier", 600)

  count_store_entries(name) |> expect.to_equal(1)
}

@external(erlang, "vestibule_state_store_test_ffi", "state_store_survives_creator_process_exit")
fn state_store_survives_creator_process_exit() -> Bool

@external(erlang, "vestibule_state_store_test_ffi", "count_store_entries")
fn count_store_entries(name: String) -> Int
