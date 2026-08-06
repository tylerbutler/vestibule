import gleam/option.{None, Some}
import gleam/string
import vestibule/state_store

pub fn store_and_retrieve_state_and_verifier_test() -> Nil {
  let assert Ok(table) = state_store.try_init_named("test_store_retrieve")
  let state = "test-csrf-state-value"
  let verifier = "test-pkce-code-verifier"
  let assert Ok(session_id) =
    state_store.try_store(
      table,
      state: state,
      code_verifier: verifier,
      nonce: None,
    )
  assert state_store.consume(table, session_id) == Ok(#(state, verifier, None))
}

pub fn retrieve_deletes_after_use_test() -> Nil {
  let assert Ok(table) = state_store.try_init_named("test_delete_after_use")
  let assert Ok(session_id) =
    state_store.try_store(
      table,
      state: "one-time-state",
      code_verifier: "one-time-verifier",
      nonce: None,
    )
  let _ = state_store.consume(table, session_id)
  let assert Error(_) = state_store.consume(table, session_id)
  Nil
}

pub fn consume_deletes_after_use_test() -> Nil {
  let assert Ok(table) =
    state_store.try_init_named("test_consume_delete_after_use")
  let assert Ok(session_id) =
    state_store.try_store(
      table,
      state: "one-time-state",
      code_verifier: "one-time-verifier",
      nonce: None,
    )
  let assert Ok(_) = state_store.consume(table, session_id)
  let assert Error(_) = state_store.consume(table, session_id)
  Nil
}

pub fn retrieve_unknown_returns_error_test() -> Nil {
  let assert Ok(table) =
    state_store.try_init_named("test_unknown_returns_error")
  let assert Error(_) = state_store.consume(table, "nonexistent-session-id")
  Nil
}

pub fn try_init_named_returns_error_for_duplicate_table_test() -> Nil {
  let name = "vestibule_duplicate_test"
  let assert Ok(_) = state_store.try_init_named(name)
  let result = state_store.try_init_named(name)
  assert result == Error(state_store.TableAlreadyExists)
}

pub fn state_store_survives_creator_process_exit_test() -> Nil {
  assert state_store_survives_creator_process_exit()
}

pub fn try_store_returns_session_id_and_retrievable_value_test() -> Nil {
  let assert Ok(table) = state_store.try_init_named("vestibule_try_store_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) =
    state_store.try_store(
      table,
      state: state,
      code_verifier: verifier,
      nonce: None,
    )

  assert string.length(session_id) > 0
  assert state_store.consume(table, session_id) == Ok(#(state, verifier, None))
}

pub fn try_store_with_ttl_stores_retrievable_value_test() -> Nil {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_try_store_ttl_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) =
    state_store.try_store_with_ttl(
      table,
      state: state,
      code_verifier: verifier,
      nonce: None,
      ttl_seconds: 600,
    )

  assert state_store.consume(table, session_id) == Ok(#(state, verifier, None))
}

pub fn retrieve_consumes_expired_session_test() -> Nil {
  let assert Ok(table) =
    state_store.try_init_named("vestibule_expired_session_test")
  let assert Ok(session_id) =
    state_store.try_store_with_ttl(
      table,
      state: "state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 0,
    )

  let assert Error(_) = state_store.consume(table, session_id)
  let assert Error(_) = state_store.consume(table, session_id)
  Nil
}

pub fn storing_new_session_removes_expired_sessions_test() -> Nil {
  let name = "vestibule_cleanup_expired_session_test"
  let assert Ok(table) = state_store.try_init_named(name)
  let assert Ok(_) =
    state_store.try_store_with_ttl(
      table,
      state: "expired-state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 0,
    )

  assert count_store_entries(name) == 1

  let assert Ok(_) =
    state_store.try_store_with_ttl(
      table,
      state: "fresh-state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 600,
    )

  assert count_store_entries(name) == 1
}

pub fn store_persists_and_returns_nonce_test() -> Nil {
  let assert Ok(table) = state_store.try_init_named("test_store_nonce")
  let assert Ok(session_id) =
    state_store.try_store(
      table,
      state: "state-with-nonce",
      code_verifier: "verifier",
      nonce: Some("test-nonce-value"),
    )
  assert state_store.consume(table, session_id)
    == Ok(#("state-with-nonce", "verifier", Some("test-nonce-value")))
}

@external(erlang, "vestibule_state_store_test_ffi", "state_store_survives_creator_process_exit")
fn state_store_survives_creator_process_exit() -> Bool

@external(erlang, "vestibule_state_store_test_ffi", "count_store_entries")
fn count_store_entries(name: String) -> Int
