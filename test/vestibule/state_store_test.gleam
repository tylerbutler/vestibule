import gleam/option.{None, Some}
import gleam/string
import vestibule/state_store

pub fn store_and_retrieve_state_and_verifier_test() -> Nil {
  let assert Ok(table) = state_store.create_named("test_store_retrieve")
  let state = "test-csrf-state-value"
  let verifier = "test-pkce-code-verifier"
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "test",
      state: state,
      code_verifier: verifier,
      nonce: None,
    )
  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #(state, verifier, None)
  }
}

pub fn retrieve_deletes_after_use_test() -> Nil {
  let assert Ok(table) = state_store.create_named("test_delete_after_use")
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "test",
      state: "one-time-state",
      code_verifier: "one-time-verifier",
      nonce: None,
    )
  let _ = state_store.consume(table, session_id, provider: "test")
  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
}

pub fn consume_deletes_after_use_test() -> Nil {
  let assert Ok(table) =
    state_store.create_named("test_consume_delete_after_use")
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "test",
      state: "one-time-state",
      code_verifier: "one-time-verifier",
      nonce: None,
    )
  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
}

pub fn retrieve_unknown_returns_error_test() -> Nil {
  let assert Ok(table) = state_store.create_named("test_unknown_returns_error")
  state_store.consume(table, "nonexistent-session-id", provider: "test")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
}

pub fn create_named_returns_error_for_duplicate_table_test() -> Nil {
  let name = "vestibule_duplicate_test"
  let assert Ok(_) = state_store.create_named(name)
  let result = state_store.create_named(name)
  result
  |> fn(actual) {
    assert actual == Error(state_store.TableAlreadyExists)
  }
}

pub fn state_store_survives_creator_process_exit_test() -> Nil {
  state_store_survives_creator_process_exit()
  |> fn(actual) {
    assert actual
  }
}

pub fn store_returns_session_id_and_retrievable_value_test() -> Nil {
  let assert Ok(table) = state_store.create_named("vestibule_try_store_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "test",
      state: state,
      code_verifier: verifier,
      nonce: None,
    )

  { string.length(session_id) > 0 }
  |> fn(actual) {
    assert actual
  }
  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #(state, verifier, None)
  }
}

pub fn store_with_ttl_stores_retrievable_value_test() -> Nil {
  let assert Ok(table) =
    state_store.create_named("vestibule_try_store_ttl_test")
  let state = "state"
  let verifier = "verifier"
  let assert Ok(session_id) =
    state_store.store_with_ttl(
      table,
      provider: "test",
      state: state,
      code_verifier: verifier,
      nonce: None,
      ttl_seconds: 600,
    )

  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #(state, verifier, None)
  }
}

pub fn retrieve_consumes_expired_session_test() -> Nil {
  let assert Ok(table) =
    state_store.create_named("vestibule_expired_session_test")
  let assert Ok(session_id) =
    state_store.store_with_ttl(
      table,
      provider: "test",
      state: "state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 0,
    )

  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
}

pub fn expiration_between_peek_and_consume_is_rejected_test() -> Nil {
  let assert Ok(table) =
    state_store.create_named("vestibule_expire_between_operations_test")
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "test",
      state: "state",
      code_verifier: "verifier",
      nonce: None,
    )
  let assert Ok(_) = state_store.peek(table, session_id, provider: "test")
  assert consume_after_expiry(table, session_id, "test") == Error(Nil)
  assert state_store.consume(table, session_id, provider: "test") == Error(Nil)
}

pub fn expired_sessions_are_removed_by_sweep_not_on_insert_test() -> Nil {
  // Cleanup used to run a full table scan on every insert, which made the
  // request phase O(n) and let an unauthenticated client stall every login.
  // Inserts are now O(1); expired entries go when the owner sweeps.
  let name = "vestibule_cleanup_expired_session_test"
  let assert Ok(table) = state_store.create_named(name)
  let assert Ok(_) =
    state_store.store_with_ttl(
      table,
      provider: "test",
      state: "expired-state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 0,
    )
  let assert Ok(_) =
    state_store.store_with_ttl(
      table,
      provider: "test",
      state: "fresh-state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 600,
    )
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 2
  }

  state_store.sweep_expired(table)
  |> fn(actual) {
    assert actual == Ok(1)
  }
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 1
  }
}

pub fn owner_periodic_sweep_removes_expired_sessions_test() -> Nil {
  let name = "vestibule_periodic_sweep_test"
  let assert Ok(table) = state_store.create_named(name)
  let assert Ok(_) =
    state_store.store_with_ttl(
      table,
      provider: "test",
      state: "expired-state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 0,
    )
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 1
  }

  // Deliver the owner's own sweep tick early; the following count is
  // serviced by the same process after it, so this is deterministic.
  trigger_owner_sweep(name)
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 0
  }
}

pub fn store_rejects_new_sessions_when_full_test() -> Nil {
  let name = "vestibule_capacity_test"
  let assert Ok(table) =
    state_store.create_with_capacity(name: name, max_entries: 2)
  let store = fn(state) {
    state_store.store(
      table,
      provider: "test",
      state: state,
      code_verifier: "verifier",
      nonce: None,
    )
  }
  let assert Ok(first) = store("one")
  let assert Ok(_) = store("two")
  store("three")
  |> fn(actual) {
    assert actual == Error(state_store.StoreFull)
  }
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 2
  }

  // Consuming a session frees a slot.
  let assert Ok(_) = state_store.consume(table, first, provider: "test")
  let assert Ok(_) = store("three")
  Nil
}

pub fn store_reclaims_expired_sessions_before_reporting_full_test() -> Nil {
  let name = "vestibule_capacity_reclaim_test"
  let assert Ok(table) =
    state_store.create_with_capacity(name: name, max_entries: 1)
  let assert Ok(_) =
    state_store.store_with_ttl(
      table,
      provider: "test",
      state: "expired-state",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 0,
    )
  // At capacity, but the only occupant is expired: it is swept, not refused.
  let assert Ok(_) =
    state_store.store(
      table,
      provider: "test",
      state: "fresh-state",
      code_verifier: "verifier",
      nonce: None,
    )
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 1
  }
}

pub fn create_with_capacity_rejects_non_positive_capacity_test() -> Nil {
  state_store.create_with_capacity(name: "vestibule_zero_cap", max_entries: 0)
  |> fn(result) {
    let assert Error(value) = result
    value
  }
  Nil
}

pub fn admission_rejects_one_client_without_filling_store_test() -> Nil {
  let name = "vestibule_per_client_admission_test"
  let assert Ok(table) =
    state_store.create_with_limits(
      name: name,
      max_entries: 12,
      max_entries_per_client: 2,
    )
  let store = fn(client, state) {
    state_store.store_for_client(
      table,
      client_key: client,
      provider: "test",
      state: state,
      code_verifier: "verifier",
      nonce: None,
    )
  }
  let assert Ok(existing) = store("legitimate", "existing")
  let assert Ok(_) = store("attacker", "one")
  let assert Ok(_) = store("attacker", "two")

  store("attacker", "rejected")
  |> fn(actual) {
    assert actual == Error(state_store.ClientLimitReached)
  }
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 3
  }

  let assert Ok(_) = state_store.consume(table, existing, provider: "test")
  let assert Ok(_) = store("legitimate", "replacement")
  Nil
}

pub fn global_admission_is_a_hard_bound_without_eviction_test() -> Nil {
  let name = "vestibule_global_admission_test"
  let assert Ok(table) =
    state_store.create_with_limits(
      name: name,
      max_entries: 2,
      max_entries_per_client: 2,
    )
  let store = fn(client) {
    state_store.store_for_client(
      table,
      client_key: client,
      provider: "test",
      state: client,
      code_verifier: "verifier",
      nonce: None,
    )
  }
  let assert Ok(existing) = store("legitimate")
  let assert Ok(_) = store("attacker-one")
  assert store("attacker-two") == Error(state_store.StoreFull)
  assert count_store_entries(name) == 2
  assert state_store.consume(table, existing, provider: "test")
    == Ok(#("legitimate", "verifier", None))
}

pub fn rejected_load_never_inserts_state_test() -> Nil {
  let name = "vestibule_rejected_load_test"
  let assert Ok(table) =
    state_store.create_with_limits(
      name: name,
      max_entries: 32,
      max_entries_per_client: 1,
    )
  let assert Ok(_) =
    state_store.store_for_client(
      table,
      client_key: "attacker",
      provider: "test",
      state: "first",
      code_verifier: "verifier",
      nonce: None,
    )
  reject_many(table, 1000)
  count_store_entries(name)
  |> fn(actual) {
    assert actual == 1
  }
}

pub fn client_admission_recovers_after_expiration_test() -> Nil {
  let assert Ok(table) =
    state_store.create_with_limits(
      name: "vestibule_client_expiry_recovery_test",
      max_entries: 4,
      max_entries_per_client: 1,
    )
  let assert Ok(_) =
    state_store.store_for_client_with_ttl(
      table,
      client_key: "client",
      provider: "test",
      state: "expired",
      code_verifier: "verifier",
      nonce: None,
      ttl_seconds: 0,
    )
  let assert Ok(_) =
    state_store.store_for_client(
      table,
      client_key: "client",
      provider: "test",
      state: "fresh",
      code_verifier: "verifier",
      nonce: None,
    )
  Nil
}

fn reject_many(table: state_store.StateStore, remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      state_store.store_for_client(
        table,
        client_key: "attacker",
        provider: "test",
        state: "rejected",
        code_verifier: "verifier",
        nonce: None,
      )
      |> fn(actual) {
        assert actual == Error(state_store.ClientLimitReached)
      }
      reject_many(table, remaining - 1)
    }
  }
}

pub fn concurrent_take_has_one_winner_test() -> Nil {
  assert concurrent_take_winner_count() == 1
}

pub fn delayed_owner_rechecks_expiry_before_consume_test() -> Nil {
  assert delayed_consume_rejects_expired()
}

pub fn timed_out_insert_does_not_commit_later_test() -> Nil {
  assert timed_out_insert_does_not_commit()
}

pub fn store_persists_and_returns_nonce_test() -> Nil {
  let assert Ok(table) = state_store.create_named("test_store_nonce")
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "test",
      state: "state-with-nonce",
      code_verifier: "verifier",
      nonce: Some("test-nonce-value"),
    )
  state_store.consume(table, session_id, provider: "test")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #("state-with-nonce", "verifier", Some("test-nonce-value"))
  }
}

pub fn stored_session_term_does_not_render_secrets_test() -> Nil {
  let state = "STATE-SECRET-7f3a"
  let verifier = "VERIFIER-SECRET-8b4c"
  let nonce = "NONCE-SECRET-9d5e"
  let assert Ok(table) =
    state_store.create_named("test_state_store_secret_rendering")
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "test",
      state: state,
      code_verifier: verifier,
      nonce: Some(nonce),
    )

  let rendered = format_store_entry(table, session_id)
  assert !string.contains(rendered, state)
  assert !string.contains(rendered, verifier)
  assert !string.contains(rendered, nonce)
  assert state_store.peek(table, session_id, provider: "test")
    == Ok(#(state, verifier, Some(nonce)))
}

@external(erlang, "vestibule_state_store_test_ffi", "state_store_survives_creator_process_exit")
fn state_store_survives_creator_process_exit() -> Bool

@external(erlang, "vestibule_state_store_test_ffi", "format_store_entry")
fn format_store_entry(
  table: state_store.StateStore,
  session_id: String,
) -> String

@external(erlang, "vestibule_state_store_test_ffi", "count_store_entries")
fn count_store_entries(name: String) -> Int

@external(erlang, "vestibule_state_store_test_ffi", "trigger_owner_sweep")
fn trigger_owner_sweep(name: String) -> Nil

// === provider binding ===
//
// A session minted for one provider must not satisfy another provider's
// callback; otherwise an attacker-controlled provider can redirect the
// browser to a different provider's callback with the still-valid state
// (OAuth mix-up / login CSRF).

pub fn consume_rejects_other_provider_test() -> Nil {
  let assert Ok(table) = state_store.create_named("test_consume_provider")
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "alpha",
      state: "state",
      code_verifier: "verifier",
      nonce: None,
    )
  state_store.consume(table, session_id, provider: "beta")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
  state_store.consume(table, session_id, provider: "alpha")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #("state", "verifier", None)
  }
}

pub fn peek_rejects_other_provider_without_burning_session_test() -> Nil {
  let assert Ok(table) = state_store.create_named("test_peek_provider")
  let assert Ok(session_id) =
    state_store.store(
      table,
      provider: "alpha",
      state: "state",
      code_verifier: "verifier",
      nonce: None,
    )
  state_store.peek(table, session_id, provider: "beta")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
  state_store.peek(table, session_id, provider: "alpha")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #("state", "verifier", None)
  }
  state_store.consume(table, session_id, provider: "alpha")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #("state", "verifier", None)
  }
}

// === owner process recovery ===

pub fn store_recovers_after_owner_crash_test() -> Nil {
  // The ETS owner is unsupervised. If it dies, in-flight sessions are lost,
  // but the store must heal itself on the next call instead of failing
  // every login until the VM restarts.
  let name = "vestibule_owner_recovery_test"
  let assert Ok(table) = state_store.create_named(name)
  let assert Ok(old_session) =
    state_store.store(
      table,
      provider: "test",
      state: "state",
      code_verifier: "verifier",
      nonce: None,
    )

  kill_owner()

  let assert Ok(new_session) =
    state_store.store(
      table,
      provider: "test",
      state: "state-after-crash",
      code_verifier: "verifier",
      nonce: None,
    )
  state_store.consume(table, old_session, provider: "test")
  |> fn(result) {
    let assert Error(value) = result
    value
  }
  state_store.consume(table, new_session, provider: "test")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #("state-after-crash", "verifier", None)
  }
}

pub fn operation_returns_error_when_owner_dies_mid_call_test() -> Nil {
  assert owner_death_during_call_is_controlled()
}

@external(erlang, "vestibule_state_store_test_ffi", "kill_owner")
fn kill_owner() -> Nil

@external(erlang, "vestibule_state_store_test_ffi", "concurrent_take_winner_count")
fn concurrent_take_winner_count() -> Int

@external(erlang, "vestibule_state_store_test_ffi", "delayed_consume_rejects_expired")
fn delayed_consume_rejects_expired() -> Bool

@external(erlang, "vestibule_state_store_test_ffi", "timed_out_insert_does_not_commit")
fn timed_out_insert_does_not_commit() -> Bool

@external(erlang, "vestibule_state_store_test_ffi", "owner_death_during_call_is_controlled")
fn owner_death_during_call_is_controlled() -> Bool

@external(erlang, "vestibule_state_store_test_ffi", "consume_after_expiry")
fn consume_after_expiry(
  store: state_store.StateStore,
  session_id: String,
  provider: String,
) -> Result(#(String, String, option.Option(String)), Nil)
