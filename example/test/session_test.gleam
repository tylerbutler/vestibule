import session
import startest/expect

pub fn store_and_retrieve_state_test() {
  session.create_table()
  let state = "test_csrf_state_value"
  let session_id = session.store_state(state)
  session.get_state(session_id)
  |> expect.to_equal(Ok(state))
}

pub fn get_state_deletes_after_retrieval_test() {
  session.create_table()
  let session_id = session.store_state("one_time_state")
  // First retrieval succeeds
  session.get_state(session_id)
  |> expect.to_be_ok()
  // Second retrieval fails (one-time use)
  session.get_state(session_id)
  |> expect.to_be_error()
}

pub fn get_state_returns_error_for_unknown_id_test() {
  session.create_table()
  session.get_state("nonexistent")
  |> expect.to_be_error()
}
