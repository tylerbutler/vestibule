import gleam/erlang/process
import gleam/http/response
import vestibule/error
import vestibule_apple/jwks
import vestibule_apple/jwt_signing

pub fn cache_miss_from_request_process_persists_for_third_caller_test() -> Nil {
  let assert Ok(cache) = jwks.initialize_named("apple_jwks_cross_process_miss")
  let assert Ok(expected) = jwks.parse_jwks(jwt_signing.test_key_jwks())

  let fetched =
    in_process(fn() {
      jwks.get_keys_with_sender(cache, fn(_) {
        Ok(keys_response(jwt_signing.test_key_jwks()))
      })
    })
  let reused =
    in_process(fn() { jwks.get_keys_with_sender(cache, fn(_) { Error(Nil) }) })

  assert fetched == Ok(expected)
  assert reused == Ok(expected)
}

pub fn refresh_from_request_process_persists_replacement_test() -> Nil {
  let assert Ok(cache) =
    jwks.initialize_named("apple_jwks_cross_process_refresh")
  let assert Ok(original) =
    jwks.get_keys_with_sender(cache, fn(_) {
      Ok(keys_response(jwt_signing.other_key_jwks()))
    })
  let assert Ok(replacement) = jwks.parse_jwks(jwt_signing.test_key_jwks())

  let refreshed =
    in_process(fn() {
      jwks.refresh_keys_with_sender(cache, fn(_) {
        Ok(keys_response(jwt_signing.test_key_jwks()))
      })
    })
  let reused =
    in_process(fn() { jwks.get_keys_with_sender(cache, fn(_) { Error(Nil) }) })

  assert original != replacement
  assert refreshed == Ok(replacement)
  assert reused == Ok(replacement)
}

pub fn cache_miss_reports_write_failure_after_owner_exits_test() -> Nil {
  let assert Ok(cache) =
    in_process(fn() { jwks.initialize_named("apple_jwks_missing_owner_get") })
  let assert Error(authentication_error) =
    jwks.get_keys_with_sender(cache, fn(_) {
      Ok(keys_response(jwt_signing.test_key_jwks()))
    })

  assert error.kind(authentication_error) == error.ConfigKind
  assert error.message(authentication_error)
    == "Invalid configuration: Failed to cache Apple JWKS: TableDoesNotExist"
}

pub fn refresh_reports_write_failure_after_owner_exits_test() -> Nil {
  let assert Ok(cache) =
    in_process(fn() {
      jwks.initialize_named("apple_jwks_missing_owner_refresh")
    })
  let assert Error(authentication_error) =
    jwks.refresh_keys_with_sender(cache, fn(_) {
      Ok(keys_response(jwt_signing.test_key_jwks()))
    })

  assert error.kind(authentication_error) == error.ConfigKind
  assert error.message(authentication_error)
    == "Invalid configuration: Failed to cache Apple JWKS: TableDoesNotExist"
}

pub fn failed_refresh_preserves_cached_keys_and_error_behavior_test() -> Nil {
  let assert Ok(cache) = jwks.initialize_named("apple_jwks_failed_refresh")
  let assert Ok(original) =
    jwks.get_keys_with_sender(cache, fn(_) {
      Ok(keys_response(jwt_signing.other_key_jwks()))
    })

  let assert Error(network_error) =
    in_process(fn() {
      jwks.refresh_keys_with_sender(cache, fn(_) { Error(Nil) })
    })
  let assert Error(parse_error) =
    in_process(fn() {
      jwks.refresh_keys_with_sender(cache, fn(_) {
        Ok(keys_response("not json"))
      })
    })
  let reused =
    in_process(fn() { jwks.get_keys_with_sender(cache, fn(_) { Error(Nil) }) })

  assert error.kind(network_error) == error.NetworkKind
  assert error.kind(parse_error) == error.ConfigKind
  assert reused == Ok(original)
}

fn keys_response(body: String) -> response.Response(String) {
  response.new(200)
  |> response.set_body(body)
}

fn in_process(work: fn() -> value) -> value {
  let reply = process.new_subject()
  let worker = process.spawn_unlinked(fn() { process.send(reply, work()) })
  let monitor = process.monitor(worker)
  let output = process.receive(reply, within: 1000)
  let exited =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(down) { down })
    |> process.selector_receive(within: 1000)
  case exited {
    Ok(_) -> Nil
    Error(_) -> process.kill(worker)
  }
  process.demonitor_process(monitor)

  let assert Ok(_) = exited as "JWKS test worker did not exit"
  let assert Ok(value) = output as "JWKS test worker did not reply"
  value
}
