import gleeunit

pub fn main() -> Nil {
  gleeunit.main()
}

@external(erlang, "vestibule_public_http_test_ffi", "oversized_content_length")
fn oversized_content_length() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "chunked_overflow")
fn chunked_overflow() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "close_delimited_overflow")
fn close_delimited_overflow() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "just_under_limit")
fn just_under_limit() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "close_delimited_success")
fn close_delimited_success() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "invalid_utf8_header")
fn invalid_utf8_header() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "concurrent_cleanup")
fn concurrent_cleanup() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "response_timeout")
fn response_timeout() -> Bool

pub fn oversized_content_length_is_rejected_before_body_test() -> Nil {
  assert oversized_content_length()
}

pub fn chunked_response_is_aborted_on_streaming_overflow_test() -> Nil {
  assert chunked_overflow()
}

pub fn close_delimited_response_is_aborted_on_streaming_overflow_test() -> Nil {
  assert close_delimited_overflow()
}

pub fn body_just_under_limit_succeeds_test() -> Nil {
  assert just_under_limit()
}

pub fn normal_close_delimited_provider_response_succeeds_test() -> Nil {
  assert close_delimited_success()
}

pub fn invalid_utf8_response_header_is_rejected_test() -> Nil {
  assert invalid_utf8_header()
}

pub fn concurrent_oversized_responses_close_resources_test() -> Nil {
  assert concurrent_cleanup()
}

pub fn stalled_response_obeys_deadline_test() -> Nil {
  assert response_timeout()
}
