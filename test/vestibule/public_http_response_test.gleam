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

@external(erlang, "vestibule_public_http_test_ffi", "unsupported_transfer_coding")
fn unsupported_transfer_coding() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "unsupported_content_coding")
fn unsupported_content_coding() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "ambiguous_framing")
fn ambiguous_framing() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "proxy_is_ignored")
fn proxy_is_ignored() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "request_budgets_precede_dns")
fn request_budgets_precede_dns() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "resolver_result_is_pinned")
fn resolver_result_is_pinned() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "mixed_dns_answer_is_rejected")
fn mixed_dns_answer_is_rejected() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "tls_uses_original_host_and_system_ca")
fn tls_uses_original_host_and_system_ca() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "tls_handshake_matrix")
fn tls_handshake_matrix() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "admission_is_bounded_and_reusable")
fn admission_is_bounded_and_reusable() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "admission_timeout_is_cancelled")
fn admission_timeout_is_cancelled() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "late_release_is_reclaimed")
fn late_release_is_reclaimed() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "caller_death_cleans_up")
fn caller_death_cleans_up() -> Bool

@external(erlang, "vestibule_public_http_test_ffi", "deadline_releases_admission")
fn deadline_releases_admission() -> Bool

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

pub fn unsupported_transfer_coding_is_rejected_test() -> Nil {
  assert unsupported_transfer_coding()
}

pub fn unsupported_content_coding_is_rejected_test() -> Nil {
  assert unsupported_content_coding()
}

pub fn transfer_encoding_and_content_length_are_rejected_test() -> Nil {
  assert ambiguous_framing()
}

pub fn proxy_environment_is_ignored_test() -> Nil {
  assert proxy_is_ignored()
}

pub fn outbound_request_budgets_are_checked_before_dns_test() -> Nil {
  assert request_budgets_precede_dns()
}

pub fn validated_resolver_address_is_given_to_connector_test() -> Nil {
  assert resolver_result_is_pinned()
}

pub fn mixed_public_and_private_dns_answers_are_rejected_test() -> Nil {
  assert mixed_dns_answer_is_rejected()
}

pub fn tls_uses_original_hostname_and_system_ca_test() -> Nil {
  assert tls_uses_original_host_and_system_ca()
}

pub fn tls_handshake_certificate_matrix_test() -> Nil {
  assert tls_handshake_matrix()
}

pub fn public_http_admission_is_bounded_and_reusable_test() -> Nil {
  assert admission_is_bounded_and_reusable()
}

pub fn timed_out_admission_request_is_cancelled_test() -> Nil {
  assert admission_timeout_is_cancelled()
}

pub fn late_admission_release_is_reclaimed_test() -> Nil {
  assert late_release_is_reclaimed()
}

pub fn caller_death_stops_worker_and_releases_admission_test() -> Nil {
  assert caller_death_cleans_up()
}

pub fn deadline_stops_worker_and_releases_admission_test() -> Nil {
  assert deadline_releases_admission()
}
