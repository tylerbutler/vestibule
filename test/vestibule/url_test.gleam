/// Tests for URL HTTPS validation.
///
/// Verifies that the URL validation utility correctly enforces HTTPS
/// while allowing HTTP for localhost development addresses.
import startest/expect
import vestibule/url

// ===========================================================================
// HTTPS URLs (should be accepted)
// ===========================================================================

pub fn accepts_https_url_test() {
  url.validate_https_url("https://example.com/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("https://example.com/callback")
}

pub fn accepts_https_with_port_test() {
  url.validate_https_url("https://example.com:8443/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("https://example.com:8443/callback")
}

pub fn accepts_https_with_path_and_query_test() {
  url.validate_https_url("https://example.com/auth/callback?foo=bar")
  |> expect.to_be_ok()
  |> expect.to_equal("https://example.com/auth/callback?foo=bar")
}

pub fn accepts_https_localhost_test() {
  url.validate_https_url("https://localhost/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("https://localhost/callback")
}

// ===========================================================================
// HTTP localhost exceptions (should be accepted)
// ===========================================================================

pub fn accepts_http_localhost_test() {
  url.validate_https_url("http://localhost/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://localhost/callback")
}

pub fn accepts_http_localhost_with_port_test() {
  url.validate_https_url("http://localhost:8080/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://localhost:8080/callback")
}

pub fn accepts_http_127001_test() {
  url.validate_https_url("http://127.0.0.1/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://127.0.0.1/callback")
}

pub fn accepts_http_127001_with_port_test() {
  url.validate_https_url("http://127.0.0.1:3000/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://127.0.0.1:3000/callback")
}

pub fn accepts_http_ipv6_loopback_test() {
  url.validate_https_url("http://[::1]/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://[::1]/callback")
}

pub fn accepts_http_ipv6_loopback_with_port_test() {
  url.validate_https_url("http://[::1]:8080/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://[::1]:8080/callback")
}

// ===========================================================================
// HTTP non-localhost (should be rejected)
// ===========================================================================

pub fn rejects_http_external_url_test() {
  let _ =
    url.validate_https_url("http://example.com/callback")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_http_ip_address_test() {
  let _ =
    url.validate_https_url("http://192.168.1.1/callback")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_http_internal_network_test() {
  let _ =
    url.validate_https_url("http://internal.corp.example.com/callback")
    |> expect.to_be_error()
  Nil
}

// ===========================================================================
// Other schemes (should be rejected)
// ===========================================================================

pub fn rejects_ftp_scheme_test() {
  let _ =
    url.validate_https_url("ftp://example.com/file")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_ws_scheme_test() {
  let _ =
    url.validate_https_url("ws://example.com/ws")
    |> expect.to_be_error()
  Nil
}

// ===========================================================================
// Invalid URLs (should be rejected)
// ===========================================================================

pub fn rejects_empty_string_test() {
  let _ =
    url.validate_https_url("")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_relative_path_test() {
  let _ =
    url.validate_https_url("/callback")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_no_scheme_test() {
  let _ =
    url.validate_https_url("example.com/callback")
    |> expect.to_be_error()
  Nil
}

// ===========================================================================
// Case insensitivity for localhost
// ===========================================================================

pub fn accepts_http_localhost_uppercase_test() {
  url.validate_https_url("http://LOCALHOST/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://LOCALHOST/callback")
}

pub fn accepts_http_localhost_mixed_case_test() {
  url.validate_https_url("http://LocalHost:3000/callback")
  |> expect.to_be_ok()
  |> expect.to_equal("http://LocalHost:3000/callback")
}
