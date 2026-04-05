import startest
import startest/expect

import vestibule_indieauth/url

pub fn main() {
  startest.run(startest.default_config())
}

// === validate_profile_url ===

pub fn valid_https_url_test() {
  url.validate_profile_url("https://example.com/")
  |> expect.to_be_ok()
  |> expect.to_equal("https://example.com/")
}

pub fn valid_http_url_test() {
  url.validate_profile_url("http://example.com/")
  |> expect.to_be_ok()
  |> expect.to_equal("http://example.com/")
}

pub fn valid_url_with_path_test() {
  url.validate_profile_url("https://example.com/username")
  |> expect.to_be_ok()
  |> expect.to_equal("https://example.com/username")
}

pub fn valid_url_with_query_test() {
  url.validate_profile_url("https://example.com/users?id=100")
  |> expect.to_be_ok()
  |> expect.to_equal("https://example.com/users?id=100")
}

pub fn rejects_missing_scheme_adds_https_test() {
  // canonicalize prepends https:// so this becomes a valid URL
  url.validate_profile_url("example.com")
  |> expect.to_be_ok()
  |> expect.to_equal("https://example.com/")
}

pub fn rejects_invalid_scheme_test() {
  let _ =
    url.validate_profile_url("mailto:user@example.com")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_fragment_test() {
  let _ =
    url.validate_profile_url("https://example.com/#me")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_port_test() {
  let _ =
    url.validate_profile_url("https://example.com:8443/")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_userinfo_test() {
  let _ =
    url.validate_profile_url("https://user:pass@example.com/")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_ip_address_test() {
  let _ =
    url.validate_profile_url("https://172.28.92.51/")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_double_dot_path_test() {
  let _ =
    url.validate_profile_url("https://example.com/foo/../bar")
    |> expect.to_be_error()
  Nil
}

pub fn rejects_single_dot_path_test() {
  let _ =
    url.validate_profile_url("https://example.com/./foo")
    |> expect.to_be_error()
  Nil
}

// === canonicalize ===

pub fn canonicalize_adds_https_test() {
  url.canonicalize("example.com")
  |> expect.to_equal("https://example.com/")
}

pub fn canonicalize_adds_trailing_slash_test() {
  url.canonicalize("https://example.com")
  |> expect.to_equal("https://example.com/")
}

pub fn canonicalize_lowercases_host_test() {
  url.canonicalize("https://EXAMPLE.COM/path")
  |> expect.to_equal("https://example.com/path")
}

pub fn canonicalize_preserves_path_test() {
  url.canonicalize("https://example.com/username")
  |> expect.to_equal("https://example.com/username")
}

pub fn canonicalize_preserves_http_test() {
  url.canonicalize("http://example.com/")
  |> expect.to_equal("http://example.com/")
}
