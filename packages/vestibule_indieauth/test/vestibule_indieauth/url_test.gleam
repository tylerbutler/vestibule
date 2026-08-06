import vestibule_indieauth/url

// === validate_profile_url ===

pub fn valid_https_url_test() {
  assert url.validate_profile_url("https://example.com/")
    == Ok("https://example.com/")
}

pub fn valid_http_url_test() {
  assert url.validate_profile_url("http://example.com/")
    == Ok("http://example.com/")
}

pub fn valid_url_with_path_test() {
  assert url.validate_profile_url("https://example.com/username")
    == Ok("https://example.com/username")
}

pub fn valid_url_with_query_test() {
  assert url.validate_profile_url("https://example.com/users?id=100")
    == Ok("https://example.com/users?id=100")
}

pub fn rejects_missing_scheme_adds_https_test() {
  // canonicalize prepends https:// so this becomes a valid URL
  assert url.validate_profile_url("example.com") == Ok("https://example.com/")
}

pub fn rejects_invalid_scheme_test() {
  let assert Error(_) = url.validate_profile_url("mailto:user@example.com")
  Nil
}

pub fn rejects_fragment_test() {
  let assert Error(_) = url.validate_profile_url("https://example.com/#me")
  Nil
}

pub fn rejects_port_test() {
  let assert Error(_) = url.validate_profile_url("https://example.com:8443/")
  Nil
}

pub fn rejects_userinfo_test() {
  let assert Error(_) =
    url.validate_profile_url("https://user:pass@example.com/")
  Nil
}

pub fn rejects_ip_address_test() {
  let assert Error(_) = url.validate_profile_url("https://172.28.92.51/")
  Nil
}

pub fn rejects_double_dot_path_test() {
  let assert Error(_) =
    url.validate_profile_url("https://example.com/foo/../bar")
  Nil
}

pub fn rejects_single_dot_path_test() {
  let assert Error(_) = url.validate_profile_url("https://example.com/./foo")
  Nil
}

// === canonicalize ===

pub fn canonicalize_adds_https_test() {
  assert url.canonicalize("example.com") == "https://example.com/"
}

pub fn canonicalize_adds_trailing_slash_test() {
  assert url.canonicalize("https://example.com") == "https://example.com/"
}

pub fn canonicalize_lowercases_host_test() {
  assert url.canonicalize("https://EXAMPLE.COM/path")
    == "https://example.com/path"
}

pub fn canonicalize_preserves_path_test() {
  assert url.canonicalize("https://example.com/username")
    == "https://example.com/username"
}

pub fn canonicalize_preserves_http_test() {
  assert url.canonicalize("http://example.com/") == "http://example.com/"
}
