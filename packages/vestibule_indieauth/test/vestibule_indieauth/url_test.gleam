import vestibule_indieauth/url

// === validate_profile_url ===

pub fn valid_https_url_test() -> Nil {
  url.validate_profile_url("https://example.com/")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == "https://example.com/"
  }
}

pub fn valid_http_url_test() -> Nil {
  url.validate_profile_url("http://example.com/")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == "http://example.com/"
  }
}

pub fn valid_url_with_path_test() -> Nil {
  url.validate_profile_url("https://example.com/username")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == "https://example.com/username"
  }
}

pub fn valid_url_with_query_test() -> Nil {
  url.validate_profile_url("https://example.com/users?id=100")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == "https://example.com/users?id=100"
  }
}

pub fn rejects_missing_scheme_adds_https_test() -> Nil {
  // canonicalize prepends https:// so this becomes a valid URL
  url.validate_profile_url("example.com")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == "https://example.com/"
  }
}

pub fn rejects_invalid_scheme_test() -> Nil {
  let _ =
    url.validate_profile_url("mailto:user@example.com")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn rejects_fragment_test() -> Nil {
  let _ =
    url.validate_profile_url("https://example.com/#me")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn rejects_port_test() -> Nil {
  let _ =
    url.validate_profile_url("https://example.com:8443/")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn rejects_userinfo_test() -> Nil {
  let _ =
    url.validate_profile_url("https://user:pass@example.com/")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn rejects_ip_address_test() -> Nil {
  let _ =
    url.validate_profile_url("https://172.28.92.51/")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn rejects_double_dot_path_test() -> Nil {
  let _ =
    url.validate_profile_url("https://example.com/foo/../bar")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn rejects_single_dot_path_test() -> Nil {
  let _ =
    url.validate_profile_url("https://example.com/./foo")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// === canonicalize ===

pub fn canonicalize_adds_https_test() -> Nil {
  url.canonicalize("example.com")
  |> fn(actual) {
    assert actual == "https://example.com/"
  }
}

pub fn canonicalize_adds_trailing_slash_test() -> Nil {
  url.canonicalize("https://example.com")
  |> fn(actual) {
    assert actual == "https://example.com/"
  }
}

pub fn canonicalize_lowercases_host_test() -> Nil {
  url.canonicalize("https://EXAMPLE.COM/path")
  |> fn(actual) {
    assert actual == "https://example.com/path"
  }
}

pub fn canonicalize_preserves_path_test() -> Nil {
  url.canonicalize("https://example.com/username")
  |> fn(actual) {
    assert actual == "https://example.com/username"
  }
}

pub fn canonicalize_preserves_http_test() -> Nil {
  url.canonicalize("http://example.com/")
  |> fn(actual) {
    assert actual == "http://example.com/"
  }
}

// Profile URLs are fetched server-side during discovery, so a non-public
// host would turn the login form into an SSRF primitive.

pub fn rejects_localhost_profile_url_test() -> Nil {
  let _ =
    url.validate_profile_url("http://localhost/")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn rejects_dot_local_profile_url_test() -> Nil {
  let _ =
    url.validate_profile_url("https://printer.local/")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}
