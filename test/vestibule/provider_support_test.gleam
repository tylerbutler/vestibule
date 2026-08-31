import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/string
import vestibule/credential
import vestibule/error
import vestibule/internal/public_http
import vestibule/provider_support

pub fn build_json_request_with_auth_is_sans_io_test() -> Nil {
  let assert Ok(http_request) =
    provider_support.build_json_request_with_auth(
      "https://api.example.com/userinfo",
      "Bearer test-token",
      "example",
    )
  assert http_request.host == "api.example.com"
  assert http_request.path == "/userinfo"
  assert request.get_header(http_request, "authorization")
    == Ok("Bearer test-token")
  assert request.get_header(http_request, "accept") == Ok("application/json")
}

pub fn parse_json_response_is_sans_io_test() -> Nil {
  let http_response =
    response.Response(status: 200, headers: [], body: "{\"value\":\"ok\"}")
  assert provider_support.parse_json_response(http_response, fn(body) {
      Ok(body)
    })
    == Ok("{\"value\":\"ok\"}")
}

pub fn check_response_status_accepts_2xx_test() -> Nil {
  let result =
    response.Response(status: 204, headers: [], body: "ok")
    |> provider_support.check_response_status()
  assert result == Ok("ok")
}

pub fn check_response_status_rejects_non_2xx_test() -> Nil {
  let result =
    response.Response(status: 500, headers: [], body: "boom")
    |> provider_support.check_response_status()

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.HttpKind
      assert error.http_status(auth_error) == Some(500)
      assert error.http_summary(auth_error) == Some("boom")
    }
    Ok(_) -> panic as "expected HttpError"
  }
}

pub fn http_error_truncates_long_body_test() -> Nil {
  let long_body = string.repeat("x", 200)
  let result =
    response.Response(status: 400, headers: [], body: long_body)
    |> provider_support.check_response_status()

  case result {
    Error(auth_error) -> {
      assert error.http_status(auth_error) == Some(400)
      let summary = error.http_summary(auth_error) |> option.unwrap("")
      assert string.length(summary) <= 120
    }
    Ok(_) -> panic as "expected HttpError"
  }
}

pub fn require_https_accepts_https_test() -> Nil {
  assert provider_support.require_https("https://example.com") == Ok(Nil)
}

pub fn require_https_allows_localhost_http_test() -> Nil {
  assert provider_support.require_https("http://localhost/callback") == Ok(Nil)
}

pub fn require_https_rejects_remote_http_test() -> Nil {
  let result = provider_support.require_https("http://example.com")

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert string.contains(
        error.message(auth_error),
        "HTTPS required for endpoint URL: http://example.com",
      )
    }
    Ok(_) -> panic as "expected ConfigError"
  }
}

pub fn require_https_rejects_https_without_host_test() -> Nil {
  let result = provider_support.require_https("https:///callback")

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert string.contains(
        error.message(auth_error),
        "URL must include a host: https:///callback",
      )
    }
    Ok(_) -> panic as "expected ConfigError"
  }
}

pub fn require_public_https_accepts_public_host_test() -> Nil {
  assert provider_support.require_public_https("https://example.com/userinfo")
    == Ok(Nil)
}

pub fn require_public_https_rejects_http_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("http://accounts.example.com")
  Nil
}

pub fn require_public_https_rejects_localhost_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://localhost/userinfo")
  Nil
}

pub fn require_public_https_rejects_loopback_ipv4_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://127.0.0.1/userinfo")
  Nil
}

pub fn require_public_https_rejects_loopback_ipv6_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://[::1]/userinfo")
  Nil
}

pub fn require_public_https_rejects_private_10_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://10.0.0.5/userinfo")
  Nil
}

pub fn require_public_https_rejects_private_192_168_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://192.168.1.1/userinfo")
  Nil
}

pub fn require_public_https_rejects_private_172_16_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://172.16.0.1/userinfo")
  Nil
}

pub fn require_public_https_rejects_link_local_metadata_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://169.254.169.254/userinfo")
  Nil
}

pub fn require_public_https_rejects_cgnat_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://100.64.0.1/userinfo")
  Nil
}

pub fn require_public_https_rejects_ula_ipv6_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://[fd00::1]/userinfo")
  Nil
}

pub fn require_public_https_rejects_link_local_ipv6_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://[fe80::1]/userinfo")
  Nil
}

pub fn require_public_https_allows_public_ipv4_test() -> Nil {
  assert provider_support.require_public_https("https://8.8.8.8/userinfo")
    == Ok(Nil)
}

pub fn parse_redirect_uri_rejects_remote_http_test() -> Nil {
  let result =
    provider_support.parse_redirect_uri("http://example.com/callback")

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert string.contains(
        error.message(auth_error),
        "Redirect URI must use HTTPS (except localhost): http://example.com/callback",
      )
    }
    Ok(_) -> panic as "expected ConfigError"
  }
}

pub fn parse_redirect_uri_rejects_https_without_host_test() -> Nil {
  let result = provider_support.parse_redirect_uri("https:///callback")

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert string.contains(
        error.message(auth_error),
        "Redirect URI must include a host: https:///callback",
      )
    }
    Ok(_) -> panic as "expected ConfigError"
  }
}

pub fn append_query_parameters_preserves_existing_query_test() -> Nil {
  assert provider_support.append_query_params(
      "https://example.com/auth?existing=1",
      [#("prompt", "consent")],
    )
    == "https://example.com/auth?existing=1&prompt=consent"
}

pub fn append_query_parameters_encodes_values_test() -> Nil {
  assert provider_support.append_query_params("https://example.com/auth", [
      #("state", "a&b=c"),
    ])
    == "https://example.com/auth?state=a%26b%3Dc"
}

pub fn check_token_error_returns_provider_error_test() -> Nil {
  let result =
    provider_support.check_token_error(
      "{\"error\":\"invalid_grant\",\"error_description\":\"expired\"}",
    )

  assert result
    == Error(error.provider(
      code: "invalid_grant",
      description: "expired",
      uri: None,
    ))
}

pub fn check_token_error_preserves_error_uri_test() -> Nil {
  let result =
    provider_support.check_token_error(
      "{\"error\":\"invalid_grant\",\"error_description\":\"expired\",\"error_uri\":\"https://example.com/error\"}",
    )

  assert result
    == Error(error.provider(
      code: "invalid_grant",
      description: "expired",
      uri: Some("https://example.com/error"),
    ))
}

pub fn parse_oauth_token_response_required_scope_success_test() -> Nil {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"refresh_token\":\"ref\",\"expires_in\":3600,\"scope\":\"repo,user:email\"}"

  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(","),
    )
    == Ok(
      credential.new(
        token: "tok",
        refresh_token: Some("ref"),
        token_type: "Bearer",
        expires_in: Some(3600),
        scopes: ["repo", "user:email"],
      ),
    )
}

pub fn parse_oauth_token_response_required_scope_empty_test() -> Nil {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"\"}"

  let assert Ok(oauth_credentials) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(","),
    )
  assert credential.scopes(oauth_credentials) == []
}

pub fn parse_oauth_token_response_optional_scope_missing_test() -> Nil {
  let body = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}"

  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
    == Ok(
      credential.new(
        token: "tok",
        refresh_token: None,
        token_type: "Bearer",
        expires_in: None,
        scopes: [],
      ),
    )
}

pub fn parse_oauth_token_response_optional_scope_empty_test() -> Nil {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"\"}"

  let assert Ok(oauth_credentials) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  assert credential.scopes(oauth_credentials) == []
}

pub fn parse_oauth_token_response_no_scope_ignores_present_scope_test() -> Nil {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"ignored\"}"

  let assert Ok(oauth_credentials) =
    provider_support.parse_oauth_token_response(body, provider_support.NoScope)
  assert credential.scopes(oauth_credentials) == []
}

pub fn parse_oauth_token_response_calls_check_token_error_first_test() -> Nil {
  let body =
    "{\"error\":\"invalid_client\",\"error_description\":\"bad secret\"}"

  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(" "),
    )
    == Error(error.provider(
      code: "invalid_client",
      description: "bad secret",
      uri: None,
    ))
}

pub fn parse_oauth_token_response_malformed_json_is_decode_error_test() -> Nil {
  let result =
    provider_support.parse_oauth_token_response(
      "not valid json",
      provider_support.RequiredScope(" "),
    )

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.DecodeKind
      assert string.contains(error.message(auth_error), "token response")
      assert string.contains(
        error.message(auth_error),
        "UnexpectedByte(\"0x6F\")",
      )
    }
    Ok(_) -> panic as "expected DecodeError"
  }
}

pub fn parse_oauth_token_response_requires_access_token_test() -> Nil {
  let body = "{\"token_type\":\"Bearer\",\"scope\":\"repo\"}"
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(" "),
    )

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.DecodeKind
      assert string.contains(error.message(auth_error), "token response")
      assert string.contains(error.message(auth_error), "access_token")
    }
    Ok(_) -> panic as "expected DecodeError"
  }
}

pub fn parse_oauth_token_response_requires_token_type_test() -> Nil {
  let body = "{\"access_token\":\"tok\",\"scope\":\"repo\"}"
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(" "),
    )

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.DecodeKind
      assert string.contains(error.message(auth_error), "token response")
      assert string.contains(error.message(auth_error), "token_type")
    }
    Ok(_) -> panic as "expected DecodeError"
  }
}

pub fn parse_oauth_token_response_required_scope_rejects_missing_scope_test() -> Nil {
  let body = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}"
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(" "),
    )

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.DecodeKind
      assert string.contains(error.message(auth_error), "token response")
      assert string.contains(error.message(auth_error), "scope")
    }
    Ok(_) -> panic as "expected DecodeError"
  }
}

pub fn check_response_status_truncates_error_body_test() -> Nil {
  let long_body = string.repeat("secret-body-", 20)
  let result =
    response.Response(status: 502, headers: [], body: long_body)
    |> provider_support.check_response_status()

  case result {
    Error(auth_error) -> {
      assert error.http_status(auth_error) == Some(502)
      let summary = error.http_summary(auth_error) |> option.unwrap("")
      assert string.length(summary) <= 120
    }
    Ok(_) -> panic as "expected HttpError"
  }
}

pub fn fetch_json_with_auth_rejects_remote_http_before_sending_token_test() -> Nil {
  let result =
    provider_support.fetch_json_with_auth(
      "http://example.com/userinfo",
      "Bearer secret-token",
      fn(_body) { Ok("parsed") },
      "test userinfo",
    )

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert string.contains(
        error.message(auth_error),
        "HTTPS required for endpoint URL: http://example.com/userinfo",
      )
    }
    Ok(_) -> panic as "expected ConfigError before sending bearer token"
  }
}

pub fn fetch_json_with_auth_rejects_loopback_before_sending_token_test() -> Nil {
  let result =
    provider_support.fetch_json_with_auth(
      "https://127.0.0.1/userinfo",
      "Bearer secret-token",
      fn(_body) { Ok("parsed") },
      "test userinfo",
    )

  case result {
    Error(auth_error) -> {
      assert error.kind(auth_error) == error.ConfigKind
      assert string.contains(error.message(auth_error), "not publicly routable")
      assert !string.contains(error.message(auth_error), "secret-token")
    }
    Ok(_) -> panic as "expected ConfigError before sending bearer token"
  }
}

// Forms Erlang's resolver accepts as loopback that a naive dotted-quad parse
// would treat as public hostnames (verified with `inet:getaddr/2`).

pub fn require_public_https_rejects_shorthand_ipv4_test() -> Nil {
  let _ =
    provider_support.require_public_https("https://127.1/userinfo")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn require_public_https_rejects_decimal_ipv4_test() -> Nil {
  let _ =
    provider_support.require_public_https("https://2130706433/userinfo")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn require_public_https_rejects_octal_ipv4_test() -> Nil {
  let _ =
    provider_support.require_public_https("https://0177.0.0.1/userinfo")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn require_public_https_rejects_trailing_dot_localhost_test() -> Nil {
  let _ =
    provider_support.require_public_https("https://localhost./userinfo")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn require_public_https_rejects_ipv4_mapped_ipv6_test() -> Nil {
  let _ =
    provider_support.require_public_https("https://[::ffff:127.0.0.1]/userinfo")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn require_public_https_rejects_hex_ipv4_mapped_ipv6_test() -> Nil {
  let assert Error(_) =
    provider_support.require_public_https("https://[::ffff:7f00:1]/userinfo")
  Nil
}

pub fn address_classifier_rejects_hex_ipv4_mapped_loopback_test() -> Nil {
  assert !public_http.address_is_global("::ffff:7f00:1")
}

pub fn address_classifier_rejects_dotted_ipv4_mapped_loopback_test() -> Nil {
  assert !public_http.address_is_global("::ffff:127.0.0.1")
}

pub fn address_classifier_rejects_ipv4_compatible_loopback_test() -> Nil {
  assert !public_http.address_is_global("::7f00:1")
}

pub fn address_classifier_rejects_ipv4_translatable_loopback_test() -> Nil {
  assert !public_http.address_is_global("0:0:0:0:ffff:0:7f00:1")
}

pub fn address_classifier_rejects_mapped_metadata_address_test() -> Nil {
  assert !public_http.address_is_global("::ffff:a9fe:a9fe")
}

pub fn address_classifier_rejects_mapped_private_address_test() -> Nil {
  assert !public_http.address_is_global("::ffff:a00:1")
}

pub fn address_classifier_rejects_mapped_link_local_address_test() -> Nil {
  assert !public_http.address_is_global("::ffff:a9fe:1")
}

pub fn address_classifier_accepts_public_mapped_ipv4_test() -> Nil {
  assert public_http.address_is_global("::ffff:808:808")
}

pub fn address_classifier_rejects_public_compatible_ipv4_test() -> Nil {
  assert !public_http.address_is_global("::808:808")
}

pub fn address_classifier_accepts_public_ipv4_test() -> Nil {
  assert public_http.address_is_global("8.8.8.8")
}

pub fn address_classifier_accepts_public_ipv6_test() -> Nil {
  assert public_http.address_is_global("2606:4700:4700::1111")
}

pub fn address_classifier_rejects_ipv6_special_purpose_ranges_test() -> Nil {
  assert !public_http.address_is_global("::")
  assert !public_http.address_is_global("::1")
  assert !public_http.address_is_global("64:ff9b:1::")
  assert !public_http.address_is_global("64:ff9b:1:ffff:ffff:ffff:ffff:ffff")
  assert !public_http.address_is_global("100::")
  assert !public_http.address_is_global("100:0:0:1::")
  assert !public_http.address_is_global("2001::")
  assert !public_http.address_is_global("2001:1::")
  assert !public_http.address_is_global("2001:1::4")
  assert !public_http.address_is_global("2001:2::")
  assert !public_http.address_is_global("2001:2:ffff:ffff:ffff:ffff:ffff:ffff")
  assert !public_http.address_is_global(
    "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
  )
  assert !public_http.address_is_global("2001:10::")
  assert !public_http.address_is_global("2001:20::")
  assert !public_http.address_is_global("2001:40::")
  assert !public_http.address_is_global("2001:0:4136:e378:8000:63bf:3fff:fdd2")
  assert !public_http.address_is_global("2001:db8::")
  assert !public_http.address_is_global("2002:808:808::")
  assert !public_http.address_is_global(
    "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
  )
  assert !public_http.address_is_global("5f00::")
  assert !public_http.address_is_global("fc00::")
  assert !public_http.address_is_global(
    "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  )
  assert !public_http.address_is_global("fe80::")
  assert !public_http.address_is_global("fec0::")
  assert !public_http.address_is_global("ff0e::1")
}

pub fn address_classifier_accepts_ipv6_global_registry_exceptions_test() -> Nil {
  assert public_http.address_is_global("2001:1::1")
  assert public_http.address_is_global("2001:1::2")
  assert public_http.address_is_global("2001:1::3")
  assert public_http.address_is_global("2001:3::")
  assert public_http.address_is_global("2001:3:ffff:ffff:ffff:ffff:ffff:ffff")
  assert public_http.address_is_global("2001:4:112::")
  assert public_http.address_is_global("2001:4:112:ffff:ffff:ffff:ffff:ffff")
  assert public_http.address_is_global("2001:30::")
  assert public_http.address_is_global("2001:3f:ffff:ffff:ffff:ffff:ffff:ffff")
  assert public_http.address_is_global("2001:200::")
  assert public_http.address_is_global("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff")
  assert public_http.address_is_global("2001:db9::")
  assert public_http.address_is_global("2003::")
  assert public_http.address_is_global(
    "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  )
  assert public_http.address_is_global("3fff:1000::")
}

pub fn address_classifier_checks_ipv4_inside_ipv6_test() -> Nil {
  assert public_http.address_is_global("192.0.0.9")
  assert public_http.address_is_global("192.0.0.10")
  assert !public_http.address_is_global("192.0.0.8")
  assert !public_http.address_is_global("192.0.0.11")
  assert public_http.address_is_global("::ffff:808:808")
  assert public_http.address_is_global("64:ff9b::808:808")
  assert public_http.address_is_global("::ffff:c000:9")
  assert public_http.address_is_global("64:ff9b::c000:9")
  assert !public_http.address_is_global("::ffff:c000:8")
  assert !public_http.address_is_global("64:ff9b::c000:8")
  assert !public_http.address_is_global("::ffff:a00:1")
  assert !public_http.address_is_global("64:ff9b::a00:1")
  assert !public_http.address_is_global("::ffff:a9fe:a9fe")
  assert !public_http.address_is_global("64:ff9b::a9fe:a9fe")
  assert !public_http.address_is_global("::ffff:0:808:808")
  assert !public_http.address_is_global("::ffff:0:a00:1")
  assert !public_http.address_is_global("2002:808:808::")
  assert !public_http.address_is_global("2002:a00:1::")
}

pub fn resolved_benchmarking_ipv6_is_rejected_test() -> Nil {
  let assert Error(reason) =
    public_http.validate_addresses("benchmark.example", ["2001:2::"])
  assert string.contains(reason, "2001:2::")
}

pub fn resolved_loopback_hostname_is_rejected_test() -> Nil {
  let assert Error(reason) =
    public_http.validate_addresses("alias.example", ["127.0.0.1"])
  assert string.contains(reason, "non-public address")
}

pub fn resolved_private_hostname_is_rejected_test() -> Nil {
  let assert Error(reason) =
    public_http.validate_addresses("alias.example", ["10.20.30.40"])
  assert string.contains(reason, "10.20.30.40")
}

pub fn resolved_link_local_hostname_is_rejected_test() -> Nil {
  let assert Error(reason) =
    public_http.validate_addresses("alias.example", ["169.254.169.254"])
  assert string.contains(reason, "169.254.169.254")
}

pub fn mixed_public_and_private_dns_answers_are_rejected_test() -> Nil {
  let assert Error(reason) =
    public_http.validate_addresses("rebind.example", ["8.8.8.8", "192.168.1.10"])
  assert string.contains(reason, "192.168.1.10")
}

pub fn all_public_dns_answers_are_accepted_test() -> Nil {
  assert public_http.validate_addresses("public.example", [
      "8.8.8.8",
      "2606:4700:4700::1111",
    ])
    == Ok(Nil)
}

pub fn localhost_alias_resolving_to_loopback_is_rejected_test() -> Nil {
  let assert Error(auth_error) =
    provider_support.require_public_host("https://localhost.localdomain/")
  assert string.contains(error.message(auth_error), "non-public address")
}

pub fn unresolved_hostname_is_rejected_without_fallback_test() -> Nil {
  let assert Error(auth_error) =
    provider_support.require_public_host(
      "https://definitely-not-resolvable.invalid/",
    )
  assert string.contains(error.message(auth_error), "Could not resolve host")
}

pub fn secure_sender_rejects_dns_loopback_before_connecting_test() -> Nil {
  let assert Ok(http_request) = request.to("https://localhost.localdomain/")
  let assert Ok(secure_request) = provider_support.secure_request(http_request)
  let assert Error(auth_error) = provider_support.send_public(secure_request)
  assert error.kind(auth_error) == error.ConfigKind
  assert string.contains(error.message(auth_error), "non-public address")
}

pub fn secure_request_rejects_plain_http_test() -> Nil {
  let assert Ok(http_request) = request.to("http://example.com/")
  let assert Error(auth_error) = provider_support.secure_request(http_request)
  assert error.kind(auth_error) == error.ConfigKind
  assert string.contains(error.message(auth_error), "HTTPS required")
}

// === require_public_host ===

pub fn require_public_host_accepts_http_public_host_test() -> Nil {
  provider_support.require_public_host("http://example.com/")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
}

pub fn require_public_host_accepts_https_public_host_test() -> Nil {
  provider_support.require_public_host("https://example.com/")
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
}

pub fn require_public_host_rejects_localhost_test() -> Nil {
  let _ =
    provider_support.require_public_host("http://localhost/")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn require_public_host_rejects_private_ipv4_test() -> Nil {
  let _ =
    provider_support.require_public_host("http://10.0.0.5/")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn require_public_host_rejects_missing_host_test() -> Nil {
  let _ =
    provider_support.require_public_host("http:///path")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}
