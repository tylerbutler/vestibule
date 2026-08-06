import gleam/http/response
import gleam/option.{None, Some}
import gleam/string
import vestibule/credentials
import vestibule/error
import vestibule/provider_support

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
    Error(err) -> {
      assert error.kind(err) == error.HttpKind
      assert error.http_status(err) == Some(500)
      assert error.http_summary(err) == Some("boom")
    }
    _ -> panic as "expected HttpError"
  }
}

pub fn http_error_truncates_long_body_test() -> Nil {
  let long_body = string.repeat("x", 200)
  let result =
    response.Response(status: 400, headers: [], body: long_body)
    |> provider_support.check_response_status()

  case result {
    Error(err) -> {
      assert error.http_status(err) == Some(400)
      let summary = error.http_summary(err) |> option.unwrap("")
      assert string.length(summary) <= 120
    }
    _ -> panic as "expected HttpError"
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
    Error(err) -> {
      assert error.kind(err) == error.ConfigKind
      assert string.contains(
        error.message(err),
        "HTTPS required for endpoint URL: http://example.com",
      )
    }
    _ -> panic as "expected ConfigError"
  }
}

pub fn require_https_rejects_https_without_host_test() -> Nil {
  let result = provider_support.require_https("https:///callback")

  case result {
    Error(err) -> {
      assert error.kind(err) == error.ConfigKind
      assert string.contains(
        error.message(err),
        "URL must include a host: https:///callback",
      )
    }
    _ -> panic as "expected ConfigError"
  }
}

pub fn require_public_https_accepts_public_host_test() -> Nil {
  assert provider_support.require_public_https(
      "https://accounts.example.com/userinfo",
    )
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
    Error(err) -> {
      assert error.kind(err) == error.ConfigKind
      assert string.contains(
        error.message(err),
        "Redirect URI must use HTTPS (except localhost): http://example.com/callback",
      )
    }
    _ -> panic as "expected ConfigError"
  }
}

pub fn parse_redirect_uri_rejects_https_without_host_test() -> Nil {
  let result = provider_support.parse_redirect_uri("https:///callback")

  case result {
    Error(err) -> {
      assert error.kind(err) == error.ConfigKind
      assert string.contains(
        error.message(err),
        "Redirect URI must include a host: https:///callback",
      )
    }
    _ -> panic as "expected ConfigError"
  }
}

pub fn append_query_params_preserves_existing_query_test() -> Nil {
  assert provider_support.append_query_params(
      "https://example.com/auth?existing=1",
      [#("prompt", "consent")],
    )
    == "https://example.com/auth?existing=1&prompt=consent"
}

pub fn append_query_params_encodes_values_test() -> Nil {
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
      credentials.new(
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
  assert credentials.scopes(oauth_credentials) == []
}

pub fn parse_oauth_token_response_optional_scope_missing_test() -> Nil {
  let body = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}"

  assert provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
    == Ok(
      credentials.new(
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
  assert credentials.scopes(oauth_credentials) == []
}

pub fn parse_oauth_token_response_no_scope_ignores_present_scope_test() -> Nil {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"ignored\"}"

  let assert Ok(oauth_credentials) =
    provider_support.parse_oauth_token_response(body, provider_support.NoScope)
  assert credentials.scopes(oauth_credentials) == []
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
    Error(err) -> {
      assert error.kind(err) == error.DecodeKind
      assert string.contains(error.message(err), "token response")
      assert string.contains(error.message(err), "UnexpectedByte(\"0x6F\")")
    }
    _ -> panic as "expected DecodeError"
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
    Error(err) -> {
      assert error.kind(err) == error.DecodeKind
      assert string.contains(error.message(err), "token response")
      assert string.contains(error.message(err), "access_token")
    }
    _ -> panic as "expected DecodeError"
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
    Error(err) -> {
      assert error.kind(err) == error.DecodeKind
      assert string.contains(error.message(err), "token response")
      assert string.contains(error.message(err), "token_type")
    }
    _ -> panic as "expected DecodeError"
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
    Error(err) -> {
      assert error.kind(err) == error.DecodeKind
      assert string.contains(error.message(err), "token response")
      assert string.contains(error.message(err), "scope")
    }
    _ -> panic as "expected DecodeError"
  }
}

pub fn check_response_status_truncates_error_body_test() -> Nil {
  let long_body = string.repeat("secret-body-", 20)
  let result =
    response.Response(status: 502, headers: [], body: long_body)
    |> provider_support.check_response_status()

  case result {
    Error(err) -> {
      assert error.http_status(err) == Some(502)
      let summary = error.http_summary(err) |> option.unwrap("")
      assert string.length(summary) <= 120
    }
    _ -> panic as "expected HttpError"
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
    Error(err) -> {
      assert error.kind(err) == error.ConfigKind
      assert string.contains(
        error.message(err),
        "HTTPS required for endpoint URL: http://example.com/userinfo",
      )
    }
    _ -> panic as "expected ConfigError before sending bearer token"
  }
}
