import gleam/http/response
import gleam/option.{None, Some}
import gleam/string
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule/error
import vestibule/provider_support

pub fn check_response_status_accepts_2xx_test() {
  response.Response(status: 204, headers: [], body: "ok")
  |> provider_support.check_response_status()
  |> expect.to_equal(Ok("ok"))
}

pub fn check_response_status_rejects_non_2xx_test() {
  let result =
    response.Response(status: 500, headers: [], body: "boom")
    |> provider_support.check_response_status()

  case result {
    Error(error.NetworkError(reason:)) ->
      reason |> expect.to_equal("HTTP 500: boom")
    _ -> panic as "expected NetworkError"
  }
}

pub fn require_https_accepts_https_test() {
  provider_support.require_https("https://example.com")
  |> expect.to_equal(Ok(Nil))
}

pub fn require_https_allows_localhost_http_test() {
  provider_support.require_https("http://localhost/callback")
  |> expect.to_equal(Ok(Nil))
}

pub fn require_https_rejects_remote_http_test() {
  let result = provider_support.require_https("http://example.com")

  case result {
    Error(error.ConfigError(reason:)) ->
      reason
      |> expect.to_equal("HTTPS required for endpoint URL: http://example.com")
    _ -> panic as "expected ConfigError"
  }
}

pub fn parse_redirect_uri_rejects_remote_http_test() {
  let result =
    provider_support.parse_redirect_uri("http://example.com/callback")

  case result {
    Error(error.ConfigError(reason:)) ->
      reason
      |> expect.to_equal(
        "Redirect URI must use HTTPS (except localhost): http://example.com/callback",
      )
    _ -> panic as "expected ConfigError"
  }
}

pub fn append_query_params_preserves_existing_query_test() {
  provider_support.append_query_params("https://example.com/auth?existing=1", [
    #("prompt", "consent"),
  ])
  |> expect.to_equal("https://example.com/auth?existing=1&prompt=consent")
}

pub fn append_query_params_encodes_values_test() {
  provider_support.append_query_params("https://example.com/auth", [
    #("state", "a&b=c"),
  ])
  |> expect.to_equal("https://example.com/auth?state=a%26b%3Dc")
}

pub fn check_token_error_returns_provider_error_test() {
  let result =
    provider_support.check_token_error(
      "{\"error\":\"invalid_grant\",\"error_description\":\"expired\"}",
    )

  result
  |> expect.to_equal(
    Error(error.ProviderError(code: "invalid_grant", description: "expired")),
  )
}

pub fn parse_oauth_token_response_required_scope_success_test() {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"refresh_token\":\"ref\",\"expires_in\":3600,\"scope\":\"repo,user:email\"}"

  provider_support.parse_oauth_token_response(
    body,
    provider_support.RequiredScope(","),
  )
  |> expect.to_equal(
    Ok(
      Credentials(
        token: "tok",
        refresh_token: Some("ref"),
        token_type: "Bearer",
        expires_in: Some(3600),
        scopes: ["repo", "user:email"],
      ),
    ),
  )
}

pub fn parse_oauth_token_response_required_scope_empty_test() {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"\"}"

  let assert Ok(credentials) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(","),
    )
  credentials.scopes |> expect.to_equal([])
}

pub fn parse_oauth_token_response_optional_scope_missing_test() {
  let body = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}"

  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> expect.to_equal(
    Ok(
      Credentials(
        token: "tok",
        refresh_token: None,
        token_type: "Bearer",
        expires_in: None,
        scopes: [],
      ),
    ),
  )
}

pub fn parse_oauth_token_response_optional_scope_empty_test() {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"\"}"

  let assert Ok(credentials) =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.OptionalScope(" "),
    )
  credentials.scopes |> expect.to_equal([])
}

pub fn parse_oauth_token_response_no_scope_ignores_present_scope_test() {
  let body =
    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"ignored\"}"

  let assert Ok(credentials) =
    provider_support.parse_oauth_token_response(body, provider_support.NoScope)
  credentials.scopes |> expect.to_equal([])
}

pub fn parse_oauth_token_response_calls_check_token_error_first_test() {
  let body =
    "{\"error\":\"invalid_client\",\"error_description\":\"bad secret\"}"

  provider_support.parse_oauth_token_response(
    body,
    provider_support.RequiredScope(" "),
  )
  |> expect.to_equal(
    Error(error.ProviderError(code: "invalid_client", description: "bad secret")),
  )
}

pub fn parse_oauth_token_response_requires_access_token_test() {
  let body = "{\"token_type\":\"Bearer\",\"scope\":\"repo\"}"
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(" "),
    )

  case result {
    Error(error.CodeExchangeFailed(reason:)) ->
      string.contains(reason, "access_token") |> expect.to_be_true()
    _ -> panic as "expected CodeExchangeFailed"
  }
}

pub fn parse_oauth_token_response_requires_token_type_test() {
  let body = "{\"access_token\":\"tok\",\"scope\":\"repo\"}"
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(" "),
    )

  case result {
    Error(error.CodeExchangeFailed(reason:)) ->
      string.contains(reason, "token_type") |> expect.to_be_true()
    _ -> panic as "expected CodeExchangeFailed"
  }
}

pub fn parse_oauth_token_response_required_scope_rejects_missing_scope_test() {
  let body = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}"
  let result =
    provider_support.parse_oauth_token_response(
      body,
      provider_support.RequiredScope(" "),
    )

  case result {
    Error(error.CodeExchangeFailed(reason:)) ->
      string.contains(reason, "scope") |> expect.to_be_true()
    _ -> panic as "expected CodeExchangeFailed"
  }
}
