import gleam/dict
import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/string
import gleam/time/duration
import gleeunit
import vestibule
import vestibule/auth
import vestibule/config
import vestibule/credential
import vestibule/error
import vestibule/strategy
import vestibule/user_info
import vestibule_google
import vestibule_google/jwt_signing
import ywt/claim

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn parse_token_response_success_test() -> Nil {
  let body =
    "{\"access_token\":\"ya29.test_token\",\"expires_in\":3599,\"scope\":\"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile\",\"token_type\":\"Bearer\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual
        == credential.new(
          token: "ya29.test_token",
          refresh_token: None,
          token_type: "Bearer",
          expires_in: Some(3599),
          scopes: [
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
          ],
        )
    }
  Nil
}

pub fn parse_token_response_with_refresh_token_test() -> Nil {
  let body =
    "{\"access_token\":\"ya29.test\",\"expires_in\":3600,\"refresh_token\":\"1//test_refresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual
        == credential.new(
          token: "ya29.test",
          refresh_token: Some("1//test_refresh"),
          token_type: "Bearer",
          expires_in: Some(3600),
          scopes: ["openid"],
        )
    }
  Nil
}

pub fn parse_token_response_empty_scope_is_rejected_test() -> Nil {
  let body =
    "{\"access_token\":\"ya29.test\",\"expires_in\":3600,\"scope\":\"\",\"token_type\":\"Bearer\"}"
  let assert Error(authentication_error) =
    vestibule_google.parse_token_response(body)
  assert error.kind(authentication_error) == error.CodeExchangeKind
}

pub fn parse_token_response_error_test() -> Nil {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been expired or revoked.\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_token_response_error_without_description_test() -> Nil {
  let body = "{\"error\":\"invalid_grant\"}"
  let assert Error(authentication_error) =
    vestibule_google.parse_token_response(body)
  assert error.kind(authentication_error) == error.ProviderKind
  assert error.message(authentication_error)
    == "Provider returned error: invalid_grant — Provider rejected the request"
}

pub fn parse_user_response_full_test() -> Nil {
  let body =
    "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"given_name\":\"Jane\",\"family_name\":\"Doe\",\"picture\":\"https://lh3.googleusercontent.com/photo.jpg\",\"email\":\"jane@example.com\",\"email_verified\":true}"
  let assert Ok(#(user_id, user)) = vestibule_google.parse_user_response(body)
  let _ =
    user_id
    |> fn(actual) {
      assert actual == "1234567890"
    }
  let _ =
    user_info.name(user)
    |> fn(actual) {
      assert actual == Some("Jane Doe")
    }
  let _ =
    user_info.email(user)
    |> fn(actual) {
      assert actual == Some("jane@example.com")
    }
  let _ =
    user_info.nickname(user)
    |> fn(actual) {
      assert actual == Some("jane@example.com")
    }
  let _ =
    user_info.image(user)
    |> fn(actual) {
      assert actual == Some("https://lh3.googleusercontent.com/photo.jpg")
    }
  let _ =
    user_info.description(user)
    |> fn(actual) {
      assert actual == None
    }
  Nil
}

pub fn parse_user_response_unverified_email_test() -> Nil {
  let body =
    "{\"sub\":\"999\",\"name\":\"Test\",\"email\":\"unverified@example.com\",\"email_verified\":false}"
  let assert Ok(#(_user_id, user)) = vestibule_google.parse_user_response(body)
  let _ =
    user_info.email(user)
    |> fn(actual) {
      assert actual == None
    }
  let _ =
    user_info.nickname(user)
    |> fn(actual) {
      assert actual == Some("unverified@example.com")
    }
  Nil
}

pub fn parse_user_response_minimal_test() -> Nil {
  let body = "{\"sub\":\"abc-123\"}"
  let assert Ok(#(user_id, user)) = vestibule_google.parse_user_response(body)
  let _ =
    user_id
    |> fn(actual) {
      assert actual == "abc-123"
    }
  let _ =
    user_info.name(user)
    |> fn(actual) {
      assert actual == None
    }
  let _ =
    user_info.email(user)
    |> fn(actual) {
      assert actual == None
    }
  let _ =
    user_info.nickname(user)
    |> fn(actual) {
      assert actual == None
    }
  let _ =
    user_info.image(user)
    |> fn(actual) {
      assert actual == None
    }
  Nil
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() -> Nil {
  let google_strategy = vestibule_google.strategy()
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "not a uri",
      auth: config.client_secret_auth("secret"),
    )
  let _ =
    strategy.build_authorize_url(
      google_strategy,
      config: client_config,
      options: config.authorize_options(),
      scopes: ["openid"],
      state: "state",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn authorize_url_includes_extra_parameters_test() -> Nil {
  let google_strategy = vestibule_google.strategy()
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "consent")])
  let assert Ok(url) =
    strategy.build_authorize_url(
      google_strategy,
      config: client_config,
      options: options,
      scopes: ["openid"],
      state: "state",
    )
  let _ =
    { string.contains(url, "prompt=consent") }
    |> fn(actual) {
      assert actual
    }
  Nil
}

// --- Hosted-domain (hd) enforcement ---

pub fn parse_user_response_with_hosted_domain_present_test() -> Nil {
  let body =
    "{\"sub\":\"42\",\"email\":\"jane@corp.example\",\"email_verified\":true,\"hd\":\"corp.example\"}"
  let assert Ok(#(user_id, _user, hosted_domain)) =
    vestibule_google.parse_user_response_with_hosted_domain(body)
  let _ =
    user_id
    |> fn(actual) {
      assert actual == "42"
    }
  let _ =
    hosted_domain
    |> fn(actual) {
      assert actual == Some("corp.example")
    }
  Nil
}

pub fn parse_user_response_with_hosted_domain_absent_test() -> Nil {
  let body =
    "{\"sub\":\"42\",\"email\":\"jane@gmail.com\",\"email_verified\":true}"
  let assert Ok(#(_user_id, _user, hosted_domain)) =
    vestibule_google.parse_user_response_with_hosted_domain(body)
  let _ =
    hosted_domain
    |> fn(actual) {
      assert actual == None
    }
  Nil
}

pub fn validate_hosted_domain_match_test() -> Nil {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: Some("corp.example"),
    )
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual == Some("corp.example")
    }
  Nil
}

pub fn validate_hosted_domain_mismatch_fails_test() -> Nil {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: Some("evil.com"),
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
    |> fn(auth_error) {
      assert error.kind(auth_error) == error.UserInfoKind
    }
  Nil
}

pub fn validate_hosted_domain_missing_claim_fails_test() -> Nil {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: Some("corp.example"),
      returned: None,
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
    |> fn(auth_error) {
      assert error.kind(auth_error) == error.UserInfoKind
    }
  Nil
}

pub fn validate_hosted_domain_not_required_passes_through_test() -> Nil {
  let _ =
    vestibule_google.validate_hosted_domain(
      required: None,
      returned: Some("corp.example"),
    )
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual == Some("corp.example")
    }

  let _ =
    vestibule_google.validate_hosted_domain(required: None, returned: None)
    |> fn(result) {
      let assert Ok(value) = result
      value
    }
    |> fn(actual) {
      assert actual == None
    }
  Nil
}

pub fn strategy_for_hosted_domain_authorize_url_includes_hosted_domain_hint_test() -> Nil {
  let google_strategy =
    vestibule_google.strategy_for_hosted_domain("corp.example")
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth("secret"),
    )
  let assert Ok(url) =
    strategy.build_authorize_url(
      google_strategy,
      config: client_config,
      options: config.authorize_options(),
      scopes: ["openid"],
      state: "state",
    )
  let _ =
    { string.contains(url, "hd=corp.example") }
    |> fn(actual) {
      assert actual
    }
  Nil
}

pub fn sans_io_token_request_and_response_preserve_id_token_test() -> Nil {
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.client_secret_auth("client-secret"),
    )
  let assert Ok(http_request) =
    vestibule_google.build_authorization_code_request(
      client_config,
      "code-123",
      Some("verifier-123"),
    )
  assert http_request.method == http.Post
  assert http_request.host == "oauth2.googleapis.com"
  assert string.ends_with(http_request.path, "/token")
  assert string.contains(http_request.body, "code_verifier=verifier-123")
  assert request.get_header(http_request, "accept") == Ok("application/json")

  let http_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"access-123\",\"token_type\":\"Bearer\",\"scope\":\"openid\",\"id_token\":\"header.payload.signature\"}",
    )
  let assert Ok(exchange) =
    vestibule_google.parse_authorization_code_response(http_response)
  let assert Ok(id_token) =
    dict.get(strategy.exchange_artifacts(exchange), "id_token")
  assert decode.run(id_token, decode.string) == Ok("header.payload.signature")
}

pub fn sans_io_refresh_and_user_info_test() -> Nil {
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example.com/callback",
      auth: config.client_secret_auth("client-secret"),
    )
  let assert Ok(refresh_request) =
    vestibule_google.build_refresh_token_request(client_config, "refresh-123")
  assert string.contains(refresh_request.body, "grant_type=refresh_token")
  let refresh_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"access_token\":\"new-access\",\"token_type\":\"Bearer\"}",
    )
  let assert Ok(refreshed_credentials) =
    vestibule_google.parse_refresh_token_response(refresh_response)
  assert credential.token(refreshed_credentials) == "new-access"

  let oauth_credentials =
    credential.new(
      token: "access-123",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: [],
    )
  let assert Ok(user_request) =
    vestibule_google.build_user_info_request(oauth_credentials)
  assert user_request.host == "www.googleapis.com"
  assert request.get_header(user_request, "authorization")
    == Ok("Bearer access-123")

  let user_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"sub\":\"user-123\",\"email\":\"user@example.com\",\"email_verified\":true}",
    )
  let assert Ok(#(user_id, user, _hosted_domain)) =
    vestibule_google.parse_user_info_response(user_response)
  assert user_id == "user-123"
  assert user_info.email(user) == Some("user@example.com")
}

pub fn jwks_request_and_invalid_response_test() -> Nil {
  let assert Ok(http_request) = vestibule_google.build_jwks_request()
  assert http_request.host == "www.googleapis.com"
  assert http_request.path == "/oauth2/v3/certs"
  assert request.get_header(http_request, "accept") == Ok("application/json")

  let invalid_response =
    response.Response(status: 200, headers: [], body: "{\"keys\":[]}")
  let assert Error(authentication_error) =
    vestibule_google.parse_jwks_response(invalid_response)
  assert error.kind(authentication_error) == error.UserInfoKind
}

pub fn callback_accepts_signed_bound_hosted_domain_identity_test() -> Nil {
  let assert Ok(auth_result) =
    google_callback("user-123", "corp.example", "nonce", "nonce")
  assert auth.uid(auth_result) == "user-123"
}

pub fn callback_rejects_signed_token_userinfo_substitution_test() -> Nil {
  let assert Error(auth_error) =
    google_callback("victim", "corp.example", "nonce", "nonce")
  assert error.kind(auth_error) == error.UserInfoKind
}

pub fn callback_rejects_wrong_signed_hosted_domain_test() -> Nil {
  let assert Error(auth_error) =
    google_callback("user-123", "evil.example", "nonce", "nonce")
  assert error.kind(auth_error) == error.UserInfoKind
}

pub fn callback_rejects_wrong_signed_nonce_test() -> Nil {
  let assert Error(auth_error) =
    google_callback("user-123", "corp.example", "wrong", "nonce")
  assert error.kind(auth_error) == error.InvalidNonceKind
}

pub fn callback_rejects_tampered_rs256_signature_before_userinfo_test() -> Nil {
  let id_token =
    google_token(
      "https://accounts.google.com",
      "client-id",
      Some("corp.example"),
      "nonce",
      duration.minutes(5),
    )
    |> jwt_signing.tamper_signature
  let assert Error(_) =
    run_google_callback(
      Some(id_token),
      "user-123",
      Some("corp.example"),
      "nonce",
      False,
    )
  Nil
}

pub fn callback_rejects_missing_id_token_before_userinfo_test() -> Nil {
  let assert Error(_) =
    run_google_callback(None, "user-123", Some("corp.example"), "nonce", False)
  Nil
}

pub fn callback_rejects_wrong_id_token_issuer_before_userinfo_test() -> Nil {
  let id_token =
    google_token(
      "https://evil.example",
      "client-id",
      Some("corp.example"),
      "nonce",
      duration.minutes(5),
    )
  let assert Error(_) =
    run_google_callback(
      Some(id_token),
      "user-123",
      Some("corp.example"),
      "nonce",
      False,
    )
  Nil
}

pub fn callback_rejects_wrong_id_token_audience_before_userinfo_test() -> Nil {
  let id_token =
    google_token(
      "https://accounts.google.com",
      "other-client",
      Some("corp.example"),
      "nonce",
      duration.minutes(5),
    )
  let assert Error(_) =
    run_google_callback(
      Some(id_token),
      "user-123",
      Some("corp.example"),
      "nonce",
      False,
    )
  Nil
}

pub fn callback_rejects_expired_id_token_before_userinfo_test() -> Nil {
  let id_token =
    google_token(
      "https://accounts.google.com",
      "client-id",
      Some("corp.example"),
      "nonce",
      duration.seconds(-120),
    )
  let assert Error(_) =
    run_google_callback(
      Some(id_token),
      "user-123",
      Some("corp.example"),
      "nonce",
      False,
    )
  Nil
}

pub fn callback_rejects_missing_signed_hd_even_when_userinfo_allows_domain_test() -> Nil {
  let id_token =
    google_token(
      "https://accounts.google.com",
      "client-id",
      None,
      "nonce",
      duration.minutes(5),
    )
  let assert Error(auth_error) =
    run_google_callback(
      Some(id_token),
      "user-123",
      Some("corp.example"),
      "nonce",
      True,
    )
  assert error.kind(auth_error) == error.UserInfoKind
}

fn google_callback(
  userinfo_subject: String,
  hosted_domain: String,
  token_nonce: String,
  expected_nonce: String,
) {
  let id_token =
    google_token(
      "https://accounts.google.com",
      "client-id",
      Some(hosted_domain),
      token_nonce,
      duration.minutes(5),
    )
  run_google_callback(
    Some(id_token),
    userinfo_subject,
    None,
    expected_nonce,
    True,
  )
}

fn google_token(
  issuer: String,
  audience: String,
  hosted_domain: Option(String),
  nonce: String,
  max_age: duration.Duration,
) -> String {
  let payload = case hosted_domain {
    Some(domain) -> [
      #("sub", json.string("user-123")),
      #("hd", json.string(domain)),
    ]
    None -> [#("sub", json.string("user-123"))]
  }
  jwt_signing.encode(payload, [
    claim.issuer(issuer, []),
    claim.audience(audience, []),
    claim.custom(
      name: "nonce",
      value: nonce,
      encode: json.string,
      decoder: decode.string,
    ),
    claim.expires_at(max_age: max_age, leeway: duration.seconds(0)),
  ])
}

fn run_google_callback(
  id_token: Option(String),
  userinfo_subject: String,
  userinfo_hosted_domain: Option(String),
  expected_nonce: String,
  allow_userinfo: Bool,
) {
  let sender = fn(http_request: request.Request(String)) {
    case
      http_request.host,
      string.ends_with(http_request.path, "/token"),
      string.ends_with(http_request.path, "/certs"),
      string.ends_with(http_request.path, "/userinfo")
    {
      "oauth2.googleapis.com", True, _, _ -> {
        let fields = [
          #("access_token", json.string("access-token")),
          #("token_type", json.string("Bearer")),
          #("scope", json.string("openid email profile")),
        ]
        let fields = case id_token {
          Some(token) -> [#("id_token", json.string(token)), ..fields]
          None -> fields
        }
        Ok(response.Response(
          status: 200,
          headers: [],
          body: json.object(fields) |> json.to_string(),
        ))
      }
      "www.googleapis.com", _, True, _ ->
        Ok(response.Response(status: 200, headers: [], body: jwt_signing.jwks()))
      "www.googleapis.com", _, _, True -> {
        case allow_userinfo {
          False -> panic as "invalid Google ID token reached userinfo"
          True -> Nil
        }
        let fields = [
          #("sub", json.string(userinfo_subject)),
          #("email", json.string("user@example.com")),
          #("email_verified", json.bool(True)),
        ]
        let fields = case userinfo_hosted_domain {
          Some(domain) -> [#("hd", json.string(domain)), ..fields]
          None -> fields
        }
        Ok(response.Response(
          status: 200,
          headers: [],
          body: json.object(fields) |> json.to_string(),
        ))
      }
      _, _, _, _ -> Error(Nil)
    }
  }
  vestibule.handle_callback(
    vestibule_google.strategy_for_hosted_domain_with_sender(
      "corp.example",
      sender,
    ),
    config: config.new(
      client_id: "client-id",
      redirect_uri: "https://app.example/callback",
      auth: config.client_secret_auth("secret"),
    ),
    callback_params: dict.from_list([
      #("state", "state"),
      #("code", "code"),
    ]),
    expected_state: "state",
    code_verifier: "verifier",
    expected_nonce: Some(expected_nonce),
  )
}
