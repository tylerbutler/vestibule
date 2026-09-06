import gleam/dict
import gleam/dynamic/decode
import gleam/http/response
import gleam/json
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import vestibule
import vestibule/auth
import vestibule/authorization_request
import vestibule/config
import vestibule/error
import vestibule/oidc
import vestibule/provider_support
import vestibule/strategy
import vestibule_oidc
import vestibule_oidc/jwt_signing
import ywt/claim

pub fn callback_accepts_matching_verified_subject_test() -> Nil {
  let assert Ok(auth_result) =
    callback_result("matching", "user-123", "user-123", ValidToken)
  assert auth.uid(auth_result) == "user-123"
  assert auth.provider(auth_result) == "https://matching.example/tenant"
}

pub fn callback_rejects_userinfo_subject_substitution_test() -> Nil {
  let assert Error(auth_error) =
    callback_result("subject-mismatch", "attacker", "victim", ValidToken)
  assert error.kind(auth_error) == error.UserInfoKind
  assert !string.contains(error.message(auth_error), "******")
}

pub fn callback_rejects_forged_id_token_test() -> Nil {
  let assert Error(auth_error) =
    callback_result("forged", "user-123", "user-123", ForgedToken)
  assert error.kind(auth_error) == error.UserInfoKind
  assert !string.contains(error.message(auth_error), "******")
}

pub fn callback_rejects_wrong_audience_test() -> Nil {
  let assert Error(auth_error) =
    callback_result("audience", "user-123", "user-123", WrongAudience)
  assert error.kind(auth_error) == error.UserInfoKind
}

pub fn callback_rejects_empty_userinfo_subject_test() -> Nil {
  let assert Error(auth_error) =
    callback_result("empty-subject", "user-123", "", ValidToken)
  assert error.kind(auth_error) == error.UserInfoKind
}

pub fn callback_rejects_empty_id_token_subject_test() -> Nil {
  let assert Error(auth_error) =
    callback_result("empty-id-subject", "", "", ValidToken)
  assert error.kind(auth_error) == error.UserInfoKind
}

pub fn callback_refreshes_unknown_kid_once_test() -> Nil {
  reset_counter()
  let issuer = "https://refresh.example/tenant"
  let oidc_config = oidc_config(issuer)
  let client_config = client_config()
  let initial_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, issuer)
  let assert Ok(request) =
    vestibule.create_authorization_request(
      initial_strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let assert Some(nonce) = authorization_request.nonce(request)
  let token = signed_token(issuer, "client-id", nonce, "user-123")
  let sender = fn(http_request) {
    let path = provider_support.secure_request_uri(http_request).path
    case
      string.ends_with(path, "/token"),
      string.ends_with(path, "/keys"),
      string.ends_with(path, "/userinfo")
    {
      True, _, _ -> Ok(http_response(token_response(token)))
      _, True, _ -> {
        let call = increment_counter()
        case call {
          1 -> Ok(http_response(jwt_signing.wrong_jwks()))
          _ -> Ok(http_response(jwt_signing.jwks()))
        }
      }
      _, _, True -> Ok(http_response("{\"sub\":\"user-123\"}"))
      _, _, _ -> Error(error.network(reason: "Unexpected OIDC test endpoint"))
    }
  }
  let oidc_strategy =
    vestibule_oidc.strategy_from_config_with_sender(oidc_config, issuer, sender)
  let assert Ok(_) =
    vestibule.handle_callback(
      oidc_strategy,
      config: client_config,
      callback_params: dict.from_list([
        #("state", authorization_request.state(request)),
        #("code", "authorization-code"),
      ]),
      expected_state: authorization_request.state(request),
      code_verifier: authorization_request.code_verifier(request),
      expected_nonce: Some(nonce),
    )
  assert counter() == 2
}

pub fn issuer_namespace_preserves_path_and_port_test() -> Nil {
  let first = oidc_config("https://login.example:8443/trusted")
  let second = oidc_config("https://login.example:9443/trusted")
  let third = oidc_config("https://login.example:8443/other")
  assert vestibule_oidc.issuer_namespace(first)
    == "https://login.example:8443/trusted"
  assert vestibule_oidc.issuer_namespace(first)
    != vestibule_oidc.issuer_namespace(second)
  assert vestibule_oidc.issuer_namespace(first)
    != vestibule_oidc.issuer_namespace(third)
  assert vestibule_oidc.issuer_namespace(first)
    == vestibule_oidc.issuer_namespace(first)
}

pub fn issuer_namespace_preserves_trailing_slash_test() -> Nil {
  let without_slash = oidc_config("https://login.example/tenant")
  let with_slash = oidc_config("https://login.example/tenant/")
  assert vestibule_oidc.issuer_namespace(without_slash)
    != vestibule_oidc.issuer_namespace(with_slash)
}

pub fn discovered_configs_build_distinct_account_namespaces_test() -> Nil {
  let first_document =
    "{\"issuer\":\"https://login.example:8443/trusted\",\"authorization_endpoint\":\"https://login.example:8443/trusted/authorize\",\"token_endpoint\":\"https://login.example:8443/trusted/token\",\"userinfo_endpoint\":\"https://login.example:8443/trusted/userinfo\",\"jwks_uri\":\"https://login.example:8443/trusted/keys\",\"id_token_signing_alg_values_supported\":[\"RS256\"]}"
  let second_document =
    "{\"issuer\":\"https://login.example:8443/other\",\"authorization_endpoint\":\"https://login.example:8443/other/authorize\",\"token_endpoint\":\"https://login.example:8443/other/token\",\"userinfo_endpoint\":\"https://login.example:8443/other/userinfo\",\"jwks_uri\":\"https://login.example:8443/other/keys\",\"id_token_signing_alg_values_supported\":[\"RS256\"]}"
  let assert Ok(first) = vestibule_oidc.parse_discovery_document(first_document)
  let assert Ok(second) =
    vestibule_oidc.parse_discovery_document(second_document)
  let first_strategy =
    vestibule_oidc.strategy_from_config(
      first,
      vestibule_oidc.issuer_namespace(first),
    )
  let second_strategy =
    vestibule_oidc.strategy_from_config(
      second,
      vestibule_oidc.issuer_namespace(second),
    )
  assert strategy.provider(first_strategy)
    == "https://login.example:8443/trusted"
  assert strategy.provider(first_strategy) != strategy.provider(second_strategy)
}

pub fn jwks_request_is_bounded_test() -> Nil {
  let oidc_config = oidc_config("https://bounded.example/tenant")
  let assert Ok(http_request) = vestibule_oidc.build_jwks_request(oidc_config)
  assert provider_support.secure_request_response_limit(http_request)
    == provider_support.DiscoveryResponse
}

pub fn verifier_accepts_audience_array_with_azp_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let token =
    jwt_signing.encode(
      payload: [
        #("sub", json.string("user-123")),
        #("aud", json.array(["client-id", "api"], of: json.string)),
        #("azp", json.string("client-id")),
      ],
      claims: [
        claim.issuer("https://array.example", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
    )
  let assert Ok(verified) =
    oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://array.example",
      audience: "client-id",
      expected_nonce: None,
    )
  assert oidc.subject(verified) == "user-123"
}

pub fn verifier_rejects_multiple_audiences_without_azp_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let token =
    jwt_signing.encode(
      payload: [
        #("sub", json.string("user-123")),
        #("aud", json.array(["client-id", "api"], of: json.string)),
      ],
      claims: [
        claim.issuer("https://array-missing-azp.example", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
    )
  assert oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://array-missing-azp.example",
      audience: "client-id",
      expected_nonce: None,
    )
    == Error(oidc.MissingClaim("azp"))
}

pub fn verifier_rejects_expired_token_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let token =
    jwt_signing.encode(
      payload: [
        #("sub", json.string("user-123")),
        #("exp", json.int(1)),
      ],
      claims: [
        claim.issuer("https://expired.example", []),
        claim.audience("client-id", []),
      ],
    )
  assert oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://expired.example",
      audience: "client-id",
      expected_nonce: None,
    )
    == Error(oidc.Expired)
}

pub fn verifier_rejects_missing_subject_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let token =
    jwt_signing.encode(payload: [], claims: [
      claim.issuer("https://missing-subject.example", []),
      claim.audience("client-id", []),
      claim.expires_at(
        max_age: duration.minutes(5),
        leeway: duration.seconds(0),
      ),
    ])
  let assert Error(_) =
    oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://missing-subject.example",
      audience: "client-id",
      expected_nonce: None,
    )
  Nil
}

pub fn verifier_rejects_future_time_claims_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let future_iat =
    jwt_signing.encode(
      payload: [
        #("sub", json.string("user-123")),
        #("iat", json.int(4_000_000_000)),
      ],
      claims: [
        claim.issuer("https://future-iat.example", []),
        claim.audience("client-id", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
    )
  assert oidc.verify_rs256(
      token: future_iat,
      using: keys,
      issuer: "https://future-iat.example",
      audience: "client-id",
      expected_nonce: None,
    )
    == Error(oidc.InvalidIssuedAt)

  let future_nbf =
    jwt_signing.encode(
      payload: [
        #("sub", json.string("user-123")),
        #("nbf", json.int(4_000_000_000)),
      ],
      claims: [
        claim.issuer("https://future-nbf.example", []),
        claim.audience("client-id", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
    )
  assert oidc.verify_rs256(
      token: future_nbf,
      using: keys,
      issuer: "https://future-nbf.example",
      audience: "client-id",
      expected_nonce: None,
    )
    == Error(oidc.NotYetValid)
}

pub fn verifier_rejects_nonce_mismatch_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let token =
    signed_token(
      "https://nonce.example",
      "client-id",
      "actual-nonce",
      "user-123",
    )
  assert oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://nonce.example",
      audience: "client-id",
      expected_nonce: Some("expected-nonce"),
    )
    == Error(oidc.InvalidNonce)
}

pub fn verifier_rejects_unsigned_algorithm_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let token =
    signed_token("https://algorithm.example", "client-id", "nonce", "user-123")
    |> jwt_signing.with_algorithm("none")
  assert oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://algorithm.example",
      audience: "client-id",
      expected_nonce: Some("nonce"),
    )
    == Error(oidc.UnsupportedAlgorithm)
}

pub fn verifier_accepts_jwk_without_optional_algorithm_test() -> Nil {
  let jwks = string.replace(jwt_signing.jwks(), "\",\"alg\":\"RS256", "")
  let assert Ok(keys) = oidc.parse_jwks(jwks)
  let token =
    signed_token(
      "https://missing-key-alg.example",
      "client-id",
      "nonce",
      "user-123",
    )
  let assert Ok(_) =
    oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://missing-key-alg.example",
      audience: "client-id",
      expected_nonce: Some("nonce"),
    )
  Nil
}

pub fn verifier_ignores_unrelated_jwks_algorithms_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.mixed_jwks())
  let token =
    signed_token("https://mixed-keys.example", "client-id", "nonce", "user-123")
  let assert Ok(_) =
    oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://mixed-keys.example",
      audience: "client-id",
      expected_nonce: Some("nonce"),
    )
  Nil
}

pub fn verifier_exposes_provider_specific_string_claims_test() -> Nil {
  let assert Ok(keys) = oidc.parse_jwks(jwt_signing.jwks())
  let token =
    jwt_signing.encode(
      payload: [
        #("sub", json.string("user-123")),
        #("hd", json.string("example.com")),
        #("tid", json.string("tenant-id")),
      ],
      claims: [
        claim.issuer("https://claims.example", []),
        claim.audience("client-id", []),
        claim.expires_at(
          max_age: duration.minutes(5),
          leeway: duration.seconds(0),
        ),
      ],
    )
  let assert Ok(verified) =
    oidc.verify_rs256(
      token: token,
      using: keys,
      issuer: "https://claims.example",
      audience: "client-id",
      expected_nonce: None,
    )
  assert oidc.string_claim(verified, "tid") == Ok("tenant-id")
  assert oidc.optional_string_claim(verified, "hd") == Ok(Some("example.com"))
  assert oidc.optional_string_claim(verified, "missing") == Ok(None)
}

type TokenKind {
  ValidToken
  ForgedToken
  WrongAudience
}

fn callback_result(
  issuer_name: String,
  id_subject: String,
  userinfo_subject: String,
  token_kind: TokenKind,
) {
  let issuer = "https://" <> issuer_name <> ".example/tenant"
  let oidc_config = oidc_config(issuer)
  let client_config = client_config()
  let initial_strategy =
    vestibule_oidc.strategy_from_config(oidc_config, issuer)
  let assert Ok(request) =
    vestibule.create_authorization_request(
      initial_strategy,
      config: client_config,
      options: config.authorize_options(),
    )
  let assert Some(nonce) = authorization_request.nonce(request)
  let audience = case token_kind {
    WrongAudience -> "other-client"
    ValidToken | ForgedToken -> "client-id"
  }
  let valid_token = signed_token(issuer, audience, nonce, id_subject)
  let id_token = case token_kind {
    ForgedToken -> forge_signature(valid_token)
    ValidToken | WrongAudience -> valid_token
  }
  let sender = fn(http_request) {
    let path = provider_support.secure_request_uri(http_request).path
    case
      string.ends_with(path, "/token"),
      string.ends_with(path, "/keys"),
      string.ends_with(path, "/userinfo")
    {
      True, _, _ -> Ok(http_response(token_response(id_token)))
      _, True, _ -> Ok(http_response(jwt_signing.jwks()))
      _, _, True ->
        Ok(http_response(
          json.object([#("sub", json.string(userinfo_subject))])
          |> json.to_string(),
        ))
      _, _, _ -> Error(error.network(reason: "Unexpected OIDC test endpoint"))
    }
  }
  let oidc_strategy =
    vestibule_oidc.strategy_from_config_with_sender(oidc_config, issuer, sender)
  vestibule.handle_callback(
    oidc_strategy,
    config: client_config,
    callback_params: dict.from_list([
      #("state", authorization_request.state(request)),
      #("code", "authorization-code"),
    ]),
    expected_state: authorization_request.state(request),
    code_verifier: authorization_request.code_verifier(request),
    expected_nonce: Some(nonce),
  )
}

fn forge_signature(token: String) -> String {
  let assert [header, payload, signature] = string.split(token, on: ".")
  let replacement = case string.starts_with(signature, "A") {
    True -> "B"
    False -> "A"
  }
  header
  <> "."
  <> payload
  <> "."
  <> replacement
  <> string.drop_start(signature, 1)
}

fn signed_token(
  issuer: String,
  audience: String,
  nonce: String,
  subject: String,
) -> String {
  jwt_signing.encode(payload: [#("sub", json.string(subject))], claims: [
    claim.issuer(issuer, []),
    claim.audience(audience, []),
    claim.custom(
      name: "nonce",
      value: nonce,
      encode: json.string,
      decoder: decode.string,
    ),
    claim.expires_at(max_age: duration.minutes(5), leeway: duration.seconds(0)),
  ])
}

fn oidc_config(issuer: String) -> vestibule_oidc.OidcConfig {
  let assert Ok(oidc_config) =
    vestibule_oidc.new_config_with_jwks(
      issuer: issuer,
      authorization_endpoint: issuer <> "/authorize",
      token_endpoint: issuer <> "/token",
      userinfo_endpoint: issuer <> "/userinfo",
      jwks_uri: issuer <> "/keys",
      signing_algorithms: ["RS256"],
      scopes_supported: ["openid", "profile", "email"],
    )
  oidc_config
}

fn client_config() -> config.ClientConfig {
  config.new(
    client_id: "client-id",
    redirect_uri: "https://app.example/callback",
    auth: config.client_secret_auth("client-secret"),
  )
}

fn token_response(id_token: String) -> String {
  json.object([
    #("access_token", json.string("******")),
    #("token_type", json.string("Bearer")),
    #("id_token", json.string(id_token)),
  ])
  |> json.to_string()
}

fn http_response(body: String) -> response.Response(String) {
  response.Response(status: 200, headers: [], body: body)
}

@external(erlang, "vestibule_oidc_test_ffi", "reset_counter")
fn reset_counter() -> Nil

@external(erlang, "vestibule_oidc_test_ffi", "increment_counter")
fn increment_counter() -> Int

@external(erlang, "vestibule_oidc_test_ffi", "counter")
fn counter() -> Int
