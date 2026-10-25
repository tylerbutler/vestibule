import gleam/dict
import gleam/dynamic
import gleam/http
import gleam/http/response
import gleam/list
import gleam/option.{None}
import gleam/string
import gleeunit
import vestibule
import vestibule/auth
import vestibule/config
import vestibule/credential
import vestibule/error
import vestibule/provider_support
import vestibule/strategy
import vestibule/user_info
import vestibule_indieauth
import vestibule_indieauth/discovery.{
  type DiscoveredEndpoints, DiscoveredEndpoints,
}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn strategy_rejects_confidential_client_configuration_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: None,
      userinfo_endpoint: None,
    )
  let client_config =
    config.new(
      client_id: "https://client.example/",
      redirect_uri: "https://client.example/callback",
      auth: config.client_secret_auth("secret"),
    )
  let assert Error([validation_error]) =
    vestibule_indieauth.strategy(endpoints, "https://me.example.com/")
    |> strategy.validate_config(client_config)
  assert config.validation_error_field(validation_error) == "auth"
  assert config.validation_error_reason(validation_error)
    == "IndieAuth uses public-client authentication"
}

pub fn authorize_url_includes_extra_parameters_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: None,
      userinfo_endpoint: None,
    )
  let indieauth_strategy =
    vestibule_indieauth.strategy(endpoints, "https://me.example.com/")
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_parameters([#("prompt", "login")])

  let assert Ok(authorization_url) =
    strategy.build_authorize_url(
      indieauth_strategy,
      config: client_config,
      options: options,
      scopes: ["profile"],
      state: "state",
    )

  string.contains(authorization_url, "prompt=login")
  |> fn(actual) {
    assert actual
  }
}

pub fn authorize_url_rejects_me_extra_param_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: None,
      userinfo_endpoint: None,
    )
  let indieauth_strategy =
    vestibule_indieauth.strategy(endpoints, "https://me.example.com/")
  let client_config =
    config.new(
      client_id: "client-id",
      redirect_uri: "http://localhost/callback",
      auth: config.client_secret_auth("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_parameters([#("me", "https://attacker.example.com/")])

  let result =
    strategy.build_authorize_url(
      indieauth_strategy,
      config: client_config,
      options: options,
      scopes: ["profile"],
      state: "state",
    )

  case result {
    Error(auth_error) -> {
      error.kind(auth_error)
      |> fn(actual) {
        assert actual == error.ConfigKind
      }
      error.message(auth_error)
      |> string.contains("Reserved authorization parameter not allowed: me")
      |> fn(actual) {
        assert actual
      }
    }
    Ok(_) -> panic as "expected ConfigError for reserved IndieAuth me parameter"
  }
}

pub fn metadata_issuer_is_bound_to_callback_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: option.Some("https://auth.example.com/"),
      userinfo_endpoint: None,
    )
  let indieauth_strategy =
    vestibule_indieauth.strategy(endpoints, "https://me.example.com/")
  assert strategy.callback_issuer(indieauth_strategy)
    == option.Some("https://auth.example.com/")
}

pub fn metadata_callback_missing_issuer_stops_before_token_request_test() -> Nil {
  let assert Error(auth_error) =
    metadata_callback(
      dict.from_list([
        #("state", "state"),
        #("code", "honest-code"),
      ]),
      None,
    )
  assert error.kind(auth_error) == error.CodeExchangeKind
}

pub fn metadata_callback_wrong_issuer_stops_before_token_request_test() -> Nil {
  let assert Error(auth_error) =
    metadata_callback(
      dict.from_list([
        #("state", "state"),
        #("code", "honest-code"),
        #("iss", "https://honest.example/"),
      ]),
      option.Some(False),
    )
  assert error.kind(auth_error) == error.CodeExchangeKind
}

pub fn legacy_discovery_does_not_require_callback_issuer_test() -> Nil {
  let indieauth_strategy =
    vestibule_indieauth.strategy(test_endpoints(), "https://me.example.com/")
  assert strategy.callback_issuer(indieauth_strategy) == None
}

// === fetch_user: profile URL verification ===

fn test_endpoints() -> DiscoveredEndpoints {
  DiscoveredEndpoints(
    authorization_endpoint: "https://auth.example.com/authorize",
    token_endpoint: "https://auth.example.com/token",
    issuer: None,
    userinfo_endpoint: None,
  )
}

fn test_client_config() -> config.ClientConfig {
  config.new(
    client_id: "https://app.example.com/",
    redirect_uri: "https://app.example.com/callback",
    auth: config.public_client(),
  )
}

fn metadata_callback(
  callback_params: dict.Dict(String, String),
  response_issuer_flag: option.Option(Bool),
) -> Result(auth.Auth, error.AuthError(e)) {
  let flag = case response_issuer_flag {
    option.Some(value) ->
      ",\"authorization_response_iss_parameter_supported\":"
      <> case value {
        True -> "true"
        False -> "false"
      }
    None -> ""
  }
  let assert Ok(endpoints) =
    discovery.parse_metadata(
      "{\"authorization_endpoint\":\"https://attacker.example/authorize\","
      <> "\"token_endpoint\":\"https://attacker.example/token\","
      <> "\"issuer\":\"https://attacker.example/\""
      <> flag
      <> "}",
    )
  vestibule.handle_callback(
    vestibule_indieauth.strategy(endpoints, "https://me.example.com/"),
    config: test_client_config(),
    callback_parameters: callback_params,
    expected_state: "state",
    code_verifier: "pkce-verifier",
    expected_nonce: None,
  )
}

fn exchange_with_me(me: option.Option(String)) -> strategy.ExchangeResult {
  let oauth_credentials =
    credential.new(
      token: "token",
      refresh_token: None,
      token_type: "Bearer",
      expires_in: None,
      scopes: ["profile"],
    )
  let artifacts = case me {
    option.Some(value) -> dict.from_list([#("me", dynamic.string(value))])
    None -> dict.new()
  }
  strategy.exchange_result_with_artifacts(oauth_credentials, artifacts)
}

pub fn fetch_user_uses_verified_me_as_uid_test() -> Nil {
  let indieauth_strategy =
    vestibule_indieauth.strategy(test_endpoints(), "https://me.example.com/")

  let user =
    strategy.fetch_user(
      indieauth_strategy,
      config: test_client_config(),
      exchange: exchange_with_me(option.Some("https://ME.example.com")),
    )
    |> fn(result) {
      let assert Ok(value) = result
      value
    }

  strategy.user_result_uid(user)
  |> fn(actual) {
    assert actual == "https://me.example.com/"
  }
}

pub fn fetch_user_rejects_missing_me_test() -> Nil {
  let indieauth_strategy =
    vestibule_indieauth.strategy(test_endpoints(), "https://me.example.com/")

  let result =
    strategy.fetch_user(
      indieauth_strategy,
      config: test_client_config(),
      exchange: exchange_with_me(None),
    )
  let assert Error(auth_error) = result
  error.kind(auth_error)
  |> fn(actual) {
    assert actual == error.UserInfoKind
  }
}

pub fn fetch_user_rejects_unconfirmed_foreign_me_test() -> Nil {
  // The token endpoint asserts somebody else's profile URL. Confirming it
  // requires re-discovering that URL's authorization server; nothing serves
  // IndieAuth metadata on localhost:443, so confirmation fails and the
  // identity is rejected rather than trusted.
  let indieauth_strategy =
    vestibule_indieauth.strategy(test_endpoints(), "https://me.example.com/")

  let result =
    strategy.fetch_user(
      indieauth_strategy,
      config: test_client_config(),
      exchange: exchange_with_me(option.Some("https://localhost/")),
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

const token_profile =
  ",\"profile\":{\"name\":\"Token Name\",\"email\":\"unverified@example.com\",\"photo\":\"https://images.example.com/avatar.jpg\",\"url\":\"https://profile.example.com/about\"}"

fn profile_callback(
  token_me: String,
  profile_fields: String,
  userinfo_body: option.Option(String),
) -> Result(auth.Auth, error.AuthError(Nil)) {
  let endpoints =
    DiscoveredEndpoints(
      ..test_endpoints(),
      userinfo_endpoint: option.map(userinfo_body, fn(_) {
        "https://auth.example.com/userinfo"
      }),
    )
  let indieauth_strategy =
    vestibule_indieauth.strategy_with_sender(
      endpoints,
      "https://me.example.com/",
      fn(secure_request) {
        case provider_support.secure_request_uri(secure_request).path {
          "/token" -> {
            assert provider_support.secure_request_method(secure_request)
              == http.Post
            assert string.contains(
              provider_support.secure_request_body(secure_request),
              "code_verifier=pkce-verifier",
            )
            Ok(
              response.new(200)
              |> response.set_body(
                "{\"access_token\":\"private-token\",\"token_type\":\"Bearer\",\"me\":\""
                <> token_me
                <> "\""
                <> profile_fields
                <> "}",
              ),
            )
          }
          "/userinfo" -> {
            let assert option.Some(body) = userinfo_body
            assert provider_support.secure_request_method(secure_request)
              == http.Get
            assert provider_support.secure_request_header(
                secure_request,
                "authorization",
              )
              == Ok("Bearer private-token")
            Ok(response.new(200) |> response.set_body(body))
          }
          _ -> panic as "unexpected request"
        }
      },
    )
  vestibule.handle_callback(
    indieauth_strategy,
    config: test_client_config(),
    callback_parameters: dict.from_list([
      #("state", "state"),
      #("code", "authorization-code"),
    ]),
    expected_state: "state",
    code_verifier: "pkce-verifier",
    expected_nonce: None,
  )
}

pub fn callback_retains_token_profile_without_userinfo_endpoint_test() -> Nil {
  let assert Ok(authentication) =
    profile_callback("https://ME.example.com", token_profile, None)
  assert auth.uid(authentication) == "https://me.example.com/"
  assert auth.provider(authentication) == "indieauth"
  let info = auth.info(authentication)
  assert user_info.name(info) == option.Some("Token Name")
  assert user_info.email(info) == option.Some("unverified@example.com")
  assert user_info.image(info)
    == option.Some("https://images.example.com/avatar.jpg")
  assert dict.get(user_info.urls(info), "url")
    == Ok("https://profile.example.com/about")
  assert credential.token(auth.credentials(authentication)) == "private-token"
  assert auth.extra(authentication) == dict.new()
}

pub fn callback_accepts_missing_empty_and_null_token_profiles_test() -> Nil {
  list.each(["", ",\"profile\":{}", ",\"profile\":null"], fn(profile_fields) {
    let assert Ok(authentication) =
      profile_callback("https://me.example.com/", profile_fields, None)
    let info = auth.info(authentication)
    assert auth.uid(authentication) == "https://me.example.com/"
    assert user_info.name(info) == None
    assert user_info.email(info) == None
    assert user_info.image(info) == None
    assert dict.get(user_info.urls(info), "url") == Ok(auth.uid(authentication))
  })
}

pub fn callback_accepts_partial_token_profile_and_optional_email_test() -> Nil {
  let assert Ok(authentication) =
    profile_callback(
      "https://me.example.com/",
      ",\"profile\":{\"name\":\"Only Name\",\"email\":null}",
      None,
    )
  let info = auth.info(authentication)
  assert user_info.name(info) == option.Some("Only Name")
  assert user_info.email(info) == None
  assert user_info.image(info) == None
  assert dict.get(user_info.urls(info), "url") == Ok(auth.uid(authentication))
}

pub fn callback_token_profile_cannot_bypass_identity_confirmation_test() -> Nil {
  let assert Error(auth_error) =
    profile_callback(
      "https://localhost/",
      ",\"profile\":{\"name\":\"Attacker\",\"url\":\"https://me.example.com/\"}",
      option.Some("not reached: confirmation must fail before userinfo"),
    )
  assert error.kind(auth_error) == error.UserInfoKind
  assert string.contains(error.message(auth_error), "invalid profile URL")
}

pub fn callback_rejects_unconfirmed_token_identity_with_profile_test() -> Nil {
  let assert Error(auth_error) =
    profile_callback(
      "https://unconfirmed.invalid/",
      ",\"profile\":{\"name\":\"Attacker\",\"url\":\"https://me.example.com/\"}",
      option.Some("not reached: confirmation must fail before userinfo"),
    )
  assert error.kind(auth_error) == error.UserInfoKind
  assert string.contains(error.message(auth_error), "Could not confirm")
}

pub fn callback_rejects_conflicting_userinfo_identity_with_token_profile_test() -> Nil {
  let assert Error(auth_error) =
    profile_callback(
      "https://me.example.com/",
      token_profile,
      option.Some(
        "{\"me\":\"https://other.example.com/\",\"name\":\"Other Name\",\"url\":\"https://me.example.com/\"}",
      ),
    )
  assert error.kind(auth_error) == error.UserInfoKind
  assert string.contains(error.message(auth_error), "confirmed identity")
}

pub fn callback_preserves_userinfo_endpoint_enrichment_test() -> Nil {
  let assert Ok(authentication) =
    profile_callback(
      "https://me.example.com/",
      token_profile,
      option.Some(
        "{\"me\":\"https://ME.example.com\",\"name\":\"Endpoint Name\",\"email\":\"endpoint@example.com\",\"photo\":\"https://images.example.com/new.jpg\",\"url\":\"https://profile.example.com/updated\"}",
      ),
    )
  assert auth.uid(authentication) == "https://me.example.com/"
  let info = auth.info(authentication)
  assert user_info.name(info) == option.Some("Endpoint Name")
  assert user_info.email(info) == option.Some("endpoint@example.com")
  assert user_info.image(info)
    == option.Some("https://images.example.com/new.jpg")
  assert dict.get(user_info.urls(info), "url")
    == Ok("https://profile.example.com/updated")
}

pub fn token_profile_artifacts_are_not_exposed_by_inspection_test() -> Nil {
  let indieauth_strategy =
    vestibule_indieauth.strategy_with_sender(
      test_endpoints(),
      "https://me.example.com/",
      fn(_) {
        Ok(
          response.new(200)
          |> response.set_body(
            "{\"access_token\":\"private-token\",\"token_type\":\"Bearer\",\"me\":\"https://me.example.com/\""
            <> token_profile
            <> "}",
          ),
        )
      },
    )
  let assert Ok(exchange) =
    strategy.exchange_code(
      indieauth_strategy,
      config: test_client_config(),
      code: "authorization-code",
      code_verifier: None,
    )
  let inspected = string.inspect(exchange)
  assert !string.contains(inspected, "private-token")
  assert !string.contains(inspected, "Token Name")
  assert !string.contains(inspected, "unverified@example.com")
}

pub fn refresh_uses_secure_sender_and_existing_response_parser_test() -> Nil {
  let indieauth_strategy =
    vestibule_indieauth.strategy_with_sender(
      test_endpoints(),
      "https://me.example.com/",
      fn(secure_request) {
        assert provider_support.secure_request_uri(secure_request).path
          == "/token"
        assert provider_support.secure_request_method(secure_request)
          == http.Post
        assert string.contains(
          provider_support.secure_request_body(secure_request),
          "grant_type=refresh_token",
        )
        assert provider_support.secure_request_response_limit(secure_request)
          == provider_support.TokenResponse
        Ok(
          response.new(200)
          |> response.set_body(
            "{\"access_token\":\"refreshed-token\",\"token_type\":\"Bearer\"}",
          ),
        )
      },
    )
  let assert Ok(oauth_credentials) =
    strategy.refresh_token(
      indieauth_strategy,
      config: test_client_config(),
      refresh_token: "refresh-token",
    )
  assert credential.token(oauth_credentials) == "refreshed-token"
}
