import gleam/dict
import gleam/dynamic
import gleam/option.{None}
import gleam/string
import gleeunit
import vestibule/config
import vestibule/credentials
import vestibule/error
import vestibule/strategy
import vestibule_indieauth
import vestibule_indieauth/discovery.{
  type DiscoveredEndpoints, DiscoveredEndpoints,
}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn authorize_url_includes_extra_params_test() -> Nil {
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
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("prompt", "login")])

  let assert Ok(url) =
    strategy.build_authorize_url(
      indieauth_strategy,
      config: client_config,
      options: options,
      scopes: ["profile"],
      state: "state",
    )

  string.contains(url, "prompt=login")
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
      auth: config.ClientSecret("secret"),
    )
  let assert Ok(options) =
    config.authorize_options()
    |> config.with_extra_params([#("me", "https://attacker.example.com/")])

  let result =
    strategy.build_authorize_url(
      indieauth_strategy,
      config: client_config,
      options: options,
      scopes: ["profile"],
      state: "state",
    )

  case result {
    Error(err) -> {
      error.kind(err)
      |> fn(actual) {
        assert actual == error.ConfigKind
      }
      error.message(err)
      |> string.contains("Reserved authorization parameter not allowed: me")
      |> fn(actual) {
        assert actual
      }
    }
    _ -> panic as "expected ConfigError for reserved IndieAuth me parameter"
  }
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
    auth: config.PublicClient,
  )
}

fn exchange_with_me(me: option.Option(String)) -> strategy.ExchangeResult {
  let creds =
    credentials.new(
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
  strategy.exchange_result_with_artifacts(creds, artifacts)
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
  let assert Error(err) = result
  error.kind(err)
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
