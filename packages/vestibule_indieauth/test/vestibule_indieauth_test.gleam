import gleam/option.{None}
import gleam/string
import gleeunit
import vestibule/config
import vestibule/error
import vestibule/strategy
import vestibule_indieauth
import vestibule_indieauth/discovery.{DiscoveredEndpoints}

pub fn main() {
  gleeunit.main()
}

pub fn authorize_url_includes_extra_params_test() {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: None,
      userinfo_endpoint: None,
    )
  let strat = vestibule_indieauth.strategy(endpoints, "https://me.example.com/")
  let conf =
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
      strat,
      config: conf,
      options: options,
      scopes: ["profile"],
      state: "state",
    )

  assert string.contains(url, "prompt=login")
}

pub fn authorize_url_rejects_me_extra_param_test() {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: None,
      userinfo_endpoint: None,
    )
  let strat = vestibule_indieauth.strategy(endpoints, "https://me.example.com/")
  let conf =
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
      strat,
      config: conf,
      options: options,
      scopes: ["profile"],
      state: "state",
    )

  case result {
    Error(err) -> {
      assert error.kind(err) == error.ConfigKind
      assert string.contains(
        error.message(err),
        "Reserved authorization parameter not allowed: me",
      )
    }
    _ -> panic as "expected ConfigError for reserved IndieAuth me parameter"
  }
}
