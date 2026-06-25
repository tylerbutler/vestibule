export const middlewareInstallCode = `gleam add vestibule
gleam add vestibule_github
gleam add vestibule_wisp`;

export const coreInstallCode = `gleam add vestibule
gleam add vestibule_github`;

export const coreCode = `import gleam/dict
import gleam/option
import vestibule
import vestibule/authorization_request
import vestibule/config
import vestibule/error
import vestibule_github

let strategy = vestibule_github.strategy()
let cfg =
  config.new(
    client_id: "client_id",
    redirect_uri: "http://localhost:8000/auth/github/callback",
    auth: config.ClientSecret("client_secret"),
  )

let options = config.authorize_options()
let assert Ok(auth_request) =
  vestibule.create_authorization_request(
    strategy,
    cfg: cfg,
    options: options,
  )
// Store authorization_request.state(auth_request) and
// authorization_request.code_verifier(auth_request) server-side,
// bound to this user's session, with an expiration time.
// Redirect user to authorization_request.url(auth_request).

let params =
  dict.from_list([
    #("state", "state from callback"),
    #("code", "authorization code from callback"),
  ])

// Validate the callback. Never assert here: state can mismatch and
// providers can reject the user.
case
  vestibule.handle_callback(
    strategy,
    cfg,
    params,
    "expected state from session",
    "code verifier from session",
    expected_nonce: option.None,
  )
{
  Ok(auth) -> {
    // Delete the stored state and code_verifier, then map auth.uid(auth)
    // to an account and start a session.
    sign_in(auth)
  }
  // Possible CSRF or a stale tab: discard and restart the flow.
  Error(err) ->
    case error.kind(err) {
      error.StateMismatchKind -> restart_sign_in()
      // Provider, code-exchange, network, or decode failure.
      _ -> show_auth_error(err)
    }
}`;

export const wispCode = `import gleam/http
import wisp
import vestibule/config
import vestibule/registry
import vestibule/state_store
import vestibule_wisp
import vestibule_github

let assert Ok(reg) =
  registry.new()
  |> registry.register(
    vestibule_github.strategy(),
    config.new(
      client_id: "client_id",
      redirect_uri: "http://localhost:8000/auth/github/callback",
      auth: config.ClientSecret("client_secret"),
    ),
  )

let store = state_store.init()

case wisp.path_segments(req), req.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase(
      req,
      reg,
      provider,
      store,
      authorize_options: config.authorize_options(),
    )

  ["auth", provider, "callback"], http.Get
  | ["auth", provider, "callback"], http.Post ->
    case vestibule_wisp.callback_phase_auth_result(req, reg, provider, store) {
      // auth.uid(auth) identifies the user: map it to an account, then
      // start your own session.
      Ok(auth) -> start_session(auth)

      // Benign: a stale tab, back button, or already-used callback.
      Error(vestibule_wisp.SessionExpired) ->
        wisp.redirect("/login?error=expired")

      // Everything else (forged state, provider rejection, bad params).
      Error(_) ->
        wisp.redirect("/login?error=auth")
    }

  _, _ ->
    wisp.not_found()
}`;

export const callbackFailureCode = `import gleam/option
import vestibule
import vestibule/error

case
  vestibule.handle_callback(
    strategy,
    cfg,
    params,
    expected_state,
    verifier,
    expected_nonce: option.None,
  )
{
  Ok(auth) -> sign_in(auth)

  // Classify the failure with error.kind/0; the ErrorKind enum carries an
  // OtherKind catch-all, so new kinds never break this match.
  Error(err) ->
    case error.kind(err) {
      // Wrong state: treat as hostile. Log server-side, restart the flow.
      error.StateMismatchKind -> restart_sign_in()

      // The provider rejected the request (e.g. denied consent). Inspect
      // error.provider_error(err) for the structured code/description.
      error.ProviderKind -> back_to_login()

      // Transient upstream failures are worth a retry prompt.
      error.NetworkKind | error.CodeExchangeKind -> offer_retry()

      // Catch-all: show a generic message, keep error.message(err) in logs.
      _ -> show_auth_error(err)
    }
}`;

export const discoverCode = `import vestibule/oidc

let assert Ok(strategy) = oidc.discover("https://accounts.google.com")`;

export const selfHostedCode = `import vestibule
import vestibule/config
import vestibule/oidc

// Discovery reads https://your-pocket-id-instance/.well-known/openid-configuration
let assert Ok(strategy) = oidc.discover("https://your-pocket-id-instance")
let cfg =
  config.new(
    client_id: "your-client-id",
    redirect_uri: "http://localhost:8000/auth/oidc/callback",
    auth: config.ClientSecret("your-client-secret"),
  )

let options = config.authorize_options()
let assert Ok(auth_request) =
  vestibule.create_authorization_request(
    strategy,
    cfg: cfg,
    options: options,
  )`;

export const strategyType = `pub opaque type Strategy(e)

pub fn new(
  provider provider: String,
  default_scopes default_scopes: List(String),
) -> Strategy(e)

pub fn with_authorize_url(
  strategy: Strategy(e),
  authorize_url: fn(ClientConfig, AuthorizeOptions, List(String), String) ->
    Result(String, AuthError(e)),
) -> Strategy(e)

pub fn with_exchange_code(
  strategy: Strategy(e),
  exchange_code: fn(ClientConfig, String, Option(String)) ->
    Result(ExchangeResult, AuthError(e)),
) -> Strategy(e)`;

export const authorizeUrl = `fn do_authorize_url(
  cfg: ClientConfig,
  options: AuthorizeOptions,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://id.twitch.tv")
  use redirect <- result.try(
    provider_support.parse_redirect_uri(config.redirect_uri(cfg)),
  )

  use secret <- result.try(config.client_secret(cfg))
  let client =
    glow_auth.Client(
      id: config.client_id(cfg),
      secret: secret,
      site: site,
    )

  let url =
    authorize_uri.build(
      client,
      uri_builder.RelativePath("/oauth2/authorize"),
      redirect,
    )
    |> authorize_uri.set_scope(string.join(scopes, " "))
    |> authorize_uri.set_state(state)
    |> authorize_uri.to_code_authorization_uri()
    |> uri.to_string()
    |> provider_support.append_query_params(
      dict.to_list(config.extra_params(options)),
    )

  Ok(url)
}`;

export const packageToml = `name = "vestibule_twitch"
version = "0.1.0"
description = "Twitch OAuth strategy for Vestibule"
licences = ["MIT"]
gleam = ">= 1.7.0"

[dependencies]
vestibule = ">= 1.0.0 and < 2.0.0"
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_http = ">= 4.3.0 and < 5.0.0"
gleam_httpc = ">= 5.0.0 and < 6.0.0"
gleam_json = ">= 3.1.0 and < 4.0.0"
glow_auth = ">= 1.0.1 and < 2.0.0"`;

export const exchangeAndFetch = `fn do_exchange_code(
  cfg: ClientConfig,
  code: String,
  code_verifier: Option(String),
) -> Result(strategy.ExchangeResult, AuthError(e)) {
  // Build and send the provider token request, then parse credentials.
  use body <- result.try(post_token_request(cfg, code, code_verifier))
  provider_support.parse_oauth_token_response(
    body,
    provider_support.OptionalScope(" "),
  )
  |> result.map(strategy.exchange_result)
}

fn do_fetch_user(
  _cfg: ClientConfig,
  exchange: strategy.ExchangeResult,
) -> Result(strategy.UserResult, AuthError(e)) {
  use auth_header <- result.try(
    strategy.authorization_header(strategy.exchange_credentials(exchange)),
  )
  use #(uid, info) <- result.try(provider_support.fetch_json_with_auth(
    "https://id.twitch.tv/oauth2/userinfo",
    auth_header,
    parse_user_response,
    "Twitch userinfo",
  ))

  Ok(strategy.user_result(uid: uid, info: info, extra: dict.new()))
}`;

export const strategyValue = `pub fn strategy() -> Strategy(e) {
  strategy.new(provider: "twitch", default_scopes: ["user:read:email"])
  |> strategy.with_authorize_url(do_authorize_url)
  |> strategy.with_exchange_code(do_exchange_code)
  |> strategy.with_fetch_user(do_fetch_user)
  |> strategy.with_refresh(do_refresh_token)
}`;
