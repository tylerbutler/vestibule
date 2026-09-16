import gleam/bit_array
import gleam/dict
import gleam/dynamic
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/uri
import vestibule
import vestibule/auth
import vestibule/authorization_request
import vestibule/config
import vestibule/credential
import vestibule/error
import vestibule/pkce
import vestibule/registry
import vestibule/state_store
import vestibule/strategy
import vestibule/transport_flow
import vestibule/user_info

const redirect_uri = "https://app.example/callback?x=%2f&y=%2F"

fn client_config() -> config.ClientConfig {
  config.new(
    client_id: "protocol-client",
    auth: config.public_client(),
    redirect_uri: redirect_uri,
  )
}

// The fake authorization server binds each code to its S256 challenge and
// exact redirect URI. It does not accept a code from a different flow.
fn bound_strategy() -> strategy.Strategy(Nil) {
  strategy.new(
    provider: "protocol",
    default_scopes: ["profile"],
    authorize_url: fn(client, _options, scopes, state) {
      Ok(
        "https://issuer.example/authorize?"
        <> uri.query_to_string([
          #("state", state),
          #("redirect_uri", config.redirect_uri(client)),
          #("scope", string.join(scopes, " ")),
        ]),
      )
    },
    exchange_code: fn(client, code, verifier) {
      case verifier {
        Some(value) -> {
          let expected =
            pkce.compute_challenge(value) <> ":" <> config.redirect_uri(client)
          case code == expected {
            True ->
              Ok(
                strategy.exchange_result(
                  credential.new(
                    token: "test-access-token",
                    refresh_token: None,
                    token_type: "Bearer",
                    expires_in: None,
                    scopes: ["profile"],
                  ),
                ),
              )
            False -> Error(error.code_exchange(reason: "Code binding failed"))
          }
        }
        None -> Error(error.code_exchange(reason: "PKCE is required"))
      }
    },
    fetch_user: fn(_client, _exchange) {
      Ok(strategy.user_result(
        uid: "subject",
        info: user_info.new(),
        extra: dict.new(),
      ))
    },
  )
}

fn start(store: state_store.StateStore) -> #(String, String, String) {
  let assert Ok(providers) =
    registry.new()
    |> registry.register(strategy: bound_strategy(), config: client_config())
  let assert Ok(#(url, session)) =
    transport_flow.start_authorization(
      providers,
      provider: "protocol",
      store: store,
      ttl_seconds: 600,
      options: config.authorize_options(),
    )
  let assert Ok(parsed) = uri.parse(url)
  let assert Some(query) = parsed.query
  let assert Ok(parameters) = uri.parse_query(query)
  let parameters = dict.from_list(parameters)
  let assert Ok(state) = dict.get(parameters, "state")
  let assert Ok(challenge) = dict.get(parameters, "code_challenge")
  assert dict.get(parameters, "code_challenge_method") == Ok("S256")
  assert dict.get(parameters, "redirect_uri") == Ok(redirect_uri)
  #(session, state, challenge <> ":" <> redirect_uri)
}

fn finish(
  store: state_store.StateStore,
  session: String,
  state: String,
  code: String,
) -> Result(auth.Auth, transport_flow.CallbackFlowError(Nil)) {
  transport_flow.finish_callback(
    #(bound_strategy(), client_config()),
    store: store,
    parameters: dict.from_list([#("state", state), #("code", code)]),
    session_id: session,
  )
}

pub fn code_injection_consumes_flow_without_returning_identity_test() -> Nil {
  let assert Ok(store) = state_store.create_named("protocol_code_injection")
  let #(session, state, code) = start(store)
  let #(other_session, other_state, other_code) = start(store)

  let assert Error(transport_flow.CallbackAuthFailed(failure)) =
    finish(store, session, state, other_code)
  assert error.kind(failure) == error.CodeExchangeKind
  assert finish(store, session, state, code)
    == Error(transport_flow.CallbackSessionUnavailable)
  let assert Ok(identity) =
    finish(store, other_session, other_state, other_code)
  assert auth.uid(identity) == "subject"
  assert finish(store, other_session, other_state, other_code)
    == Error(transport_flow.CallbackSessionUnavailable)
}

pub fn mixed_error_and_code_never_returns_identity_test() -> Nil {
  let assert Ok(store) = state_store.create_named("protocol_mixed_error")
  let #(session, state, code) = start(store)
  let assert Error(transport_flow.CallbackAuthFailed(failure)) =
    transport_flow.finish_callback(
      #(bound_strategy(), client_config()),
      store: store,
      parameters: dict.from_list([
        #("state", state),
        #("code", code),
        #("error", "access_denied"),
      ]),
      session_id: session,
    )
  assert error.kind(failure) == error.ProviderKind
  assert finish(store, session, state, code)
    == Error(transport_flow.CallbackSessionUnavailable)
}

pub fn wrong_state_does_not_consume_legitimate_flow_test() -> Nil {
  let assert Ok(store) = state_store.create_named("protocol_wrong_state")
  let #(session, state, code) = start(store)
  let assert Error(transport_flow.CallbackAuthFailed(failure)) =
    finish(store, session, "attacker-state", code)
  assert error.kind(failure) == error.StateMismatchKind
  let assert Ok(identity) = finish(store, session, state, code)
  assert auth.uid(identity) == "subject"
}

pub fn callback_rejects_missing_and_substituted_verifier_test() -> Nil {
  let assert Ok(flow) =
    vestibule.create_authorization_request(
      bound_strategy(),
      config: client_config(),
      options: config.authorize_options(),
    )
  let state = authorization_request.state(flow)
  let verifier = authorization_request.code_verifier(flow)
  let code = pkce.compute_challenge(verifier) <> ":" <> redirect_uri
  list.each(["", " ", pkce.generate_verifier()], fn(invalid_verifier) {
    let assert Error(failure) =
      vestibule.handle_callback(
        bound_strategy(),
        config: client_config(),
        callback_params: dict.from_list([#("state", state), #("code", code)]),
        expected_state: state,
        code_verifier: invalid_verifier,
        expected_nonce: None,
      )
    assert error.kind(failure) == error.CodeExchangeKind
  })
}

pub fn callback_rejects_empty_code_before_exchange_test() -> Nil {
  list.each(["", " \t"], fn(code) {
    let assert Error(failure) =
      vestibule.handle_callback(
        bound_strategy(),
        config: client_config(),
        callback_params: dict.from_list([#("state", "state"), #("code", code)]),
        expected_state: "state",
        code_verifier: pkce.generate_verifier(),
        expected_nonce: None,
      )
    assert error.kind(failure) == error.MissingCallbackParamKind
  })
}

pub fn reserved_parameters_cannot_replace_protocol_bindings_test() -> Nil {
  list.each(
    [
      "state", "nonce", "code_challenge", "code_challenge_method",
      "redirect_uri", "client_id", "response_type", "response_mode", "scope",
    ],
    fn(parameter) {
      let assert Error(failure) =
        config.authorize_options()
        |> config.with_extra_params([#(parameter, "attacker-value")])
      assert error.kind(failure) == error.ConfigKind
    },
  )
}

pub fn changed_redirect_uri_cannot_exchange_authorization_code_test() -> Nil {
  let assert Ok(flow) =
    vestibule.create_authorization_request(
      bound_strategy(),
      config: client_config(),
      options: config.authorize_options(),
    )
  let state = authorization_request.state(flow)
  let verifier = authorization_request.code_verifier(flow)
  let code = pkce.compute_challenge(verifier) <> ":" <> redirect_uri
  let altered_config =
    config.new(
      client_id: "protocol-client",
      auth: config.public_client(),
      redirect_uri: "https://app.example/callback?x=%2F&y=%2F",
    )
  let assert Error(failure) =
    vestibule.handle_callback(
      bound_strategy(),
      config: altered_config,
      callback_params: dict.from_list([#("state", state), #("code", code)]),
      expected_state: state,
      code_verifier: verifier,
      expected_nonce: None,
    )
  assert error.kind(failure) == error.CodeExchangeKind
}

pub fn requested_scopes_do_not_become_granted_scopes_test() -> Nil {
  list.each([[], ["email", "admin"]], fn(scopes) {
    let assert Ok(flow) =
      vestibule.create_authorization_request(
        bound_strategy(),
        config: client_config(),
        options: config.authorize_options() |> config.with_scopes(scopes),
      )
    let assert Ok(parsed) = uri.parse(authorization_request.url(flow))
    let assert Some(query) = parsed.query
    let assert Ok(parameters) = uri.parse_query(query)
    let expected_scopes = case scopes {
      [] -> "profile"
      _ -> "email admin"
    }
    assert dict.get(dict.from_list(parameters), "scope") == Ok(expected_scopes)
    let state = authorization_request.state(flow)
    let verifier = authorization_request.code_verifier(flow)
    let code = pkce.compute_challenge(verifier) <> ":" <> redirect_uri
    let assert Ok(identity) =
      vestibule.handle_callback(
        bound_strategy(),
        config: client_config(),
        callback_params: dict.from_list([#("state", state), #("code", code)]),
        expected_state: state,
        code_verifier: verifier,
        expected_nonce: None,
      )
    assert credential.scopes(auth.credentials(identity)) == ["profile"]
  })
}

pub fn nonce_substitution_rejects_callback_and_consumes_flow_test() -> Nil {
  // This strategy isolates core nonce binding. Signature verification is
  // covered by signed fixtures in the provider tests.
  let provider =
    strategy.new(
      provider: "nonce-protocol",
      default_scopes: ["openid"],
      authorize_url: fn(_config, _options, _scopes, state) {
        Ok("https://issuer.example/authorize?state=" <> state)
      },
      exchange_code: fn(_config, token, _verifier) {
        Ok(strategy.exchange_result_with_artifacts(
          credential.new(
            token: "test-access-token",
            refresh_token: None,
            token_type: "Bearer",
            expires_in: None,
            scopes: ["openid"],
          ),
          dict.from_list([#("id_token", dynamic.string(token))]),
        ))
      },
      fetch_user: fn(_config, _exchange) {
        panic as "A token from another flow must not reach user lookup"
      },
    )
    |> strategy.with_nonce()
  let assert Ok(providers) =
    registry.new()
    |> registry.register(strategy: provider, config: client_config())
  let assert Ok(store) = state_store.create_named("protocol_nonce_substitution")
  let assert Ok(#(_url, session)) =
    transport_flow.start_authorization(
      providers,
      provider: "nonce-protocol",
      store: store,
      ttl_seconds: 600,
      options: config.authorize_options(),
    )
  let assert Ok(other_flow) =
    vestibule.create_authorization_request(
      provider,
      config: client_config(),
      options: config.authorize_options(),
    )
  let assert Some(other_nonce) = authorization_request.nonce(other_flow)
  let payload = "{\"sub\":\"subject\",\"nonce\":\"" <> other_nonce <> "\"}"
  let token =
    "header."
    <> bit_array.base64_url_encode(<<payload:utf8>>, False)
    <> ".signature"
  let assert Ok(#(state, _verifier, Some(expected_nonce))) =
    state_store.peek(store, session, provider: "nonce-protocol")
  assert expected_nonce != other_nonce
  let parameters = dict.from_list([#("state", state), #("code", token)])
  let assert Error(transport_flow.CallbackAuthFailed(failure)) =
    transport_flow.finish_callback(
      #(provider, client_config()),
      store: store,
      parameters: parameters,
      session_id: session,
    )
  assert error.kind(failure) == error.InvalidNonceKind
  assert state_store.peek(store, session, provider: "nonce-protocol")
    == Error(Nil)
}

pub fn callback_issuer_is_required_and_compared_exactly_test() -> Nil {
  let provider =
    bound_strategy()
    |> strategy.with_callback_issuer("https://issuer.example/tenant")
  let assert Ok(flow) =
    vestibule.create_authorization_request(
      provider,
      config: client_config(),
      options: config.authorize_options(),
    )
  let state = authorization_request.state(flow)
  let verifier = authorization_request.code_verifier(flow)
  let code = pkce.compute_challenge(verifier) <> ":" <> redirect_uri
  let parameters = dict.from_list([#("state", state), #("code", code)])
  list.each(
    [
      parameters,
      dict.insert(parameters, "iss", ""),
      dict.insert(parameters, "iss", "https://issuer.example/other"),
      dict.insert(parameters, "iss", "https://issuer.example/tenant/"),
      dict.insert(parameters, "iss", "https://attacker.example/tenant"),
    ],
    fn(untrusted_parameters) {
      let assert Error(failure) =
        vestibule.handle_callback(
          provider,
          config: client_config(),
          callback_params: untrusted_parameters,
          expected_state: state,
          code_verifier: verifier,
          expected_nonce: None,
        )
      assert error.kind(failure) == error.CodeExchangeKind
    },
  )
  let assert Ok(identity) =
    vestibule.handle_callback(
      provider,
      config: client_config(),
      callback_params: dict.insert(
        parameters,
        "iss",
        "https://issuer.example/tenant",
      ),
      expected_state: state,
      code_verifier: verifier,
      expected_nonce: None,
    )
  assert auth.uid(identity) == "subject"
}
