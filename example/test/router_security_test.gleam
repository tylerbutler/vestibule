import gleam/bit_array
import gleam/dict
import gleam/http
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option
import gleam/string
import vestibule/config
import vestibule/credential
import vestibule/registry
import vestibule/state_store
import vestibule/strategy.{type Strategy}
import vestibule/user_info
import vestibule_example/router.{Context}
import wisp
import wisp/simulate

const provider = "test"

pub fn landing_route_escapes_and_encodes_provider_test() -> Nil {
  let context =
    context_for(malicious_provider_strategy(), "example_landing_security")
  let response = router.handle_request(simulate.request(http.Get, "/"), context)
  let body = text_body(response)

  assert response.status == 200
  assert string.contains(body, "Not security-audited")
  assert string.contains(body, "Do not use this example in production")
  assert string.contains(
    body,
    "Sign in with &lt;script&gt;alert(1)&lt;/script&gt;",
  )
  assert string.contains(body, "/auth/%3Cscript%3Ealert(1)%3C%2Fscript%3E")
  assert !string.contains(body, "<script>alert(1)</script>")
}

pub fn authorization_route_uses_local_http_cookie_contract_test() -> Nil {
  let response =
    router.handle_request(
      insecure_localhost(simulate.request(http.Get, "/auth/test")),
      context_for(success_strategy(), "example_authorization_security"),
    )
  let assert Ok(set_cookie) = list.key_find(response.headers, "set-cookie")
  let assert Ok(location) = list.key_find(response.headers, "location")

  assert response.status >= 300 && response.status < 400
  assert string.starts_with(location, "https://provider.example/authorize?")
  assert string.contains(set_cookie, "vestibule_session=")
  assert string.contains(set_cookie, "HttpOnly")
  assert string.contains(set_cookie, "SameSite=Lax")
  assert string.contains(set_cookie, "Path=/")
  assert !string.contains(set_cookie, "__Host-")
  assert !string.contains(set_cookie, "Secure")
}

pub fn authorization_route_ignores_forwarded_client_headers_test() -> Nil {
  let context =
    context_for(success_strategy(), "example_direct_client_security")
  let responses =
    [1, 2, 3, 4, 5, 6, 7, 8, 9]
    |> list.map(fn(attempt) {
      let request =
        insecure_localhost(simulate.request(http.Get, "/auth/test"))
        |> simulate.header(
          "x-forwarded-for",
          "198.51.100." <> int.to_string(attempt),
        )
      router.handle_request_for_client(
        request,
        context,
        client_key: "192.0.2.10",
      )
    })

  let assert Ok(ninth) = list.last(responses)
  assert ninth.status == 429
}

pub fn callback_route_escapes_profile_and_hides_tokens_test() -> Nil {
  let context = context_for(success_strategy(), "example_callback_security")
  let start_request =
    insecure_localhost(simulate.request(http.Get, "/auth/test"))
  let start_response = router.handle_request(start_request, context)
  let assert Ok(set_cookie) =
    list.key_find(start_response.headers, "set-cookie")
  let assert Ok(#(cookie_pair, _)) = string.split_once(set_cookie, ";")
  let assert Ok(#(_, signed_session)) = string.split_once(cookie_pair, "=")
  let assert Ok(session_bits) =
    wisp.verify_signed_message(start_request, signed_session)
  let assert Ok(session_id) = bit_array.to_string(session_bits)
  let assert Ok(#(state, _, _)) =
    state_store.peek(context.state_store, session_id, provider: provider)

  let wrong_state_response =
    router.handle_request(
      insecure_localhost(simulate.request(
        http.Get,
        "/auth/test/callback?state=wrong&code=code",
      ))
        |> simulate.header("cookie", cookie_pair),
      context,
    )
  assert wrong_state_response.status == 400
  assert list.key_find(wrong_state_response.headers, "set-cookie") == Error(Nil)

  let callback =
    simulate.request(http.Post, "/auth/test/callback")
    |> simulate.form_body([#("state", state), #("code", "code")])
    |> insecure_localhost
    |> simulate.header("cookie", cookie_pair)
  let response = router.handle_request(callback, context)
  let body = text_body(response)
  let assert Ok(expired_cookie) = list.key_find(response.headers, "set-cookie")

  assert response.status == 200
  assert string.contains(expired_cookie, "vestibule_session=")
  assert string.contains(expired_cookie, "Max-Age=0")
  assert string.contains(body, "No application login session was created.")
  assert string.contains(body, "&lt;img src=x onerror=alert(1)&gt;")
  assert string.contains(body, "&lt;script&gt;alert(2)&lt;/script&gt;")
  assert string.contains(body, "https://images.example/avatar.png&quot;")
  assert !string.contains(body, "<script>")
  assert !string.contains(body, "access-token-secret")
  assert !string.contains(body, "refresh-token-secret")

  let replay_response = router.handle_request(callback, context)
  assert replay_response.status == 400
  assert string.contains(text_body(replay_response), "Authentication failed")
}

pub fn callback_routes_reject_missing_flow_without_reflection_test() -> Nil {
  let context =
    context_for(success_strategy(), "example_callback_rejection_security")
  let attacker = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

  let get_response =
    router.handle_request(
      simulate.request(http.Get, "/auth/" <> attacker <> "/callback"),
      context,
    )
  let post_response =
    router.handle_request(
      simulate.request(http.Post, "/auth/test/callback?state=x&code=y"),
      context,
    )

  assert get_response.status == 404
  assert !string.contains(text_body(get_response), "script")
  assert post_response.status == 400
  assert string.contains(text_body(post_response), "Authentication failed")
  assert !string.contains(text_body(post_response), "state=x")
}

pub fn unsupported_routes_do_not_create_oauth_state_test() -> Nil {
  let context =
    context_for(success_strategy(), "example_unsupported_route_security")
  let responses = [
    router.handle_request(simulate.request(http.Post, "/"), context),
    router.handle_request(simulate.request(http.Put, "/auth/test"), context),
    router.handle_request(
      simulate.request(http.Delete, "/auth/test/callback"),
      context,
    ),
    router.handle_request(simulate.request(http.Get, "/missing"), context),
  ]

  list.each(responses, fn(response) {
    assert response.status == 404
    assert list.key_find(response.headers, "set-cookie") == Error(Nil)
  })
}

fn context_for(
  strategy: Strategy(Nil),
  store_name: String,
) -> router.Context(Nil) {
  let assert Ok(store) = state_store.create_named(store_name)
  let assert Ok(provider_registry) =
    registry.new()
    |> registry.register(strategy: strategy, config: test_config())
  Context(registry: provider_registry, state_store: store)
}

fn success_strategy() -> Strategy(Nil) {
  strategy.new(
    provider: provider,
    default_scopes: [],
    authorize_url: fn(_config, _options, _scopes, state) {
      Ok("https://provider.example/authorize?state=" <> state)
    },
    exchange_code: fn(_config, _code, _verifier) {
      Ok(
        strategy.exchange_result(
          credential.new(
            token: "access-token-secret",
            refresh_token: option.Some("refresh-token-secret"),
            token_type: "Bearer",
            expires_in: option.Some(3600),
            scopes: [],
          ),
        ),
      )
    },
    fetch_user: fn(_config, _exchange) {
      let info =
        user_info.new()
        |> user_info.with_name(option.Some("<img src=x onerror=alert(1)>"))
        |> user_info.with_email(option.Some("<script>alert(2)</script>"))
        |> user_info.with_nickname(option.Some("\" onclick=\"alert(3)"))
        |> user_info.with_image(option.Some(
          "https://images.example/avatar.png\"><script>alert(4)</script>",
        ))
      Ok(strategy.user_result(
        uid: "<svg onload=alert(5)>",
        info: info,
        extra: dict.new(),
      ))
    },
  )
}

fn malicious_provider_strategy() -> Strategy(Nil) {
  strategy.new(
    provider: "<script>alert(1)</script>",
    default_scopes: [],
    authorize_url: fn(_config, _options, _scopes, _state) {
      Ok("https://provider.example")
    },
    exchange_code: fn(_config, _code, _verifier) { panic as "not used" },
    fetch_user: fn(_config, _exchange) { panic as "not used" },
  )
}

fn test_config() -> config.ClientConfig {
  config.new(
    client_id: "client-id",
    redirect_uri: "http://localhost:8000/auth/test/callback",
    auth: config.client_secret_auth("client-secret"),
  )
}

fn insecure_localhost(http_request: wisp.Request) -> wisp.Request {
  request.Request(..http_request, scheme: http.Http, host: "localhost")
}

fn text_body(response: wisp.Response) -> String {
  case response.body {
    wisp.Text(body) -> body
    wisp.Bytes(_) | wisp.File(_, _, _) -> panic as "expected text response"
  }
}
