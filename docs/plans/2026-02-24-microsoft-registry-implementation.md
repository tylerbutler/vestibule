# Microsoft Strategy, Provider Registry & Example App Updates — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Microsoft OAuth strategy, a provider registry for managing multiple strategies, and update the example app to support multiple providers with dynamic UI.

**Architecture:** Microsoft strategy follows the same pattern as GitHub (glow_auth for URL building, httpc for token exchange and user info). Provider registry wraps a Dict mapping provider names to Strategy+Config pairs. Example app uses the registry for dynamic provider rendering and graceful credential loading.

**Tech Stack:** Gleam 1.14+, glow_auth, gleam_httpc, gleam_json, gleam_crypto (SHA-256 for Gravatar), startest

**Design doc:** `docs/plans/2026-02-24-microsoft-registry-design.md`

---

### Task 1: Microsoft Strategy — Token Parsing

**Files:**
- Create: `test/vestibule/strategy/microsoft_test.gleam`
- Create: `src/vestibule/strategy/microsoft.gleam`

**Step 1: Write failing tests for token response parsing**

Create `test/vestibule/strategy/microsoft_test.gleam`:

```gleam
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule/strategy/microsoft

pub fn parse_token_response_success_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read profile openid email\",\"expires_in\":3736,\"ext_expires_in\":3736,\"access_token\":\"eyJ0eXAi_test_token\",\"refresh_token\":\"AwABAAAA_test_refresh\"}"
  let assert Ok(creds) = microsoft.parse_token_response(body)
  creds.token |> expect.to_equal("eyJ0eXAi_test_token")
  creds.token_type |> expect.to_equal("Bearer")
  creds.refresh_token |> expect.to_equal(Ok("AwABAAAA_test_refresh"))
  creds.expires_at |> expect.to_equal(Ok(3736))
  creds.scopes |> expect.to_equal(["User.Read", "profile", "openid", "email"])
}

pub fn parse_token_response_without_refresh_token_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read\",\"expires_in\":3600,\"access_token\":\"test_token\"}"
  let assert Ok(creds) = microsoft.parse_token_response(body)
  creds.token |> expect.to_equal("test_token")
  creds.refresh_token |> expect.to_be_error()
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS70000: The provided value for the input parameter 'code' is not valid.\"}"
  let result = microsoft.parse_token_response(body)
  result |> expect.to_be_error()
}
```

**Step 2: Run tests to verify they fail**

```bash
gleam test
```

Expected: Compilation error — `vestibule/strategy/microsoft` module not found.

**Step 3: Implement token parsing in microsoft.gleam**

Create `src/vestibule/strategy/microsoft.gleam`:

```gleam
import gleam/json
import gleam/json/decode
import gleam/option
import gleam/string
import vestibule/credentials.{Credentials}
import vestibule/error

/// Parse Microsoft token response JSON.
pub fn parse_token_response(
  body: String,
) -> Result(Credentials, error.AuthError) {
  // Try error response first
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.field("error_description", decode.string)
    decode.success(#(error_code, description))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description)) ->
      Error(error.ProviderError(code: code, description: description))
    _ -> parse_success_token(body)
  }
}

fn parse_success_token(body: String) -> Result(Credentials, error.AuthError) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use scope <- decode.field("scope", decode.string)
    use expires_in <- decode.optional_field(
      "expires_in",
      option.None,
      decode.optional(decode.int),
    )
    use refresh_token <- decode.optional_field(
      "refresh_token",
      option.None,
      decode.optional(decode.string),
    )
    decode.success(Credentials(
      token: access_token,
      refresh_token: option.to_result(refresh_token, Nil),
      token_type: token_type,
      expires_at: option.to_result(expires_in, Nil),
      scopes: string.split(scope, " "),
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse Microsoft token response",
      ))
  }
}
```

Note: Check if `Credentials.refresh_token` and `expires_at` use `Option` or `Result`. The GitHub strategy uses `Option(String)` and `Option(Int)`. Adjust field access in tests accordingly (e.g., `expect.to_equal(option.Some(...))` instead of `expect.to_equal(Ok(...))`). Verify by reading `src/vestibule/credentials.gleam`.

**Step 4: Run tests to verify they pass**

```bash
gleam test
```

Expected: All token parsing tests pass.

**Step 5: Commit**

```bash
git add src/vestibule/strategy/microsoft.gleam test/vestibule/strategy/microsoft_test.gleam
git commit -m "feat: add Microsoft strategy token response parsing"
```

---

### Task 2: Microsoft Strategy — User Info Parsing

**Files:**
- Modify: `test/vestibule/strategy/microsoft_test.gleam`
- Modify: `src/vestibule/strategy/microsoft.gleam`

**Step 1: Write failing tests for user info parsing**

Add to `test/vestibule/strategy/microsoft_test.gleam`:

```gleam
import gleam/dict
import gleam/option

pub fn parse_user_response_full_test() {
  let body =
    "{\"id\":\"87d349ed-44d7-43e1-9a83-5f2406dee5bd\",\"displayName\":\"Adele Vance\",\"mail\":\"AdeleV@contoso.com\",\"userPrincipalName\":\"AdeleV@contoso.com\",\"jobTitle\":\"Retail Manager\"}"
  let assert Ok(#(uid, info)) = microsoft.parse_user_response(body)
  uid |> expect.to_equal("87d349ed-44d7-43e1-9a83-5f2406dee5bd")
  info.name |> expect.to_equal(option.Some("Adele Vance"))
  info.email |> expect.to_equal(option.Some("AdeleV@contoso.com"))
  info.nickname |> expect.to_equal(option.Some("AdeleV@contoso.com"))
  info.description |> expect.to_equal(option.Some("Retail Manager"))
  // Gravatar URL from SHA-256 of lowercase email
  info.image |> expect.to_be_some()
}

pub fn parse_user_response_minimal_test() {
  let body =
    "{\"id\":\"abc-123\",\"userPrincipalName\":\"user@example.com\"}"
  let assert Ok(#(uid, info)) = microsoft.parse_user_response(body)
  uid |> expect.to_equal("abc-123")
  info.name |> expect.to_equal(option.None)
  info.email |> expect.to_equal(option.Some("user@example.com"))
  info.nickname |> expect.to_equal(option.Some("user@example.com"))
  info.description |> expect.to_equal(option.None)
}

pub fn parse_user_response_mail_preferred_over_upn_test() {
  let body =
    "{\"id\":\"abc\",\"mail\":\"real@example.com\",\"userPrincipalName\":\"upn@example.com\"}"
  let assert Ok(#(_uid, info)) = microsoft.parse_user_response(body)
  info.email |> expect.to_equal(option.Some("real@example.com"))
}
```

**Step 2: Run tests to verify they fail**

```bash
gleam test
```

Expected: Compilation error — `parse_user_response` not found.

**Step 3: Implement user info parsing**

Add to `src/vestibule/strategy/microsoft.gleam`:

```gleam
import gleam/bit_array
import gleam/crypto
import gleam/dict
import gleam/option.{type Option, None, Some}
import vestibule/user_info

/// Parse Microsoft Graph /me response JSON.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, user_info.UserInfo), error.AuthError) {
  let decoder = {
    use id <- decode.field("id", decode.string)
    use display_name <- decode.optional_field(
      "displayName",
      None,
      decode.optional(decode.string),
    )
    use mail <- decode.optional_field(
      "mail",
      None,
      decode.optional(decode.string),
    )
    use upn <- decode.field("userPrincipalName", decode.string)
    use job_title <- decode.optional_field(
      "jobTitle",
      None,
      decode.optional(decode.string),
    )
    let email = case mail {
      Some(_) -> mail
      None -> Some(upn)
    }
    let image = case email {
      Some(addr) -> Some(gravatar_url(addr))
      None -> None
    }
    decode.success(#(
      id,
      user_info.UserInfo(
        name: display_name,
        email: email,
        nickname: Some(upn),
        image: image,
        description: job_title,
        urls: dict.new(),
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    _ ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse Microsoft user response",
      ))
  }
}

fn gravatar_url(email: String) -> String {
  let hash =
    email
    |> string.lowercase
    |> string.trim
    |> fn(e) { <<e:utf8>> }
    |> crypto.hash(crypto.Sha256, _)
    |> hex_encode
  "https://www.gravatar.com/avatar/" <> hash <> "?d=identicon"
}

fn hex_encode(bytes: BitArray) -> String {
  bytes
  |> bit_array.base16_encode
  |> string.lowercase
}
```

Note: Check if `bit_array.base16_encode` exists in `gleam_stdlib`. If not, use `crypto` or a manual hex encoder. Also verify `string.trim` exists. Adjust as needed during implementation.

**Step 4: Run tests to verify they pass**

```bash
gleam test
```

Expected: All user info tests pass.

**Step 5: Commit**

```bash
git add src/vestibule/strategy/microsoft.gleam test/vestibule/strategy/microsoft_test.gleam
git commit -m "feat: add Microsoft strategy user info parsing with Gravatar fallback"
```

---

### Task 3: Microsoft Strategy — Full Strategy Wiring

**Files:**
- Modify: `src/vestibule/strategy/microsoft.gleam`

**Step 1: Implement the strategy() function and OAuth flow functions**

Add to `src/vestibule/strategy/microsoft.gleam`:

```gleam
import gleam/http/request
import gleam/httpc
import gleam/uri
import glow_auth
import glow_auth/authorize_uri
import glow_auth/token_request
import glow_auth/uri_builder
import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/strategy.{type Strategy, Strategy}

/// Create a Microsoft authentication strategy using /common tenant.
pub fn strategy() -> Strategy {
  Strategy(
    provider: "microsoft",
    default_scopes: ["User.Read"],
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
}

fn do_authorize_url(
  config: Config,
  scopes: List(String),
  state: String,
) -> Result(String, error.AuthError) {
  let assert Ok(site) =
    uri.parse("https://login.microsoftonline.com/common/oauth2/v2.0")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
      site: site,
    )
  authorize_uri.build(
    client,
    uri_builder.RelativePath("/authorize"),
    redirect,
  )
  |> authorize_uri.set_scope(string.join(scopes, " "))
  |> authorize_uri.set_state(state)
  |> authorize_uri.to_code_authorization_uri()
  |> uri.to_string()
  |> Ok
}

fn do_exchange_code(
  config: Config,
  code: String,
) -> Result(Credentials, error.AuthError) {
  let assert Ok(site) =
    uri.parse("https://login.microsoftonline.com/common/oauth2/v2.0")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
      site: site,
    )
  let req =
    token_request.authorization_code(
      client,
      uri_builder.RelativePath("/token"),
      code,
      redirect,
    )
    |> request.set_header("accept", "application/json")
  case httpc.send(req) {
    Ok(response) -> parse_token_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Microsoft token endpoint",
      ))
  }
}

fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, user_info.UserInfo), error.AuthError) {
  let assert Ok(user_req) = request.to("https://graph.microsoft.com/v1.0/me")
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
  case httpc.send(user_req) {
    Ok(response) -> parse_user_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Microsoft Graph API",
      ))
  }
}
```

Note: The `glow_auth` site URL for Microsoft uses a path-based endpoint structure. The authorize URL is `{site}/authorize` and token URL is `{site}/token`. If `glow_auth` doesn't handle this correctly (e.g., path concatenation issues), you may need to use a different site base URL and adjust the relative paths. Verify during implementation.

**Step 2: Verify compilation**

```bash
gleam build
```

Expected: Compiles with no errors.

**Step 3: Commit**

```bash
git add src/vestibule/strategy/microsoft.gleam
git commit -m "feat: wire up Microsoft strategy with glow_auth OAuth flow"
```

---

### Task 4: Provider Registry

**Files:**
- Create: `test/vestibule/registry_test.gleam`
- Create: `src/vestibule/registry.gleam`

**Step 1: Write failing tests**

Create `test/vestibule/registry_test.gleam`:

```gleam
import startest/expect
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule/error
import vestibule/registry
import vestibule/strategy.{Strategy}
import vestibule/user_info

fn test_strategy(name: String) -> Strategy {
  Strategy(
    provider: name,
    default_scopes: [],
    authorize_url: fn(_config, _scopes, _state) { Ok("https://example.com") },
    exchange_code: fn(_config, _code) {
      Error(error.ConfigError(reason: "test"))
    },
    fetch_user: fn(_creds) { Error(error.ConfigError(reason: "test")) },
  )
}

fn test_config() -> config.Config {
  config.new("client_id", "client_secret", "https://example.com/callback")
}

pub fn new_registry_has_no_providers_test() {
  let reg = registry.new()
  registry.providers(reg)
  |> expect.to_equal([])
}

pub fn register_and_get_provider_test() {
  let strategy = test_strategy("github")
  let cfg = test_config()
  let reg =
    registry.new()
    |> registry.register(strategy, cfg)
  let assert Ok(#(s, _c)) = registry.get(reg, "github")
  s.provider |> expect.to_equal("github")
}

pub fn get_unknown_provider_returns_error_test() {
  let reg = registry.new()
  registry.get(reg, "unknown")
  |> expect.to_be_error()
}

pub fn providers_returns_registered_names_test() {
  let reg =
    registry.new()
    |> registry.register(test_strategy("github"), test_config())
    |> registry.register(test_strategy("microsoft"), test_config())
  let names = registry.providers(reg)
  names |> list.contains("github") |> expect.to_be_true()
  names |> list.contains("microsoft") |> expect.to_be_true()
  names |> list.length |> expect.to_equal(2)
}
```

**Step 2: Run tests to verify they fail**

```bash
gleam test
```

Expected: Compilation error — `vestibule/registry` module not found.

**Step 3: Implement registry.gleam**

Create `src/vestibule/registry.gleam`:

```gleam
import gleam/dict.{type Dict}
import vestibule/config.{type Config}
import vestibule/strategy.{type Strategy}

/// A registry mapping provider names to Strategy + Config pairs.
pub opaque type Registry {
  Registry(providers: Dict(String, #(Strategy, Config)))
}

/// Create an empty registry.
pub fn new() -> Registry {
  Registry(providers: dict.new())
}

/// Register a strategy with its config. Provider name is taken from the strategy.
pub fn register(
  registry: Registry,
  strategy: Strategy,
  config: Config,
) -> Registry {
  Registry(
    providers: dict.insert(
      registry.providers,
      strategy.provider,
      #(strategy, config),
    ),
  )
}

/// Look up a provider by name.
pub fn get(
  registry: Registry,
  provider: String,
) -> Result(#(Strategy, Config), Nil) {
  dict.get(registry.providers, provider)
}

/// List all registered provider names.
pub fn providers(registry: Registry) -> List(String) {
  dict.keys(registry.providers)
}
```

**Step 4: Run tests to verify they pass**

```bash
gleam test
```

Expected: All registry tests pass.

**Step 5: Commit**

```bash
git add src/vestibule/registry.gleam test/vestibule/registry_test.gleam
git commit -m "feat: add provider registry for managing multiple strategies"
```

---

### Task 5: Update Example App — Multi-Provider Support

**Files:**
- Modify: `example/gleam.toml` (if needed — vestibule path dep already covers new modules)
- Modify: `example/src/vestibule_example.gleam`
- Modify: `example/src/router.gleam`
- Modify: `example/src/pages.gleam`
- Modify: `example/.env.example`

**Step 1: Update vestibule_example.gleam with graceful credential loading**

Replace `example/src/vestibule_example.gleam`:

```gleam
import envoy
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/result
import mist
import wisp
import wisp/wisp_mist

import router.{Context}
import session
import vestibule/config
import vestibule/registry
import vestibule/strategy/github
import vestibule/strategy/microsoft

pub fn main() {
  let port =
    envoy.get("PORT")
    |> result.try(int.parse)
    |> result.unwrap(8000)
  let secret_key_base =
    envoy.get("SECRET_KEY_BASE")
    |> result.unwrap(
      "development-secret-key-base-change-in-production-please",
    )
  let callback_base = "http://localhost:" <> int.to_string(port)

  // Build registry with available providers
  let reg = registry.new()

  let reg = case envoy.get("GITHUB_CLIENT_ID"), envoy.get("GITHUB_CLIENT_SECRET") {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: github")
      registry.register(
        reg,
        github.strategy(),
        config.new(id, secret, callback_base <> "/auth/github/callback"),
      )
    }
    _, _ -> reg
  }

  let reg = case envoy.get("MICROSOFT_CLIENT_ID"), envoy.get("MICROSOFT_CLIENT_SECRET") {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: microsoft")
      registry.register(
        reg,
        microsoft.strategy(),
        config.new(id, secret, callback_base <> "/auth/microsoft/callback"),
      )
    }
    _, _ -> reg
  }

  // Require at least one provider
  case registry.providers(reg) {
    [] -> {
      io.println("Error: No OAuth providers configured.")
      io.println("Set GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET and/or")
      io.println("MICROSOFT_CLIENT_ID + MICROSOFT_CLIENT_SECRET in your .env file.")
      panic as "No providers configured"
    }
    _ -> Nil
  }

  let ctx = Context(registry: reg)

  // Initialize session store
  session.create_table()

  // Configure Wisp logging
  wisp.configure_logger()

  // Start the server
  let handler = fn(req) { router.handle_request(req, ctx) }
  let assert Ok(_) =
    handler
    |> wisp_mist.handler(secret_key_base)
    |> mist.new
    |> mist.port(port)
    |> mist.start

  io.println(
    "Vestibule demo running on http://localhost:" <> int.to_string(port),
  )

  process.sleep_forever()
}
```

**Step 2: Update router.gleam with parameterized provider routes**

Replace `example/src/router.gleam`:

```gleam
import gleam/dict
import gleam/http
import wisp.{type Request, type Response}

import pages
import session
import vestibule
import vestibule/error
import vestibule/registry.{type Registry}

/// Application context passed to the router.
pub type Context {
  Context(registry: Registry)
}

/// Route incoming requests.
pub fn handle_request(req: Request, ctx: Context) -> Response {
  use <- wisp.log_request(req)

  case wisp.path_segments(req), req.method {
    // Landing page
    [], http.Get -> pages.landing(registry.providers(ctx.registry))

    // Phase 1: Redirect to provider
    ["auth", provider], http.Get -> begin_auth(req, ctx, provider)

    // Phase 2: Handle callback
    ["auth", provider, "callback"], http.Get ->
      handle_callback(req, ctx, provider)

    // Everything else
    _, _ -> wisp.not_found()
  }
}

fn begin_auth(req: Request, ctx: Context, provider: String) -> Response {
  case registry.get(ctx.registry, provider) {
    Error(Nil) -> wisp.not_found()
    Ok(#(strategy, config)) ->
      case vestibule.authorize_url(strategy, config) {
        Ok(#(url, state)) -> {
          let session_id = session.store_state(state)
          wisp.redirect(url)
          |> wisp.set_cookie(
            req,
            "vestibule_session",
            session_id,
            wisp.Signed,
            600,
          )
        }
        Error(err) -> pages.error(err)
      }
  }
}

fn handle_callback(req: Request, ctx: Context, provider: String) -> Response {
  case registry.get(ctx.registry, provider) {
    Error(Nil) -> wisp.not_found()
    Ok(#(strategy, config)) -> {
      let session_result =
        wisp.get_cookie(req, "vestibule_session", wisp.Signed)
      case session_result {
        Error(Nil) ->
          pages.error(error.ConfigError(reason: "Missing session cookie"))
        Ok(session_id) ->
          case session.get_state(session_id) {
            Error(Nil) ->
              pages.error(error.ConfigError(
                reason: "Session expired or already used",
              ))
            Ok(expected_state) -> {
              let params =
                wisp.get_query(req)
                |> dict.from_list()
              case
                vestibule.handle_callback(
                  strategy,
                  config,
                  params,
                  expected_state,
                )
              {
                Ok(auth) -> pages.success(auth)
                Error(err) -> pages.error(err)
              }
            }
          }
      }
    }
  }
}
```

**Step 3: Update pages.gleam with dynamic landing page**

Modify `example/src/pages.gleam` — change `landing()` to accept provider list:

```gleam
import gleam/list
import gleam/string

/// Landing page with dynamic provider buttons.
pub fn landing(providers: List(String)) -> wisp.Response {
  let buttons =
    providers
    |> list.map(fn(provider) {
      "<a href=\"/auth/"
      <> provider
      <> "\"\n     style=\"display: inline-block; padding: 12px 24px; background: #24292e; color: white; text-decoration: none; border-radius: 6px; font-size: 16px; margin: 8px;\">\n    Sign in with "
      <> capitalize(provider)
      <> "\n  </a>"
    })
    |> string.join("\n  ")
  wisp.html_response(
    "<html>
<head><title>Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center;\">
  <h1>Vestibule Demo</h1>
  <p>OAuth2 authentication library for Gleam</p>
  " <> buttons <> "
</body>
</html>",
    200,
  )
}

fn capitalize(s: String) -> String {
  case string.pop_grapheme(s) {
    Ok(#(first, rest)) -> string.uppercase(first) <> rest
    Error(Nil) -> s
  }
}
```

Note: Keep `success()` and `error()` functions unchanged. Only `landing()` changes signature.

**Step 4: Update .env.example**

Replace `example/.env.example`:

```
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
# PORT=8000
# SECRET_KEY_BASE=your_secret_key_base
```

**Step 5: Verify compilation**

```bash
cd example && gleam build
```

Expected: Compiles with no errors.

**Step 6: Run example tests**

```bash
cd example && gleam test
```

Expected: All session tests still pass (3/3).

**Step 7: Commit**

```bash
git add example/src/ example/.env.example
git commit -m "feat(example): update example app for multi-provider support

Dynamic landing page renders buttons per registered provider.
Graceful credential loading — only registers providers with env vars set.
Routes parameterized by provider name via registry lookup."
```

---

### Task 6: Verification and Cleanup

**Files:** None — verification only.

**Step 1: Run full test suite from repo root**

```bash
gleam check
gleam format src test
gleam build
gleam test
```

Expected: All checks pass, all tests pass.

**Step 2: Run example verification**

```bash
cd example
gleam check
gleam format src test
gleam build
gleam test
```

Expected: All checks pass.

**Step 3: Commit any formatting changes**

```bash
git add -A
git commit -m "style: apply gleam format"
```

(Only if there are formatting changes.)

---

## Summary of Commits

| # | Message | What |
|---|---------|------|
| 1 | `feat: add Microsoft strategy token response parsing` | Token parsing + tests |
| 2 | `feat: add Microsoft strategy user info parsing with Gravatar fallback` | User info parsing + Gravatar + tests |
| 3 | `feat: wire up Microsoft strategy with glow_auth OAuth flow` | Full strategy wiring |
| 4 | `feat: add provider registry for managing multiple strategies` | Registry + tests |
| 5 | `feat(example): update example app for multi-provider support` | Multi-provider example |
| 6 | `style: apply gleam format` | If needed |
