# Phase 1: Core + GitHub Strategy Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build vestibule's core types, CSRF state management, strategy interface, and GitHub provider strategy.

**Architecture:** Types-first bottom-up. Pure type modules first, then state management with crypto, then the GitHub strategy with HTTP/JSON, then the top-level orchestrator. TDD throughout — write failing tests, implement, commit.

**Tech Stack:** Gleam 1.14+, glow_auth 1.0.1, gleam_httpc 5.0.0, gleam_json 3.1.0, gleam_crypto 1.5.1, gleeunit

**Design doc:** `docs/plans/2026-02-24-phase1-core-github-design.md`

---

### Task 1: Add Dependencies

**Files:**
- Modify: `gleam.toml`

**Step 1: Update gleam.toml dependencies**

Replace the `[dependencies]` section with:

```toml
[dependencies]
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_crypto = ">= 1.5.0 and < 2.0.0"
gleam_http = ">= 4.3.0 and < 5.0.0"
gleam_httpc = ">= 5.0.0 and < 6.0.0"
gleam_json = ">= 3.1.0 and < 4.0.0"
glow_auth = ">= 1.0.1 and < 2.0.0"
```

**Step 2: Download deps and verify compilation**

Run: `gleam build`
Expected: Downloads all packages, compiles successfully

**Step 3: Commit**

```bash
git add gleam.toml manifest.toml
git commit -m "feat: add OAuth2 and HTTP dependencies for Phase 1"
```

---

### Task 2: Core Type Modules (error, user_info, credentials)

**Files:**
- Create: `src/vestibule/error.gleam`
- Create: `src/vestibule/user_info.gleam`
- Create: `src/vestibule/credentials.gleam`

These are pure data types with no logic to test. We verify they compile and are usable.

**Step 1: Create error.gleam**

```gleam
/// Authentication error types.
pub type AuthError {
  /// State parameter mismatch — possible CSRF attack.
  StateMismatch
  /// Failed to exchange authorization code for tokens.
  CodeExchangeFailed(reason: String)
  /// Failed to fetch user info from provider.
  UserInfoFailed(reason: String)
  /// Provider returned an error response.
  ProviderError(code: String, description: String)
  /// HTTP request failed.
  NetworkError(reason: String)
  /// Invalid configuration.
  ConfigError(reason: String)
}
```

**Step 2: Create user_info.gleam**

```gleam
import gleam/dict.{type Dict}
import gleam/option.{type Option}

/// Normalized user information across all providers.
pub type UserInfo {
  UserInfo(
    name: Option(String),
    email: Option(String),
    nickname: Option(String),
    image: Option(String),
    description: Option(String),
    urls: Dict(String, String),
  )
}
```

**Step 3: Create credentials.gleam**

```gleam
import gleam/option.{type Option}

/// OAuth credentials from the provider.
pub type Credentials {
  Credentials(
    token: String,
    refresh_token: Option(String),
    token_type: String,
    expires_at: Option(Int),
    scopes: List(String),
  )
}
```

**Step 4: Verify compilation**

Run: `gleam build`
Expected: Compiles with no errors

**Step 5: Commit**

```bash
git add src/vestibule/error.gleam src/vestibule/user_info.gleam src/vestibule/credentials.gleam
git commit -m "feat: add core types — AuthError, UserInfo, Credentials"
```

---

### Task 3: Config Module with Tests

**Files:**
- Create: `src/vestibule/config.gleam`
- Create: `test/vestibule/config_test.gleam`

**Step 1: Write failing tests**

Create `test/vestibule/config_test.gleam`:

```gleam
import gleam/dict
import gleeunit/should
import vestibule/config

pub fn new_creates_config_with_empty_defaults_test() {
  let c = config.new("id", "secret", "http://localhost/callback")
  c.client_id |> should.equal("id")
  c.client_secret |> should.equal("secret")
  c.redirect_uri |> should.equal("http://localhost/callback")
  c.scopes |> should.equal([])
  c.extra_params |> should.equal(dict.new())
}

pub fn with_scopes_replaces_scopes_test() {
  let c =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_scopes(["user:email", "read:org"])
  c.scopes |> should.equal(["user:email", "read:org"])
}

pub fn with_extra_params_adds_params_test() {
  let c =
    config.new("id", "secret", "http://localhost/callback")
    |> config.with_extra_params([#("allow_signup", "false")])
  c.extra_params |> should.equal(dict.from_list([#("allow_signup", "false")]))
}
```

**Step 2: Run tests to verify they fail**

Run: `gleam test`
Expected: Compilation error — `config` module not found

**Step 3: Implement config.gleam**

```gleam
import gleam/dict.{type Dict}

/// Provider configuration.
pub type Config {
  Config(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: List(String),
    extra_params: Dict(String, String),
  )
}

/// Create a new config with the required fields and empty defaults.
pub fn new(
  client_id: String,
  client_secret: String,
  redirect_uri: String,
) -> Config {
  Config(
    client_id: client_id,
    client_secret: client_secret,
    redirect_uri: redirect_uri,
    scopes: [],
    extra_params: dict.new(),
  )
}

/// Set custom scopes, replacing any defaults.
pub fn with_scopes(config: Config, scopes: List(String)) -> Config {
  Config(..config, scopes: scopes)
}

/// Add extra query parameters to the authorization URL.
pub fn with_extra_params(
  config: Config,
  params: List(#(String, String)),
) -> Config {
  Config(..config, extra_params: dict.from_list(params))
}
```

**Step 4: Run tests to verify they pass**

Run: `gleam test`
Expected: All config tests pass

**Step 5: Commit**

```bash
git add src/vestibule/config.gleam test/vestibule/config_test.gleam
git commit -m "feat: add Config type with builder functions and tests"
```

---

### Task 4: Auth and Strategy Type Modules

**Files:**
- Create: `src/vestibule/auth.gleam`
- Create: `src/vestibule/strategy.gleam`

**Step 1: Create auth.gleam**

```gleam
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import vestibule/credentials.{type Credentials}
import vestibule/user_info.{type UserInfo}

/// The normalized result of a successful authentication.
pub type Auth {
  Auth(
    /// Unique identifier from the provider (e.g., GitHub user ID).
    uid: String,
    /// Provider name matching the strategy.
    provider: String,
    /// Normalized user information.
    info: UserInfo,
    /// OAuth credentials (tokens, expiry).
    credentials: Credentials,
    /// Provider-specific extra data.
    extra: Dict(String, Dynamic),
  )
}
```

**Step 2: Create strategy.gleam**

```gleam
import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/user_info.{type UserInfo}

/// A strategy is a record containing the functions needed
/// to authenticate with a specific provider.
pub type Strategy {
  Strategy(
    /// Human-readable provider name (e.g., "github", "google").
    provider: String,
    /// Default scopes for this provider.
    default_scopes: List(String),
    /// Build the authorization URL to redirect the user to.
    /// Parameters: config, scopes, state.
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError),
    /// Exchange an authorization code for credentials.
    exchange_code: fn(Config, String) ->
      Result(Credentials, AuthError),
    /// Fetch user info using the obtained credentials.
    /// Returns #(uid, user_info).
    fetch_user: fn(Credentials) ->
      Result(#(String, UserInfo), AuthError),
  )
}
```

Note: `fetch_user` returns `#(String, UserInfo)` — a tuple of (uid, user_info) — because the uid comes from the user info response and the orchestrator needs it for the `Auth` result. Also added `default_scopes` field so the orchestrator can merge scopes.

**Step 3: Verify compilation**

Run: `gleam build`
Expected: Compiles with no errors

**Step 4: Commit**

```bash
git add src/vestibule/auth.gleam src/vestibule/strategy.gleam
git commit -m "feat: add Auth result and Strategy types"
```

---

### Task 5: State Module with Tests

**Files:**
- Create: `src/vestibule/state.gleam`
- Create: `test/vestibule/state_test.gleam`

**Step 1: Write failing tests**

Create `test/vestibule/state_test.gleam`:

```gleam
import gleam/string
import gleeunit/should
import vestibule/error
import vestibule/state

pub fn generate_produces_nonempty_string_test() {
  let s = state.generate()
  { string.length(s) >= 43 } |> should.be_true()
}

pub fn generate_produces_unique_values_test() {
  let a = state.generate()
  let b = state.generate()
  { a != b } |> should.be_true()
}

pub fn validate_accepts_matching_state_test() {
  let s = state.generate()
  state.validate(s, s)
  |> should.be_ok()
}

pub fn validate_rejects_mismatched_state_test() {
  state.validate("abc123", "def456")
  |> should.equal(Error(error.StateMismatch))
}

pub fn validate_rejects_empty_state_test() {
  state.validate("", "some-state")
  |> should.equal(Error(error.StateMismatch))
}
```

**Step 2: Run tests to verify they fail**

Run: `gleam test`
Expected: Compilation error — `state` module not found

**Step 3: Implement state.gleam**

```gleam
import gleam/bit_array
import gleam/crypto

import vestibule/error.{type AuthError, StateMismatch}

/// Generate a cryptographically random state parameter.
/// Returns 32 bytes of random data, base64url-encoded (no padding).
pub fn generate() -> String {
  crypto.strong_random_bytes(32)
  |> bit_array.base64_url_encode(False)
}

/// Validate a received state parameter against the expected value.
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate(
  received: String,
  expected: String,
) -> Result(Nil, AuthError) {
  let received_bits = <<received:utf8>>
  let expected_bits = <<expected:utf8>>
  case crypto.secure_compare(received_bits, expected_bits) {
    True -> Ok(Nil)
    False -> Error(StateMismatch)
  }
}
```

**Step 4: Run tests to verify they pass**

Run: `gleam test`
Expected: All state tests pass

**Step 5: Commit**

```bash
git add src/vestibule/state.gleam test/vestibule/state_test.gleam
git commit -m "feat: add CSRF state generation and validation with tests"
```

---

### Task 6: GitHub Strategy — JSON Parsers with Tests

This task builds the internal JSON parsing functions for GitHub's API responses. These are pure functions (no HTTP) and fully testable.

**Files:**
- Create: `src/vestibule/strategy/github.gleam`
- Create: `test/vestibule/strategy/github_test.gleam`

**Step 1: Write failing tests for token response parsing**

Create `test/vestibule/strategy/github_test.gleam`:

```gleam
import gleam/option.{None, Some}
import gleeunit/should
import vestibule/credentials.{Credentials}
import vestibule/strategy/github

pub fn parse_token_response_success_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email\"}"
  github.parse_token_response(json)
  |> should.be_ok()
  |> should.equal(Credentials(
    token: "gho_abc123",
    refresh_token: None,
    token_type: "bearer",
    expires_at: None,
    scopes: ["user:email"],
  ))
}

pub fn parse_token_response_with_multiple_scopes_test() {
  let json =
    "{\"access_token\":\"gho_abc123\",\"token_type\":\"bearer\",\"scope\":\"user:email,read:org\"}"
  let result = github.parse_token_response(json)
  let assert Ok(creds) = result
  creds.scopes |> should.equal(["user:email", "read:org"])
}

pub fn parse_token_response_error_test() {
  let json =
    "{\"error\":\"bad_verification_code\",\"error_description\":\"The code has expired\"}"
  github.parse_token_response(json)
  |> should.be_error()
}
```

**Step 2: Run tests to verify they fail**

Run: `gleam test`
Expected: Compilation error — `github` module not found

**Step 3: Create github.gleam with token response parser**

Create `src/vestibule/strategy/github.gleam` with:

```gleam
import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option, None}
import gleam/string

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info.{type UserInfo}

/// Create a GitHub authentication strategy.
pub fn strategy() -> Strategy {
  Strategy(
    provider: "github",
    default_scopes: ["user:email"],
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
}

/// Parse a GitHub token exchange response into Credentials.
/// Exported for testing.
pub fn parse_token_response(
  body: String,
) -> Result(Credentials, AuthError) {
  // First check if it's an error response
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

fn parse_success_token(body: String) -> Result(Credentials, AuthError) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use scope <- decode.field("scope", decode.string)
    decode.success(Credentials(
      token: access_token,
      refresh_token: None,
      token_type: token_type,
      expires_at: None,
      scopes: string.split(scope, ","),
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse token response",
      ))
  }
}

// Placeholder implementations — will be filled in next tasks
fn do_authorize_url(
  _config: Config,
  _scopes: List(String),
  _state: String,
) -> Result(String, AuthError) {
  Error(error.ConfigError(reason: "Not implemented"))
}

fn do_exchange_code(
  _config: Config,
  _code: String,
) -> Result(Credentials, AuthError) {
  Error(error.ConfigError(reason: "Not implemented"))
}

fn do_fetch_user(
  _credentials: Credentials,
) -> Result(#(String, UserInfo), AuthError) {
  Error(error.ConfigError(reason: "Not implemented"))
}
```

**Step 4: Run tests to verify they pass**

Run: `gleam test`
Expected: All parse_token_response tests pass

**Step 5: Commit**

```bash
git add src/vestibule/strategy/github.gleam test/vestibule/strategy/github_test.gleam
git commit -m "feat(github): add token response parser with tests"
```

---

### Task 7: GitHub Strategy — User Info Parser with Tests

**Files:**
- Modify: `src/vestibule/strategy/github.gleam`
- Modify: `test/vestibule/strategy/github_test.gleam`

**Step 1: Add failing tests for user info parsing**

Append to `test/vestibule/strategy/github_test.gleam`:

```gleam
import gleam/dict

pub fn parse_user_response_full_test() {
  let json =
    "{\"id\":12345,\"login\":\"octocat\",\"name\":\"The Octocat\",\"avatar_url\":\"https://avatars.githubusercontent.com/u/12345\",\"bio\":\"A cat that codes\",\"html_url\":\"https://github.com/octocat\"}"
  let result = github.parse_user_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> should.equal("12345")
  info.name |> should.equal(Some("The Octocat"))
  info.nickname |> should.equal(Some("octocat"))
  info.image
  |> should.equal(Some(
    "https://avatars.githubusercontent.com/u/12345",
  ))
  info.description |> should.equal(Some("A cat that codes"))
  info.urls
  |> should.equal(dict.from_list([
    #("html_url", "https://github.com/octocat"),
  ]))
}

pub fn parse_user_response_minimal_test() {
  let json = "{\"id\":99,\"login\":\"minimal\"}"
  let result = github.parse_user_response(json)
  let assert Ok(#(uid, info)) = result
  uid |> should.equal("99")
  info.name |> should.equal(None)
  info.email |> should.equal(None)
}

pub fn parse_emails_response_test() {
  let json =
    "[{\"email\":\"octocat@github.com\",\"primary\":true,\"verified\":true},{\"email\":\"other@example.com\",\"primary\":false,\"verified\":true}]"
  github.parse_primary_email(json)
  |> should.equal(Some("octocat@github.com"))
}

pub fn parse_emails_no_verified_primary_test() {
  let json =
    "[{\"email\":\"unverified@example.com\",\"primary\":true,\"verified\":false}]"
  github.parse_primary_email(json)
  |> should.equal(None)
}
```

**Step 2: Run tests to verify they fail**

Run: `gleam test`
Expected: Compilation error — `parse_user_response` and `parse_primary_email` not found

**Step 3: Add user info and email parsers to github.gleam**

Add to `src/vestibule/strategy/github.gleam`:

```gleam
import gleam/dict
import gleam/int
import gleam/list

/// Parse a GitHub /user API response into a uid and UserInfo.
/// Exported for testing.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError) {
  let decoder = {
    use id <- decode.field("id", decode.int)
    use login <- decode.field("login", decode.string)
    use name <- decode.optional_field("name", None, decode.optional(decode.string))
    use avatar_url <- decode.optional_field(
      "avatar_url",
      None,
      decode.optional(decode.string),
    )
    use bio <- decode.optional_field("bio", None, decode.optional(decode.string))
    use html_url <- decode.optional_field(
      "html_url",
      None,
      decode.optional(decode.string),
    )
    let urls = case html_url {
      option.Some(url) -> dict.from_list([#("html_url", url)])
      None -> dict.new()
    }
    decode.success(#(
      int.to_string(id),
      user_info.UserInfo(
        name: name,
        email: None,
        nickname: option.Some(login),
        image: avatar_url,
        description: bio,
        urls: urls,
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    _ ->
      Error(error.UserInfoFailed(reason: "Failed to parse GitHub user response"))
  }
}

/// Parse the primary verified email from GitHub /user/emails response.
/// Exported for testing.
pub fn parse_primary_email(body: String) -> Option(String) {
  let email_decoder = {
    use email <- decode.field("email", decode.string)
    use primary <- decode.field("primary", decode.bool)
    use verified <- decode.field("verified", decode.bool)
    decode.success(#(email, primary, verified))
  }
  let list_decoder = decode.list(email_decoder)
  case json.parse(body, list_decoder) {
    Ok(emails) ->
      emails
      |> list.find(fn(e) {
        let #(_, primary, verified) = e
        primary && verified
      })
      |> option.from_result()
      |> option.map(fn(e) {
        let #(email, _, _) = e
        email
      })
    _ -> None
  }
}
```

Also add these imports at the top of github.gleam (merge with existing):

```gleam
import gleam/dict
import gleam/int
import gleam/list
```

**Step 4: Run tests to verify they pass**

Run: `gleam test`
Expected: All github tests pass

**Step 5: Commit**

```bash
git add src/vestibule/strategy/github.gleam test/vestibule/strategy/github_test.gleam
git commit -m "feat(github): add user info and email parsers with tests"
```

---

### Task 8: GitHub Strategy — authorize_url Implementation

**Files:**
- Modify: `src/vestibule/strategy/github.gleam`

**Step 1: Implement do_authorize_url**

Replace the placeholder `do_authorize_url` function in `src/vestibule/strategy/github.gleam`:

```gleam
import gleam/uri

import glow_auth
import glow_auth/authorize_uri
import glow_auth/uri/uri_builder
```

```gleam
fn do_authorize_url(
  config: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError) {
  let assert Ok(site) = uri.parse("https://github.com")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client = glow_auth.Client(
    id: config.client_id,
    secret: config.client_secret,
    site: site,
  )
  let url =
    authorize_uri.build(
      client,
      uri_builder.RelativePath("/login/oauth/authorize"),
      redirect,
    )
    |> authorize_uri.set_scope(string.join(scopes, " "))
    |> authorize_uri.set_state(state)
    |> authorize_uri.to_code_authorization_uri()
    |> uri.to_string()
  Ok(url)
}
```

**Step 2: Run existing tests to ensure nothing breaks**

Run: `gleam test`
Expected: All tests still pass

**Step 3: Commit**

```bash
git add src/vestibule/strategy/github.gleam
git commit -m "feat(github): implement authorize_url with glow_auth"
```

---

### Task 9: GitHub Strategy — exchange_code Implementation

**Files:**
- Modify: `src/vestibule/strategy/github.gleam`

**Step 1: Implement do_exchange_code**

Add import at top:
```gleam
import gleam/http/request
import gleam/httpc
import glow_auth/token_request
```

Replace the placeholder `do_exchange_code`:

```gleam
fn do_exchange_code(
  config: Config,
  code: String,
) -> Result(Credentials, AuthError) {
  let assert Ok(site) = uri.parse("https://github.com")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client = glow_auth.Client(
    id: config.client_id,
    secret: config.client_secret,
    site: site,
  )
  let req =
    token_request.authorization_code(
      client,
      uri_builder.RelativePath("/login/oauth/access_token"),
      code,
      redirect,
    )
    |> request.set_header("accept", "application/json")

  case httpc.send(req) {
    Ok(response) -> parse_token_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to GitHub token endpoint",
      ))
  }
}
```

**Step 2: Verify compilation**

Run: `gleam build`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add src/vestibule/strategy/github.gleam
git commit -m "feat(github): implement code-to-token exchange via glow_auth"
```

---

### Task 10: GitHub Strategy — fetch_user Implementation

**Files:**
- Modify: `src/vestibule/strategy/github.gleam`

**Step 1: Implement do_fetch_user**

Replace the placeholder `do_fetch_user`:

```gleam
fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError) {
  // Fetch user profile
  let assert Ok(user_req) =
    request.to("https://api.github.com/user")
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
    |> request.set_header("user-agent", "vestibule-gleam")

  use user_response <- result_try_network(httpc.send(user_req))
  use #(uid, info) <- result_try(parse_user_response(user_response.body))

  // Fetch verified primary email
  let assert Ok(email_req) =
    request.to("https://api.github.com/user/emails")
  let email_req =
    email_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
    |> request.set_header("user-agent", "vestibule-gleam")

  let email = case httpc.send(email_req) {
    Ok(response) -> parse_primary_email(response.body)
    Error(_) -> None
  }

  // Merge email into user info (email from /user/emails takes precedence)
  let final_info = case email {
    option.Some(_) -> user_info.UserInfo(..info, email: email)
    None -> info
  }

  Ok(#(uid, final_info))
}

fn result_try_network(
  result: Result(a, b),
) -> Result(a, AuthError) {
  case result {
    Ok(value) -> Ok(value)
    Error(_) ->
      Error(error.NetworkError(reason: "HTTP request failed"))
  }
}

fn result_try(
  result: Result(a, AuthError),
) -> Result(a, AuthError) {
  result
}
```

Note: The `result_try_network` and `result_try` helpers need `use` syntax. Actually, let's simplify — use `gleam/result` instead:

```gleam
import gleam/result

fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError) {
  let assert Ok(user_req) =
    request.to("https://api.github.com/user")
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
    |> request.set_header("user-agent", "vestibule-gleam")

  let user_response = case httpc.send(user_req) {
    Ok(resp) -> Ok(resp)
    Error(_) ->
      Error(error.NetworkError(reason: "Failed to fetch GitHub user info"))
  }

  use resp <- result.try(user_response)
  use #(uid, info) <- result.try(parse_user_response(resp.body))

  // Fetch verified primary email (best-effort — don't fail if this errors)
  let assert Ok(email_req) =
    request.to("https://api.github.com/user/emails")
  let email_req =
    email_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
    |> request.set_header("user-agent", "vestibule-gleam")

  let email = case httpc.send(email_req) {
    Ok(response) -> parse_primary_email(response.body)
    Error(_) -> None
  }

  let final_info = case email {
    option.Some(_) -> user_info.UserInfo(..info, email: email)
    None -> info
  }

  Ok(#(uid, final_info))
}
```

**Step 2: Verify compilation**

Run: `gleam build`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add src/vestibule/strategy/github.gleam
git commit -m "feat(github): implement user info fetching with email lookup"
```

---

### Task 11: Public API Orchestrator with Tests

**Files:**
- Modify: `src/vestibule.gleam`
- Modify: `test/vestibule_test.gleam`

**Step 1: Write failing tests**

Replace `test/vestibule_test.gleam`:

```gleam
import gleam/dict
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import gleeunit/should
import vestibule
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule/error
import vestibule/strategy.{Strategy}
import vestibule/user_info.{UserInfo}

pub fn main() -> Nil {
  gleeunit.main()
}

// A fake strategy for testing the orchestrator
fn test_strategy() -> Strategy {
  Strategy(
    provider: "test",
    default_scopes: ["default_scope"],
    authorize_url: fn(_config, scopes, state) {
      Ok(
        "https://test.com/auth?scope="
        <> string.join(scopes, " ")
        <> "&state="
        <> state,
      )
    },
    exchange_code: fn(_config, code) {
      case code {
        "valid_code" ->
          Ok(Credentials(
            token: "test_token",
            refresh_token: None,
            token_type: "bearer",
            expires_at: None,
            scopes: ["default_scope"],
          ))
        _ -> Error(error.CodeExchangeFailed(reason: "bad code"))
      }
    },
    fetch_user: fn(_creds) {
      Ok(#(
        "user123",
        UserInfo(
          name: Some("Test User"),
          email: Some("test@example.com"),
          nickname: None,
          image: None,
          description: None,
          urls: dict.new(),
        ),
      ))
    },
  )
}

pub fn authorize_url_returns_url_and_state_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let result = vestibule.authorize_url(strat, conf)
  let assert Ok(#(url, state)) = result
  // URL should contain the state
  { string.contains(url, state) } |> should.be_true()
  // State should be non-empty
  { string.length(state) >= 43 } |> should.be_true()
}

pub fn authorize_url_uses_config_scopes_when_present_test() {
  let strat = test_strategy()
  let conf =
    config.new("id", "secret", "http://localhost/cb")
    |> config.with_scopes(["custom_scope"])
  let assert Ok(#(url, _state)) = vestibule.authorize_url(strat, conf)
  { string.contains(url, "custom_scope") } |> should.be_true()
  { string.contains(url, "default_scope") } |> should.be_false()
}

pub fn authorize_url_uses_default_scopes_when_config_empty_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let assert Ok(#(url, _state)) = vestibule.authorize_url(strat, conf)
  { string.contains(url, "default_scope") } |> should.be_true()
}

pub fn handle_callback_succeeds_with_valid_params_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state_value"
  let params =
    dict.from_list([#("code", "valid_code"), #("state", state)])
  let result = vestibule.handle_callback(strat, conf, params, state)
  let assert Ok(auth) = result
  auth.uid |> should.equal("user123")
  auth.provider |> should.equal("test")
  auth.info.name |> should.equal(Some("Test User"))
  auth.credentials.token |> should.equal("test_token")
}

pub fn handle_callback_fails_on_state_mismatch_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let params =
    dict.from_list([#("code", "valid_code"), #("state", "wrong")])
  let result = vestibule.handle_callback(strat, conf, params, "expected")
  result |> should.be_error()
}

pub fn handle_callback_fails_on_missing_code_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "http://localhost/cb")
  let state = "test_state"
  let params = dict.from_list([#("state", state)])
  let result = vestibule.handle_callback(strat, conf, params, state)
  result |> should.be_error()
}
```

**Step 2: Run tests to verify they fail**

Run: `gleam test`
Expected: Compilation errors — `vestibule.authorize_url` and `vestibule.handle_callback` not found

**Step 3: Implement vestibule.gleam**

Replace `src/vestibule.gleam`:

```gleam
/// Vestibule — a strategy-based authentication library for Gleam.
///
/// Provides a consistent interface across OAuth2 identity providers
/// using a two-phase flow: redirect to provider, then handle callback.

import gleam/dict.{type Dict}
import gleam/dynamic
import gleam/list
import gleam/result

import vestibule/auth.{type Auth, Auth}
import vestibule/config.{type Config}
import vestibule/error.{type AuthError}
import vestibule/state
import vestibule/strategy.{type Strategy}

/// Phase 1: Generate the authorization URL to redirect the user to.
///
/// Returns `#(url, state)` — the caller must store the state parameter
/// in their session for validation during the callback phase.
pub fn authorize_url(
  strategy: Strategy,
  config: Config,
) -> Result(#(String, String), AuthError) {
  let csrf_state = state.generate()
  let scopes = case config.scopes {
    [] -> strategy.default_scopes
    custom -> custom
  }
  use url <- result.try(strategy.authorize_url(config, scopes, csrf_state))
  Ok(#(url, csrf_state))
}

/// Phase 2: Handle the OAuth callback from the provider.
///
/// Validates the state parameter, exchanges the authorization code
/// for credentials, and fetches normalized user information.
pub fn handle_callback(
  strategy: Strategy,
  config: Config,
  callback_params: Dict(String, String),
  expected_state: String,
) -> Result(Auth, AuthError) {
  // Extract required parameters
  use received_state <- result.try(
    dict.get(callback_params, "state")
    |> result.replace_error(error.ConfigError(
      reason: "Missing state parameter in callback",
    )),
  )
  use code <- result.try(
    dict.get(callback_params, "code")
    |> result.replace_error(error.ConfigError(
      reason: "Missing code parameter in callback",
    )),
  )

  // Check for provider errors
  use _ <- result.try(case dict.get(callback_params, "error") {
    Ok(error_code) -> {
      let description =
        dict.get(callback_params, "error_description")
        |> result.unwrap("")
      Error(error.ProviderError(code: error_code, description: description))
    }
    Error(Nil) -> Ok(Nil)
  })

  // Validate state
  use _ <- result.try(state.validate(received_state, expected_state))

  // Exchange code for credentials
  use credentials <- result.try(strategy.exchange_code(config, code))

  // Fetch user info
  use #(uid, info) <- result.try(strategy.fetch_user(credentials))

  // Assemble the Auth result
  Ok(Auth(
    uid: uid,
    provider: strategy.provider,
    info: info,
    credentials: credentials,
    extra: dict.new(),
  ))
}
```

**Step 4: Run tests to verify they pass**

Run: `gleam test`
Expected: All tests pass

**Step 5: Run format check**

Run: `gleam format src test`

**Step 6: Commit**

```bash
git add src/vestibule.gleam test/vestibule_test.gleam
git commit -m "feat: add public API orchestrator — authorize_url and handle_callback"
```

---

### Task 12: Clean Up and Final Verification

**Files:**
- All source and test files

**Step 1: Run full test suite**

Run: `gleam test`
Expected: All tests pass

**Step 2: Format all code**

Run: `gleam format src test`

**Step 3: Type check**

Run: `gleam check`
Expected: No warnings or errors

**Step 4: Build docs (verify doc comments are valid)**

Run: `gleam docs build`
Expected: Docs build without errors

**Step 5: Review for unused imports or dead code**

Scan each file for any unused imports from placeholder stages. Remove the `_` prefixed params if no longer needed. Ensure `result` import exists where used.

**Step 6: Final commit (if any cleanup was needed)**

```bash
git add -A
git commit -m "chore: clean up imports and formatting"
```

---

## Summary of Commits

| # | Message | What |
|---|---------|------|
| 1 | `feat: add OAuth2 and HTTP dependencies` | gleam.toml + manifest |
| 2 | `feat: add core types — AuthError, UserInfo, Credentials` | 3 type modules |
| 3 | `feat: add Config type with builder functions and tests` | config + tests |
| 4 | `feat: add Auth result and Strategy types` | auth + strategy types |
| 5 | `feat: add CSRF state generation and validation with tests` | state + tests |
| 6 | `feat(github): add token response parser with tests` | github JSON parsing |
| 7 | `feat(github): add user info and email parsers with tests` | github user parsing |
| 8 | `feat(github): implement authorize_url with glow_auth` | auth URL builder |
| 9 | `feat(github): implement code-to-token exchange` | token exchange |
| 10 | `feat(github): implement user info fetching` | user + email fetch |
| 11 | `feat: add public API orchestrator` | vestibule.gleam + tests |
| 12 | `chore: clean up imports and formatting` | final polish |
