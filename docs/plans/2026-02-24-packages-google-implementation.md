# Packages Layout & Google Strategy — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure the repo into a packages layout, move Microsoft to its own package, and implement a full Google OAuth provider package.

**Architecture:** Provider packages live under `packages/` with path dependencies on the core `vestibule` library. Each exports a flat module (`vestibule_google`, `vestibule_microsoft`) with `strategy()`, `parse_token_response()`, and `parse_user_response()`. The example app depends on all providers via path dependencies.

**Tech Stack:** Gleam 1.14+, glow_auth, gleam_httpc, gleam_json, gleam_crypto, startest

**Design doc:** `docs/plans/2026-02-24-packages-google-design.md`

---

### Task 1: Create vestibule_microsoft package — Move Microsoft strategy

**Files:**
- Create: `packages/vestibule_microsoft/gleam.toml`
- Create: `packages/vestibule_microsoft/src/vestibule_microsoft.gleam` (move from `src/vestibule/strategy/microsoft.gleam`)
- Create: `packages/vestibule_microsoft/test/vestibule_microsoft_test.gleam` (move from `test/vestibule/strategy/microsoft_test.gleam`)
- Delete: `src/vestibule/strategy/microsoft.gleam`
- Delete: `test/vestibule/strategy/microsoft_test.gleam`

**Step 1: Create the package directory and gleam.toml**

Create `packages/vestibule_microsoft/gleam.toml`:

```toml
name = "vestibule_microsoft"
version = "0.1.0"
description = "Microsoft OAuth strategy for vestibule"
licences = ["MIT"]
repository = { type = "github", user = "tylerbutler", repo = "vestibule", path = "packages/vestibule_microsoft" }
gleam = ">= 1.7.0"

[dependencies]
vestibule = { path = "../.." }
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_crypto = ">= 1.5.0 and < 2.0.0"
gleam_http = ">= 4.3.0 and < 5.0.0"
gleam_httpc = ">= 5.0.0 and < 6.0.0"
gleam_json = ">= 3.1.0 and < 4.0.0"
glow_auth = ">= 1.0.1 and < 2.0.0"

[dev-dependencies]
startest = ">= 0.8.0 and < 1.0.0"
```

**Step 2: Move microsoft.gleam to the new package**

Copy `src/vestibule/strategy/microsoft.gleam` to `packages/vestibule_microsoft/src/vestibule_microsoft.gleam`.

Update the module — the code stays the same, but remove the `vestibule/strategy/` prefix from the module identity (Gleam derives module name from file path relative to `src/`). The imports don't change since it still depends on `vestibule`.

**Step 3: Move the test file**

Copy `test/vestibule/strategy/microsoft_test.gleam` to `packages/vestibule_microsoft/test/vestibule_microsoft_test.gleam`.

Update the test's import and startest main:

```gleam
import gleam/option.{None, Some}
import gleam/string as gleam_string
import startest
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule_microsoft

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read profile openid email\",\"expires_in\":3736,\"ext_expires_in\":3736,\"access_token\":\"eyJ0eXAi_test_token\",\"refresh_token\":\"AwABAAAA_test_refresh\"}"
  vestibule_microsoft.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "eyJ0eXAi_test_token",
      refresh_token: Some("AwABAAAA_test_refresh"),
      token_type: "Bearer",
      expires_at: Some(3736),
      scopes: ["User.Read", "profile", "openid", "email"],
    ),
  )
}
```

(Repeat for all existing test functions, replacing `microsoft.` with `vestibule_microsoft.`.)

**Step 4: Delete the old files from core**

```bash
rm src/vestibule/strategy/microsoft.gleam
rm test/vestibule/strategy/microsoft_test.gleam
```

**Step 5: Verify the core library still compiles and tests pass**

```bash
gleam test
```

Expected: 21 tests pass (the 6 Microsoft tests are gone from core, leaving 25 minus those = the original 21 pre-Microsoft count + 4 registry tests = 25 remaining).

Note: Count the exact remaining tests. Core had 31 total: 21 original + 6 Microsoft + 4 registry. Removing 6 Microsoft leaves 25.

**Step 6: Verify the new package compiles and tests pass**

```bash
cd packages/vestibule_microsoft && gleam test
```

Expected: 6 Microsoft tests pass.

**Step 7: Commit**

```bash
git add packages/vestibule_microsoft/ && git add -u src/vestibule/strategy/microsoft.gleam test/vestibule/strategy/microsoft_test.gleam
git commit -m "refactor: extract Microsoft strategy into vestibule_microsoft package

Move Microsoft OAuth provider from src/vestibule/strategy/microsoft.gleam
to packages/vestibule_microsoft/ as an independent package."
```

---

### Task 2: Create vestibule_google package — Token Parsing

**Files:**
- Create: `packages/vestibule_google/gleam.toml`
- Create: `packages/vestibule_google/test/vestibule_google_test.gleam`
- Create: `packages/vestibule_google/src/vestibule_google.gleam`

**Step 1: Create gleam.toml**

Create `packages/vestibule_google/gleam.toml`:

```toml
name = "vestibule_google"
version = "0.1.0"
description = "Google OAuth strategy for vestibule"
licences = ["MIT"]
repository = { type = "github", user = "tylerbutler", repo = "vestibule", path = "packages/vestibule_google" }
gleam = ">= 1.7.0"

[dependencies]
vestibule = { path = "../.." }
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_http = ">= 4.3.0 and < 5.0.0"
gleam_httpc = ">= 5.0.0 and < 6.0.0"
gleam_json = ">= 3.1.0 and < 4.0.0"
glow_auth = ">= 1.0.1 and < 2.0.0"

[dev-dependencies]
startest = ">= 0.8.0 and < 1.0.0"
```

**Step 2: Write failing tests for token parsing**

Create `packages/vestibule_google/test/vestibule_google_test.gleam`:

```gleam
import gleam/option.{None, Some}
import startest
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule_google

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"ya29.test_token\",\"expires_in\":3599,\"scope\":\"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile\",\"token_type\":\"Bearer\"}"
  vestibule_google.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "ya29.test_token",
      refresh_token: None,
      token_type: "Bearer",
      expires_at: Some(3599),
      scopes: [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
      ],
    ),
  )
}

pub fn parse_token_response_with_refresh_token_test() {
  let body =
    "{\"access_token\":\"ya29.test\",\"expires_in\":3600,\"refresh_token\":\"1//test_refresh\",\"scope\":\"openid\",\"token_type\":\"Bearer\"}"
  vestibule_google.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "ya29.test",
      refresh_token: Some("1//test_refresh"),
      token_type: "Bearer",
      expires_at: Some(3600),
      scopes: ["openid"],
    ),
  )
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been expired or revoked.\"}"
  let _ =
    vestibule_google.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}
```

**Step 3: Run tests to verify they fail**

```bash
cd packages/vestibule_google && gleam test
```

Expected: Compilation error — `vestibule_google` module not found.

**Step 4: Implement token parsing**

Create `packages/vestibule_google/src/vestibule_google.gleam`:

```gleam
import gleam/dynamic/decode
import gleam/json
import gleam/option.{None}
import gleam/string

import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}

/// Parse Google token response JSON.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
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

fn parse_success_token(body: String) -> Result(Credentials, AuthError(e)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use scope <- decode.field("scope", decode.string)
    use expires_in <- decode.optional_field(
      "expires_in",
      None,
      decode.optional(decode.int),
    )
    use refresh_token <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    decode.success(Credentials(
      token: access_token,
      refresh_token: refresh_token,
      token_type: token_type,
      expires_at: expires_in,
      scopes: string.split(scope, " "),
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse Google token response",
      ))
  }
}
```

**Step 5: Run tests to verify they pass**

```bash
cd packages/vestibule_google && gleam test
```

Expected: 3 token parsing tests pass.

**Step 6: Commit**

```bash
git add packages/vestibule_google/
git commit -m "feat(vestibule_google): add token response parsing"
```

---

### Task 3: Google Strategy — User Info Parsing

**Files:**
- Modify: `packages/vestibule_google/test/vestibule_google_test.gleam`
- Modify: `packages/vestibule_google/src/vestibule_google.gleam`

**Step 1: Write failing tests for user info parsing**

Add to `packages/vestibule_google/test/vestibule_google_test.gleam`:

```gleam
pub fn parse_user_response_full_test() {
  let body =
    "{\"sub\":\"1234567890\",\"name\":\"Jane Doe\",\"given_name\":\"Jane\",\"family_name\":\"Doe\",\"picture\":\"https://lh3.googleusercontent.com/photo.jpg\",\"email\":\"jane@example.com\",\"email_verified\":true}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  uid |> expect.to_equal("1234567890")
  info.name |> expect.to_equal(Some("Jane Doe"))
  info.email |> expect.to_equal(Some("jane@example.com"))
  info.nickname |> expect.to_equal(Some("jane@example.com"))
  info.image
  |> expect.to_equal(Some("https://lh3.googleusercontent.com/photo.jpg"))
  info.description |> expect.to_equal(None)
}

pub fn parse_user_response_unverified_email_test() {
  let body =
    "{\"sub\":\"999\",\"name\":\"Test\",\"email\":\"unverified@example.com\",\"email_verified\":false}"
  let assert Ok(#(_uid, info)) = vestibule_google.parse_user_response(body)
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(Some("unverified@example.com"))
}

pub fn parse_user_response_minimal_test() {
  let body = "{\"sub\":\"abc-123\"}"
  let assert Ok(#(uid, info)) = vestibule_google.parse_user_response(body)
  uid |> expect.to_equal("abc-123")
  info.name |> expect.to_equal(None)
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(None)
  info.image |> expect.to_equal(None)
}
```

**Step 2: Run tests to verify they fail**

```bash
cd packages/vestibule_google && gleam test
```

Expected: Compilation error — `parse_user_response` not found.

**Step 3: Implement user info parsing**

Add to `packages/vestibule_google/src/vestibule_google.gleam`:

Add these imports at the top:

```gleam
import gleam/dict
import gleam/option.{type Option, None, Some}
import vestibule/user_info.{type UserInfo}
```

Note: Adjust existing `import gleam/option.{None}` to include `type Option` and `Some`.

Add these functions:

```gleam
/// Parse Google /oauth2/v3/userinfo response JSON.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let decoder = {
    use sub <- decode.field("sub", decode.string)
    use name <- decode.optional_field(
      "name",
      None,
      decode.optional(decode.string),
    )
    use picture <- decode.optional_field(
      "picture",
      None,
      decode.optional(decode.string),
    )
    use email <- decode.optional_field(
      "email",
      None,
      decode.optional(decode.string),
    )
    use email_verified <- decode.optional_field(
      "email_verified",
      None,
      decode.optional(decode.bool),
    )
    let verified_email = case email, email_verified {
      Some(addr), Some(True) -> Some(addr)
      _, _ -> None
    }
    decode.success(#(
      sub,
      user_info.UserInfo(
        name: name,
        email: verified_email,
        nickname: email,
        image: picture,
        description: None,
        urls: dict.new(),
      ),
    ))
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    _ ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse Google user response",
      ))
  }
}
```

**Step 4: Run tests to verify they pass**

```bash
cd packages/vestibule_google && gleam test
```

Expected: 6 tests pass (3 token + 3 user info).

**Step 5: Commit**

```bash
git add packages/vestibule_google/
git commit -m "feat(vestibule_google): add user info parsing

Only includes verified emails in the email field. Unverified emails
are still available via the nickname field."
```

---

### Task 4: Google Strategy — Full Strategy Wiring

**Files:**
- Modify: `packages/vestibule_google/src/vestibule_google.gleam`

**Step 1: Add strategy function and OAuth flow**

Add imports:

```gleam
import gleam/uri
import gleam/http/request
import gleam/httpc
import glow_auth
import glow_auth/authorize_uri
import glow_auth/token_request
import glow_auth/uri/uri_builder
import vestibule/config.{type Config}
import vestibule/strategy.{type Strategy, Strategy}
```

Add the strategy function and private helpers:

```gleam
/// Create a Google authentication strategy.
pub fn strategy() -> Strategy(e) {
  Strategy(
    provider: "google",
    default_scopes: ["openid", "profile", "email"],
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: do_fetch_user,
  )
}

fn do_authorize_url(
  config: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://accounts.google.com")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
      site: site,
    )
  let url =
    authorize_uri.build(
      client,
      uri_builder.RelativePath("/o/oauth2/v2/auth"),
      redirect,
    )
    |> authorize_uri.set_scope(string.join(scopes, " "))
    |> authorize_uri.set_state(state)
    |> authorize_uri.to_code_authorization_uri()
    |> uri.to_string()
  Ok(url)
}

fn do_exchange_code(
  config: Config,
  code: String,
) -> Result(Credentials, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://oauth2.googleapis.com")
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
        reason: "Failed to connect to Google token endpoint",
      ))
  }
}

fn do_fetch_user(
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let assert Ok(user_req) =
    request.to("https://www.googleapis.com/oauth2/v3/userinfo")
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("accept", "application/json")
  case httpc.send(user_req) {
    Ok(response) -> parse_user_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Google userinfo API",
      ))
  }
}
```

**Step 2: Verify compilation**

```bash
cd packages/vestibule_google && gleam build
```

Expected: Compiles with no errors.

**Step 3: Run tests to verify nothing broke**

```bash
cd packages/vestibule_google && gleam test
```

Expected: 6 tests pass.

**Step 4: Commit**

```bash
git add packages/vestibule_google/
git commit -m "feat(vestibule_google): wire up strategy with glow_auth OAuth flow

Targets accounts.google.com for authorization, oauth2.googleapis.com
for token exchange, and googleapis.com/oauth2/v3/userinfo for profile."
```

---

### Task 5: Update Example App

**Files:**
- Modify: `example/gleam.toml`
- Modify: `example/src/vestibule_example.gleam`
- Modify: `example/.env.example`

**Step 1: Add provider package dependencies to example**

Add to `example/gleam.toml` under `[dependencies]`:

```toml
vestibule_microsoft = { path = "../packages/vestibule_microsoft" }
vestibule_google = { path = "../packages/vestibule_google" }
```

**Step 2: Update vestibule_example.gleam**

Change the Microsoft import from `vestibule/strategy/microsoft` to `vestibule_microsoft`, add `vestibule_google` import, and add Google provider registration:

Replace the import:
```gleam
import vestibule/strategy/microsoft
```
with:
```gleam
import vestibule_microsoft
import vestibule_google
```

Replace `microsoft.strategy()` with `vestibule_microsoft.strategy()`.

Add Google registration block after the Microsoft block:

```gleam
  let reg = case
    envoy.get("GOOGLE_CLIENT_ID"),
    envoy.get("GOOGLE_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: google")
      registry.register(
        reg,
        vestibule_google.strategy(),
        config.new(id, secret, callback_base <> "/auth/google/callback"),
      )
    }
    _, _ -> reg
  }
```

Update the "no providers" error message to mention Google.

**Step 3: Update .env.example**

Add:
```
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

**Step 4: Verify example compiles**

```bash
cd example && gleam build
```

Expected: Compiles with no errors.

**Step 5: Run example tests**

```bash
cd example && gleam test
```

Expected: 3 session tests pass.

**Step 6: Commit**

```bash
git add example/
git commit -m "feat(example): add Google provider and use external Microsoft package

Example app now depends on vestibule_microsoft and vestibule_google
as path dependencies. Registers all three providers dynamically."
```

---

### Task 6: Verification and Cleanup

**Step 1: Run core library tests**

```bash
gleam format src test && gleam check && gleam test
```

Expected: 25 tests pass (31 minus 6 Microsoft tests that moved).

**Step 2: Run each provider package**

```bash
cd packages/vestibule_microsoft && gleam format src test && gleam test
cd ../vestibule_google && gleam format src test && gleam test
```

Expected: Microsoft 6 tests, Google 6 tests.

**Step 3: Run example**

```bash
cd example && gleam format src && gleam build && gleam test
```

Expected: 3 session tests pass.

**Step 4: Commit any formatting changes**

```bash
git add -A
git commit -m "style: apply gleam format"
```

(Only if there are formatting changes.)

---

## Summary of Commits

| # | Message | What |
|---|---------|------|
| 1 | `refactor: extract Microsoft strategy into vestibule_microsoft package` | Move Microsoft to packages/ |
| 2 | `feat(vestibule_google): add token response parsing` | Google package + token parsing + tests |
| 3 | `feat(vestibule_google): add user info parsing` | User info parsing + verified email logic + tests |
| 4 | `feat(vestibule_google): wire up strategy with glow_auth OAuth flow` | Full strategy wiring |
| 5 | `feat(example): add Google provider and use external Microsoft package` | Example app updates |
| 6 | `style: apply gleam format` | If needed |
