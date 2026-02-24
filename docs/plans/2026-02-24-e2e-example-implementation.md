# E2E Example App Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a polished Wisp web app in `example/` that demonstrates the full GitHub OAuth flow using vestibule's current API.

**Architecture:** Gleam project at `example/` with path dependency on vestibule. Wisp handles HTTP, Erlang FFI provides ETS-backed session storage for CSRF state, envoy reads GitHub credentials from env vars. Simple inline HTML pages — no templates or CSS frameworks.

**Tech Stack:** Gleam 1.14+, wisp 2.2.0, mist (via wisp), Erlang FFI for ETS, envoy 1.1.0, vestibule (path dep)

> **Implementation notes (deviations from original plan):**
> - **carpenter replaced with Erlang FFI**: carpenter 0.3.1 and bravo 4.0.1 both require `gleam_erlang < 1.0.0`, incompatible with vestibule's `gleam_erlang 1.3.0`. Session storage uses `session_ffi.erl` (~30 lines) for direct ETS access.
> - **rebar3 added to toolchain**: Required by the `telemetry` transitive dependency. Added via `mise use rebar@3.26.0`.
> - **`wisp.html_response` takes `String`**: Plan's `pages.gleam` used `string_tree.from_string` but wisp 2.2.0 expects plain `String`. Fixed to use string concatenation directly.
> - **`gleam_crypto` added as direct dep**: Needed for `crypto.strong_random_bytes` in session ID generation (was implicit via vestibule, made explicit).

**Design doc:** `docs/plans/2026-02-24-e2e-example-design.md`

---

### Task 1: Scaffold the Example Project

**Files:**
- Create: `example/gleam.toml`

**Step 1: Create the example Gleam project**

Run from repo root:

```bash
mkdir example
```

Create `example/gleam.toml`:

```toml
name = "vestibule_example"
version = "0.0.0"
description = "Example Wisp app demonstrating vestibule GitHub OAuth"
gleam = ">= 1.7.0"

[dependencies]
vestibule = { path = ".." }
wisp = ">= 2.2.0 and < 3.0.0"
mist = ">= 4.0.0 and < 6.0.0"
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_erlang = ">= 1.0.0 and < 2.0.0"
gleam_http = ">= 4.0.0 and < 5.0.0"
envoy = ">= 1.1.0 and < 2.0.0"
carpenter = ">= 0.3.0 and < 1.0.0"

[dev-dependencies]
startest = ">= 0.8.0 and < 1.0.0"
```

**Step 2: Create a minimal entrypoint so it compiles**

Create `example/src/app.gleam`:

```gleam
import gleam/io

pub fn main() {
  io.println("vestibule example — not yet implemented")
}
```

**Step 3: Build to download deps and verify**

Run from `example/`:

```bash
gleam build
```

Expected: Downloads all packages, compiles successfully.

**Step 4: Commit**

```bash
git add example/gleam.toml example/manifest.toml example/src/app.gleam
git commit -m "feat(example): scaffold example Wisp project with dependencies"
```

---

### Task 2: Session Module (ETS-backed state storage)

**Files:**
- Create: `example/src/session.gleam`
- Create: `example/test/session_test.gleam`

**Step 1: Write failing tests**

Create `example/test/session_test.gleam`:

```gleam
import startest
import startest/expect
import session

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn store_and_retrieve_state_test() {
  session.create_table()
  let state = "test_csrf_state_value"
  let session_id = session.store_state(state)
  session.get_state(session_id)
  |> expect.to_equal(Ok(state))
}

pub fn get_state_deletes_after_retrieval_test() {
  session.create_table()
  let session_id = session.store_state("one_time_state")
  // First retrieval succeeds
  session.get_state(session_id)
  |> expect.to_be_ok()
  // Second retrieval fails (one-time use)
  session.get_state(session_id)
  |> expect.to_be_error()
}

pub fn get_state_returns_error_for_unknown_id_test() {
  session.create_table()
  session.get_state("nonexistent")
  |> expect.to_be_error()
}
```

**Step 2: Run tests to verify they fail**

Run from `example/`:

```bash
gleam test
```

Expected: Compilation error — `session` module not found.

**Step 3: Implement session.gleam**

Create `example/src/session.gleam`:

```gleam
import carpenter/table
import gleam/bit_array
import gleam/crypto

/// Create the ETS table for session storage.
/// Call once at app startup.
pub fn create_table() -> Nil {
  let _table =
    table.build("vestibule_sessions")
    |> table.set
    |> table.privacy(table.Public)
    |> table.write_concurrency(table.AutoWriteConcurrency)
    |> table.read_concurrency(True)
  Nil
}

/// Store a CSRF state value and return the session ID.
pub fn store_state(state: String) -> String {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  let assert Ok(t) = table.ref("vestibule_sessions")
  t |> table.insert(session_id, state)
  session_id
}

/// Retrieve and delete a CSRF state by session ID.
/// Returns Error(Nil) if not found (one-time use).
pub fn get_state(session_id: String) -> Result(String, Nil) {
  let assert Ok(t) = table.ref("vestibule_sessions")
  case table.lookup(t, session_id) {
    [] -> Error(Nil)
    [#(_key, value), ..] -> {
      table.delete(t, session_id)
      Ok(value)
    }
  }
}
```

Note: `table.ref` may not exist in carpenter. If so, we'll need to store the table reference from `create_table` and pass it around, or use the Erlang `:ets.whereis` FFI. Adjust during implementation if the API differs.

**Step 4: Run tests to verify they pass**

Run from `example/`:

```bash
gleam test
```

Expected: All session tests pass.

**Step 5: Commit**

```bash
git add example/src/session.gleam example/test/session_test.gleam
git commit -m "feat(example): add ETS-backed session store for CSRF state"
```

---

### Task 3: HTML Pages Module

**Files:**
- Create: `example/src/pages.gleam`

No tests needed — these are pure HTML string functions.

**Step 1: Implement pages.gleam**

Create `example/src/pages.gleam`:

```gleam
import gleam/option.{type Option, None, Some}
import gleam/string_tree.{type StringTree}
import wisp

import vestibule/auth.{type Auth}
import vestibule/error.{type AuthError}

/// Landing page with GitHub sign-in link.
pub fn landing() -> wisp.Response {
  let html =
    string_tree.from_string(
      "<html>
<head><title>Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center;\">
  <h1>Vestibule Demo</h1>
  <p>OAuth2 authentication library for Gleam</p>
  <a href=\"/auth/github\"
     style=\"display: inline-block; padding: 12px 24px; background: #24292e; color: white; text-decoration: none; border-radius: 6px; font-size: 16px;\">
    Sign in with GitHub
  </a>
</body>
</html>",
    )
  wisp.html_response(html, 200)
}

/// Success page showing authenticated user info.
pub fn success(auth: Auth) -> wisp.Response {
  let name = option_or(auth.info.name, "—")
  let email = option_or(auth.info.email, "—")
  let nickname = option_or(auth.info.nickname, "—")
  let image_html = case auth.info.image {
    Some(url) ->
      "<img src=\"" <> url <> "\" width=\"80\" height=\"80\" style=\"border-radius: 50%;\" />"
    None -> ""
  }
  let html =
    string_tree.from_string(
      "<html>
<head><title>Authenticated — Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authenticated!</h1>
  " <> image_html <> "
  <table style=\"margin: 20px 0; border-collapse: collapse;\">
    <tr><td style=\"padding: 8px; font-weight: bold;\">Provider</td><td style=\"padding: 8px;\">" <> auth.provider <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">UID</td><td style=\"padding: 8px;\">" <> auth.uid <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Name</td><td style=\"padding: 8px;\">" <> name <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Email</td><td style=\"padding: 8px;\">" <> email <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Nickname</td><td style=\"padding: 8px;\">" <> nickname <> "</td></tr>
  </table>
  <a href=\"/\">Back to home</a>
</body>
</html>",
    )
  wisp.html_response(html, 200)
}

/// Error page.
pub fn error(err: AuthError) -> wisp.Response {
  let message = case err {
    error.StateMismatch -> "State mismatch — possible CSRF attack"
    error.CodeExchangeFailed(reason:) -> "Code exchange failed: " <> reason
    error.UserInfoFailed(reason:) -> "User info fetch failed: " <> reason
    error.ProviderError(code:, description:) -> "Provider error [" <> code <> "]: " <> description
    error.NetworkError(reason:) -> "Network error: " <> reason
    error.ConfigError(reason:) -> "Configuration error: " <> reason
  }
  let html =
    string_tree.from_string(
      "<html>
<head><title>Error — Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authentication Failed</h1>
  <p style=\"color: #c0392b;\">" <> message <> "</p>
  <a href=\"/\">Try again</a>
</body>
</html>",
    )
  wisp.html_response(html, 400)
}

fn option_or(opt: Option(String), default: String) -> String {
  case opt {
    Some(value) -> value
    None -> default
  }
}
```

**Step 2: Verify compilation**

Run from `example/`:

```bash
gleam build
```

Expected: Compiles with no errors.

**Step 3: Commit**

```bash
git add example/src/pages.gleam
git commit -m "feat(example): add HTML pages for landing, success, and error"
```

---

### Task 4: Router Module

**Files:**
- Create: `example/src/router.gleam`

**Step 1: Implement router.gleam**

Create `example/src/router.gleam`:

```gleam
import gleam/dict
import gleam/http
import wisp.{type Request, type Response}

import pages
import session
import vestibule
import vestibule/config.{type Config}
import vestibule/strategy.{type Strategy}

/// Application context passed to the router.
pub type Context {
  Context(strategy: Strategy, config: Config)
}

/// Route incoming requests.
pub fn handle_request(req: Request, ctx: Context) -> Response {
  use <- wisp.log_request(req)

  case wisp.path_segments(req), req.method {
    // Landing page
    [], http.Get -> pages.landing()

    // Phase 1: Redirect to GitHub
    ["auth", "github"], http.Get -> begin_auth(req, ctx)

    // Phase 2: Handle callback
    ["auth", "github", "callback"], http.Get -> handle_callback(req, ctx)

    // Everything else
    _, _ -> wisp.not_found()
  }
}

fn begin_auth(req: Request, ctx: Context) -> Response {
  case vestibule.authorize_url(ctx.strategy, ctx.config) {
    Ok(#(url, state)) -> {
      // Store CSRF state in ETS, get session ID
      let session_id = session.store_state(state)
      // Set session ID as signed cookie, redirect to provider
      wisp.redirect(url)
      |> wisp.set_cookie(req, "vestibule_session", session_id, wisp.Signed, 600)
    }
    Error(err) -> pages.error(err)
  }
}

fn handle_callback(req: Request, ctx: Context) -> Response {
  // Read session ID from cookie
  let session_result = wisp.get_cookie(req, "vestibule_session", wisp.Signed)

  case session_result {
    Error(Nil) ->
      pages.error(vestibule.error.ConfigError(
        reason: "Missing session cookie",
      ))
    Ok(session_id) -> {
      // Look up CSRF state from ETS
      case session.get_state(session_id) {
        Error(Nil) ->
          pages.error(vestibule.error.ConfigError(
            reason: "Session expired or already used",
          ))
        Ok(expected_state) -> {
          // Convert query params to Dict
          let params =
            wisp.get_query(req)
            |> dict.from_list()

          // Complete the OAuth flow
          case
            vestibule.handle_callback(
              ctx.strategy,
              ctx.config,
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
```

Note: The `vestibule.error.ConfigError` import path may need adjustment — it might need to be imported as `vestibule/error.{ConfigError}` instead. Adjust during implementation.

**Step 2: Verify compilation**

Run from `example/`:

```bash
gleam build
```

Expected: Compiles with no errors.

**Step 3: Commit**

```bash
git add example/src/router.gleam
git commit -m "feat(example): add router with auth routes"
```

---

### Task 5: App Entrypoint

**Files:**
- Modify: `example/src/app.gleam`

**Step 1: Implement app.gleam**

Replace `example/src/app.gleam`:

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
import vestibule/strategy/github

pub fn main() {
  // Read configuration from environment
  let assert Ok(client_id) = envoy.get("GITHUB_CLIENT_ID")
  let assert Ok(client_secret) = envoy.get("GITHUB_CLIENT_SECRET")
  let port =
    envoy.get("PORT")
    |> result.then(int.parse)
    |> result.unwrap(8000)
  let secret_key_base =
    envoy.get("SECRET_KEY_BASE")
    |> result.unwrap("development-secret-key-base-change-in-production-please")

  // Set up vestibule
  let strategy = github.strategy()
  let cfg =
    config.new(
      client_id,
      client_secret,
      "http://localhost:" <> int.to_string(port) <> "/auth/github/callback",
    )

  let ctx = Context(strategy: strategy, config: cfg)

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
    |> mist.start_http

  io.println(
    "Vestibule demo running on http://localhost:" <> int.to_string(port),
  )
  io.println("Sign in at http://localhost:" <> int.to_string(port) <> "/auth/github")

  process.sleep_forever()
}
```

**Step 2: Verify compilation**

Run from `example/`:

```bash
gleam build
```

Expected: Compiles with no errors.

**Step 3: Smoke test (requires env vars)**

```bash
GITHUB_CLIENT_ID=test GITHUB_CLIENT_SECRET=test gleam run
```

Expected: Server starts, prints URL. The landing page should render at `http://localhost:8000/`. The auth flow won't work with fake credentials, but the server should start.

**Step 4: Commit**

```bash
git add example/src/app.gleam
git commit -m "feat(example): add app entrypoint with env var config and server startup"
```

---

### Task 6: README and Final Verification

**Files:**
- Create: `example/README.md`

**Step 1: Create README**

Create `example/README.md`:

```markdown
# Vestibule Example — GitHub OAuth

A minimal Wisp web app demonstrating vestibule's GitHub OAuth flow.

## Prerequisites

- Gleam 1.14+
- Erlang 27+
- A [GitHub OAuth App](https://github.com/settings/developers)
  - Set the callback URL to `http://localhost:8000/auth/github/callback`

## Setup

```bash
cd example
gleam deps download
```

Set your GitHub OAuth credentials:

```bash
export GITHUB_CLIENT_ID="your_client_id"
export GITHUB_CLIENT_SECRET="your_client_secret"
```

## Run

```bash
gleam run
```

Open http://localhost:8000 and click "Sign in with GitHub".

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_CLIENT_ID` | Yes | — | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | Yes | — | GitHub OAuth App client secret |
| `PORT` | No | 8000 | HTTP server port |
| `SECRET_KEY_BASE` | No | Auto-generated | Secret for signing cookies |
```

**Step 2: Add example to root .gitignore (if needed)**

Ensure `example/build/` is not tracked. Check if the root `.gitignore` covers it or if `example/.gitignore` is needed.

**Step 3: Full verification**

Run from `example/`:

```bash
gleam check
gleam format src test
gleam build
gleam test
```

Expected: All checks pass.

**Step 4: Commit**

```bash
git add example/README.md
git commit -m "docs(example): add README with setup instructions"
```

---

### Task 7: Manual E2E Test

**Files:** None — this is a manual verification.

**Step 1: Start the server with real credentials**

```bash
cd example
export GITHUB_CLIENT_ID="<your_real_client_id>"
export GITHUB_CLIENT_SECRET="<your_real_client_secret>"
gleam run
```

**Step 2: Test the full flow**

1. Open http://localhost:8000 — verify landing page renders
2. Click "Sign in with GitHub" — verify redirect to GitHub
3. Authorize the app on GitHub — verify redirect back to callback
4. Verify success page shows your GitHub uid, name, email, avatar, nickname

**Step 3: Test error cases**

1. Visit http://localhost:8000/auth/github/callback directly (no session) — verify error page
2. Visit a nonexistent route — verify 404

**Step 4: Fix any issues found, commit if needed**

```bash
git add -A
git commit -m "fix(example): address issues found during e2e testing"
```

---

## Summary of Commits

| # | Message | What |
|---|---------|------|
| 1 | `feat(example): scaffold example Wisp project` | gleam.toml + stub entrypoint |
| 2 | `feat(example): add ETS-backed session store` | session.gleam + tests |
| 3 | `feat(example): add HTML pages` | pages.gleam |
| 4 | `feat(example): add router with auth routes` | router.gleam |
| 5 | `feat(example): add app entrypoint` | app.gleam with env config |
| 6 | `docs(example): add README` | setup instructions |
| 7 | `fix(example): e2e testing fixes` | if needed |
