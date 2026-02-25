# Wisp Middleware — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a `vestibule_wisp` package that provides middleware for handling the OAuth two-phase flow in Wisp applications, with built-in ETS-based CSRF state storage.

**Architecture:** `vestibule_wisp` lives in `packages/vestibule_wisp/` and depends on both `vestibule` and `wisp`. It contains a state store module (ETS via Erlang FFI) and a middleware module with `request_phase`/`callback_phase` functions that handle provider lookup, state management, cookie handling, and error responses. The example app is updated to use the middleware, replacing its hand-rolled `session.gleam` and shrinking `router.gleam`.

**Tech Stack:** Gleam 1.14+, wisp, vestibule, gleam_crypto (for session IDs), startest

**Design doc:** `docs/plans/2026-02-24-wisp-middleware-design.md`

---

### Task 1: Create vestibule_wisp package — State Store

**Files:**
- Create: `packages/vestibule_wisp/gleam.toml`
- Create: `packages/vestibule_wisp/src/vestibule_wisp/state_store.gleam`
- Create: `packages/vestibule_wisp/src/vestibule_wisp_state_store_ffi.erl`
- Create: `packages/vestibule_wisp/test/vestibule_wisp_test.gleam`

**Step 1: Create gleam.toml**

Create `packages/vestibule_wisp/gleam.toml`:

```toml
name = "vestibule_wisp"
version = "0.1.0"
description = "Wisp middleware for vestibule OAuth authentication"
licences = ["MIT"]
repository = { type = "github", user = "tylerbutler", repo = "vestibule", path = "packages/vestibule_wisp" }
gleam = ">= 1.7.0"

[dependencies]
vestibule = { path = "../.." }
wisp = ">= 2.2.0 and < 3.0.0"
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_http = ">= 4.3.0 and < 5.0.0"
gleam_json = ">= 3.1.0 and < 4.0.0"
gleam_crypto = ">= 1.5.0 and < 2.0.0"

[dev-dependencies]
startest = ">= 0.8.0 and < 1.0.0"
```

**Step 2: Create the Erlang FFI for ETS operations**

Create `packages/vestibule_wisp/src/vestibule_wisp_state_store_ffi.erl`:

```erlang
-module(vestibule_wisp_state_store_ffi).
-export([create_table/1, insert/3, lookup/2, delete_key/2]).

create_table(Name) ->
    Atom = binary_to_atom(Name, utf8),
    case ets:whereis(Atom) of
        undefined ->
            ets:new(Atom, [set, public, named_table]),
            nil;
        _Ref ->
            nil
    end.

insert(Name, Key, Value) ->
    Atom = binary_to_atom(Name, utf8),
    ets:insert(Atom, {Key, Value}),
    nil.

lookup(Name, Key) ->
    Atom = binary_to_atom(Name, utf8),
    case ets:lookup(Atom, Key) of
        [{_Key, Value}] -> {ok, Value};
        [] -> {error, nil}
    end.

delete_key(Name, Key) ->
    Atom = binary_to_atom(Name, utf8),
    ets:delete(Atom, Key),
    nil.
```

**Step 3: Write failing tests for state store**

Create `packages/vestibule_wisp/test/vestibule_wisp_test.gleam`:

```gleam
import startest
import startest/expect
import vestibule_wisp/state_store

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn store_and_retrieve_state_test() {
  state_store.init()
  let state = "test-csrf-state-value"
  let session_id = state_store.store(state)
  state_store.retrieve(session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(state)
}

pub fn retrieve_deletes_after_use_test() {
  state_store.init()
  let session_id = state_store.store("one-time-state")
  let _ = state_store.retrieve(session_id)
  state_store.retrieve(session_id)
  |> expect.to_be_error()
}

pub fn retrieve_unknown_returns_error_test() {
  state_store.init()
  state_store.retrieve("nonexistent-session-id")
  |> expect.to_be_error()
}
```

**Step 4: Run tests to verify they fail**

```bash
cd packages/vestibule_wisp && gleam test
```

Expected: Compilation error — `vestibule_wisp/state_store` module not found.

**Step 5: Implement state store**

Create `packages/vestibule_wisp/src/vestibule_wisp/state_store.gleam`:

```gleam
import gleam/bit_array
import gleam/crypto

const table_name = "vestibule_wisp_sessions"

/// Initialize the state store. Call once at application startup.
/// Safe to call multiple times.
pub fn init() -> Nil {
  do_create_table(table_name)
}

/// Store a CSRF state value and return a session ID.
/// The session ID should be set as a signed cookie.
pub fn store(state: String) -> String {
  let session_id =
    crypto.strong_random_bytes(16)
    |> bit_array.base64_url_encode(False)
  do_insert(table_name, session_id, state)
  session_id
}

/// Retrieve and consume a CSRF state by session ID.
/// Returns Error(Nil) if not found or already consumed (one-time use).
pub fn retrieve(session_id: String) -> Result(String, Nil) {
  case do_lookup(table_name, session_id) {
    Ok(value) -> {
      do_delete(table_name, session_id)
      Ok(value)
    }
    Error(Nil) -> Error(Nil)
  }
}

@external(erlang, "vestibule_wisp_state_store_ffi", "create_table")
fn do_create_table(name: String) -> Nil

@external(erlang, "vestibule_wisp_state_store_ffi", "insert")
fn do_insert(name: String, key: String, value: String) -> Nil

@external(erlang, "vestibule_wisp_state_store_ffi", "lookup")
fn do_lookup(name: String, key: String) -> Result(String, Nil)

@external(erlang, "vestibule_wisp_state_store_ffi", "delete_key")
fn do_delete(name: String, key: String) -> Nil
```

**Step 6: Run tests to verify they pass**

```bash
cd packages/vestibule_wisp && gleam test
```

Expected: 3 tests pass.

**Step 7: Commit**

```bash
git add packages/vestibule_wisp/
git commit -m "feat(vestibule_wisp): add ETS-based CSRF state store

Built-in state storage for OAuth CSRF state parameters using Erlang
ETS tables. Provides init/store/retrieve with one-time-use semantics."
```

---

### Task 2: Middleware — request_phase and callback_phase

**Files:**
- Create: `packages/vestibule_wisp/src/vestibule_wisp.gleam`

**Step 1: Implement the middleware module**

Create `packages/vestibule_wisp/src/vestibule_wisp.gleam`:

```gleam
import gleam/dict
import wisp.{type Request, type Response}

import vestibule
import vestibule/auth.{type Auth}
import vestibule/error.{type AuthError}
import vestibule/registry.{type Registry}
import vestibule_wisp/state_store

/// Phase 1: Redirect user to the OAuth provider.
///
/// Looks up the provider in the registry, generates an authorization URL,
/// stores the CSRF state in the state store, sets a signed session cookie,
/// and returns a redirect response.
///
/// Returns 404 if the provider is not registered.
pub fn request_phase(
  req: Request,
  registry: Registry(e),
  provider: String,
) -> Response {
  case registry.get(registry, provider) {
    Error(Nil) -> wisp.not_found()
    Ok(#(strategy, config)) ->
      case vestibule.authorize_url(strategy, config) {
        Ok(#(url, state)) -> {
          let session_id = state_store.store(state)
          wisp.redirect(url)
          |> wisp.set_cookie(
            req,
            "vestibule_session",
            session_id,
            wisp.Signed,
            600,
          )
        }
        Error(err) -> error_response(err)
      }
  }
}

/// Phase 2: Handle the OAuth callback and return the Auth result
/// to the provided callback function.
///
/// Reads the session cookie, retrieves the CSRF state, validates
/// the callback parameters, exchanges the code for credentials,
/// and fetches user info. On success, calls `on_success` with
/// the `Auth` result — you decide what response to return.
///
/// Returns an error page for missing cookies, expired sessions,
/// or authentication failures.
///
/// Returns 404 if the provider is not registered.
pub fn callback_phase(
  req: Request,
  registry: Registry(e),
  provider: String,
  on_success: fn(Auth) -> Response,
) -> Response {
  case do_callback(req, registry, provider) {
    Ok(auth) -> on_success(auth)
    Error(response) -> response
  }
}

/// Phase 2 (Result variant): Handle the OAuth callback and return
/// either the Auth result or an error Response.
///
/// Use this instead of `callback_phase` when you want to handle
/// errors yourself rather than using the default error pages.
pub fn callback_phase_result(
  req: Request,
  registry: Registry(e),
  provider: String,
) -> Result(Auth, Response) {
  do_callback(req, registry, provider)
}

fn do_callback(
  req: Request,
  registry: Registry(e),
  provider: String,
) -> Result(Auth, Response) {
  case registry.get(registry, provider) {
    Error(Nil) -> Error(wisp.not_found())
    Ok(#(strategy, config)) -> {
      case wisp.get_cookie(req, "vestibule_session", wisp.Signed) {
        Error(Nil) ->
          Error(error_response(error.ConfigError(
            reason: "Missing session cookie",
          )))
        Ok(session_id) ->
          case state_store.retrieve(session_id) {
            Error(Nil) ->
              Error(error_response(error.ConfigError(
                reason: "Session expired or already used",
              )))
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
                Ok(auth) -> Ok(auth)
                Error(err) -> Error(error_response(err))
              }
            }
          }
      }
    }
  }
}

fn error_response(err: AuthError(e)) -> Response {
  let message = case err {
    error.StateMismatch -> "State mismatch — possible CSRF attack"
    error.CodeExchangeFailed(reason:) -> "Code exchange failed: " <> reason
    error.UserInfoFailed(reason:) -> "User info fetch failed: " <> reason
    error.ProviderError(code:, description:) ->
      "Provider error [" <> code <> "]: " <> description
    error.NetworkError(reason:) -> "Network error: " <> reason
    error.ConfigError(reason:) -> "Configuration error: " <> reason
    error.Custom(_) -> "Custom provider error"
  }
  wisp.html_response(
    "<html>
<head><title>Authentication Error</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authentication Failed</h1>
  <p style=\"color: #c0392b;\">"
      <> message
      <> "</p>
  <a href=\"/\">Try again</a>
</body>
</html>",
    400,
  )
}
```

Note: The `registry` parameter in `request_phase` shadows the `registry` module import. Use qualified access `registry.get(registry, provider)`. If the compiler complains about the shadowing, rename the parameter to `reg` instead.

**Step 2: Verify compilation**

```bash
cd packages/vestibule_wisp && gleam build
```

Expected: Compiles with no errors.

**Step 3: Run existing tests to make sure nothing broke**

```bash
cd packages/vestibule_wisp && gleam test
```

Expected: 3 state store tests still pass.

**Step 4: Commit**

```bash
git add packages/vestibule_wisp/src/vestibule_wisp.gleam
git commit -m "feat(vestibule_wisp): add request_phase and callback_phase middleware

request_phase handles provider lookup, authorize URL generation, state
storage, and redirect. callback_phase handles cookie/state validation,
code exchange, user info fetch, and error pages. Also provides
callback_phase_result for custom error handling."
```

---

### Task 3: Update Example App to Use Middleware

**Files:**
- Modify: `example/gleam.toml`
- Modify: `example/src/vestibule_example.gleam`
- Modify: `example/src/router.gleam`
- Delete: `example/src/session.gleam`
- Delete: `example/src/session_ffi.erl`

**Step 1: Add vestibule_wisp dependency to example**

Add to `example/gleam.toml` under `[dependencies]`:

```toml
vestibule_wisp = { path = "../packages/vestibule_wisp" }
```

Remove the `gleam_crypto` dependency (was only used by session.gleam):

Remove:
```toml
gleam_crypto = ">= 1.5.0 and < 2.0.0"
```

**Step 2: Update vestibule_example.gleam**

Replace `import session` with `import vestibule_wisp/state_store`.
Replace `session.create_table()` with `state_store.init()`.

The full updated file:

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
import vestibule/config
import vestibule/registry
import vestibule/strategy/github
import vestibule_google
import vestibule_microsoft
import vestibule_wisp/state_store

pub fn main() {
  let port =
    envoy.get("PORT")
    |> result.try(int.parse)
    |> result.unwrap(8000)
  let secret_key_base =
    envoy.get("SECRET_KEY_BASE")
    |> result.unwrap("development-secret-key-base-change-in-production-please")
  let callback_base = "http://localhost:" <> int.to_string(port)

  // Build registry with available providers
  let reg = registry.new()

  let reg = case
    envoy.get("GITHUB_CLIENT_ID"),
    envoy.get("GITHUB_CLIENT_SECRET")
  {
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

  let reg = case
    envoy.get("MICROSOFT_CLIENT_ID"),
    envoy.get("MICROSOFT_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: microsoft")
      registry.register(
        reg,
        vestibule_microsoft.strategy(),
        config.new(id, secret, callback_base <> "/auth/microsoft/callback"),
      )
    }
    _, _ -> reg
  }

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

  // Require at least one provider
  case registry.providers(reg) {
    [] -> {
      io.println("Error: No OAuth providers configured.")
      io.println("Set GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET,")
      io.println("MICROSOFT_CLIENT_ID + MICROSOFT_CLIENT_SECRET, and/or")
      io.println("GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET in your .env file.")
      panic as "No providers configured"
    }
    _ -> Nil
  }

  let ctx = Context(registry: reg)

  // Initialize state store
  state_store.init()

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

**Step 3: Simplify router.gleam with middleware**

Replace `example/src/router.gleam` entirely:

```gleam
import gleam/http
import wisp.{type Request, type Response}

import pages
import vestibule/registry.{type Registry}
import vestibule_wisp

/// Application context passed to the router.
pub type Context(e) {
  Context(registry: Registry(e))
}

/// Route incoming requests.
pub fn handle_request(req: Request, ctx: Context(e)) -> Response {
  use <- wisp.log_request(req)

  case wisp.path_segments(req), req.method {
    // Landing page
    [], http.Get -> pages.landing(registry.providers(ctx.registry))

    // Phase 1: Redirect to provider
    ["auth", provider], http.Get ->
      vestibule_wisp.request_phase(req, ctx.registry, provider)

    // Phase 2: Handle callback
    ["auth", provider, "callback"], http.Get ->
      vestibule_wisp.callback_phase(req, ctx.registry, provider, fn(auth) {
        pages.success(auth)
      })

    // Everything else
    _, _ -> wisp.not_found()
  }
}
```

**Step 4: Remove the pages.error function from pages.gleam**

The error rendering is now handled by the middleware. Remove the `error` function and its dependency on `vestibule/error`:

Remove from `example/src/pages.gleam`:
- The `import vestibule/error.{type AuthError}` import
- The entire `pub fn error(err: AuthError(e)) -> wisp.Response` function

**Step 5: Delete old session files**

```bash
rm example/src/session.gleam
rm example/src/session_ffi.erl
```

**Step 6: Verify example compiles**

Note: The example needs rebar3 in PATH:
```bash
export PATH="/Users/tylerbu/.local/share/mise/installs/rebar/3.26.0/bin:$PATH"
```

```bash
cd example && gleam build
```

Expected: Compiles with no errors.

**Step 7: Update example tests**

The session tests in `example/test/session_test.gleam` tested the old session module. Delete the file since state_store is tested in the vestibule_wisp package:

```bash
rm example/test/session_test.gleam
```

Check if `example/test/vestibule_example_test.gleam` has any remaining test infrastructure that needs updating (it contains the startest main function).

**Step 8: Run example tests**

```bash
cd example && gleam test
```

Expected: Compiles and runs (0 tests if session tests were the only ones, or remaining tests pass).

**Step 9: Commit**

```bash
git add example/ packages/vestibule_wisp/
git commit -m "feat(example): use vestibule_wisp middleware

Replace hand-rolled session management and OAuth routing with
vestibule_wisp.request_phase and callback_phase. Router shrinks
from ~90 lines to ~30. Delete session.gleam and session_ffi.erl."
```

---

### Task 4: Verification and Cleanup

**Step 1: Format all packages**

```bash
gleam format src test
cd packages/vestibule_wisp && gleam format src test
cd ../vestibule_microsoft && gleam format src test
cd ../vestibule_google && gleam format src test
cd ../../example && gleam format src test
```

**Step 2: Run all tests**

```bash
cd /path/to/worktree
gleam test
cd packages/vestibule_wisp && gleam test
cd ../vestibule_microsoft && gleam test
cd ../vestibule_google && gleam test
export PATH="/Users/tylerbu/.local/share/mise/installs/rebar/3.26.0/bin:$PATH"
cd ../../example && gleam build && gleam test
```

Expected:
- Core: 25 tests pass
- vestibule_wisp: 3 tests pass
- vestibule_microsoft: 6 tests pass
- vestibule_google: 6 tests pass
- Example: compiles and any remaining tests pass

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
| 1 | `feat(vestibule_wisp): add ETS-based CSRF state store` | State store + FFI + tests |
| 2 | `feat(vestibule_wisp): add request_phase and callback_phase middleware` | Middleware module |
| 3 | `feat(example): use vestibule_wisp middleware` | Example app simplification |
| 4 | `style: apply gleam format` | If needed |
