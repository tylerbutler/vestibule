# Comprehensive Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address the comprehensive code-review findings with a coordinated breaking-change PR that improves safety, API clarity, provider boundaries, tests, and documentation.

**Architecture:** Add a stable `vestibule/provider_support` module for helpers that provider packages need, then migrate providers away from root internals. Make misleading or unsafe public APIs explicit: rename relative token expiration semantics to `expires_in`, add checked initialization paths, validate OIDC config before strategy creation, and expose structured Wisp callback errors below existing response wrappers.

**Tech Stack:** Gleam 1.14, BEAM/Erlang, `startest`, `glow_auth`, `gleam_httpc`, `bravo`, `wisp`, `just`.

---

## File structure

- Create `src/vestibule/provider_support.gleam`: stable public provider-support helpers for HTTP status checks, HTTPS validation, authenticated JSON fetch, redirect parsing, query appending, OAuth token-error checking, and shared token parsing.
- Modify `src/vestibule/internal/http.gleam`: keep a small compatibility wrapper or move implementation to `provider_support`; root internals should not be imported by provider packages.
- Modify `src/vestibule/credentials.gleam`: replace misleading `expires_at` with `expires_in`.
- Modify `src/vestibule.gleam`, `src/vestibule/oidc.gleam`, `src/vestibule/strategy/github.gleam`: update root code for `expires_in`, provider support imports, shared parsing, and OIDC validation.
- Modify `packages/vestibule_google/src/vestibule_google.gleam`, `packages/vestibule_microsoft/src/vestibule_microsoft.gleam`, `packages/vestibule_apple/src/vestibule_apple.gleam`, `packages/vestibule_apple/src/vestibule_apple/jwks.gleam`: migrate to `vestibule/provider_support`, update `expires_in`, remove panic-based URL parsing where practical, and normalize empty scopes.
- Modify `packages/vestibule_wisp/src/vestibule_wisp/state_store.gleam`: add checked initialization and store APIs.
- Modify `packages/vestibule_wisp/src/vestibule_wisp.gleam`: add structured callback errors and keep response wrapper behavior.
- Modify tests under `test/` and `packages/*/test/`: add targeted tests for provider support, strategy helpers, refresh behavior, OIDC validation, provider edge cases, and Wisp behavior.
- Modify docs: `README.md`, `DEV.md`, `example/README.md`, `docs/guides/writing-a-custom-strategy.md`, provider READMEs, and changelogs or release notes where needed.

---

### Task 1: Restore baseline formatting

**Files:**
- Modify: `src/vestibule.gleam`
- Modify: `src/vestibule/internal/http.gleam`
- Modify: `src/vestibule/state.gleam`

- [ ] **Step 1: Run the existing format check**

```bash
just format-check-all
```

Expected: FAIL listing `src/vestibule.gleam`, `src/vestibule/internal/http.gleam`, and `src/vestibule/state.gleam`.

- [ ] **Step 2: Apply repository formatting**

```bash
just format
```

Expected: `gleam format` rewrites the unformatted root files.

- [ ] **Step 3: Verify formatting is clean**

```bash
just format-check-all
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/vestibule.gleam src/vestibule/internal/http.gleam src/vestibule/state.gleam
git commit -m "style: format root gleam sources" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Add stable provider-support module

**Files:**
- Create: `src/vestibule/provider_support.gleam`
- Modify: `src/vestibule/internal/http.gleam`
- Create or modify: `test/vestibule/provider_support_test.gleam`

- [ ] **Step 1: Write provider-support tests**

Create `test/vestibule/provider_support_test.gleam` with focused tests:

```gleam
import gleam/http/response
import startest/expect
import vestibule/error
import vestibule/provider_support

pub fn check_response_status_accepts_2xx_test() {
  response.Response(status: 204, headers: [], body: "ok")
  |> provider_support.check_response_status()
  |> expect.to_equal(Ok("ok"))
}

pub fn check_response_status_rejects_non_2xx_test() {
  let result =
    response.Response(status: 500, headers: [], body: "boom")
    |> provider_support.check_response_status()

  case result {
    Error(error.NetworkError(reason:)) -> reason |> expect.to_equal("HTTP 500: boom")
    _ -> panic as "expected NetworkError"
  }
}

pub fn require_https_accepts_https_test() {
  provider_support.require_https("https://example.com")
  |> expect.to_equal(Ok(Nil))
}

pub fn require_https_allows_localhost_http_test() {
  provider_support.require_https("http://localhost/callback")
  |> expect.to_equal(Ok(Nil))
}

pub fn require_https_rejects_remote_http_test() {
  let result = provider_support.require_https("http://example.com")

  case result {
    Error(error.ConfigError(reason:)) ->
      reason |> expect.to_equal("HTTPS required for endpoint URL: http://example.com")
    _ -> panic as "expected ConfigError"
  }
}

pub fn parse_redirect_uri_rejects_remote_http_test() {
  let result = provider_support.parse_redirect_uri("http://example.com/callback")

  case result {
    Error(error.ConfigError(reason:)) ->
      reason
      |> expect.to_equal("Redirect URI must use HTTPS (except localhost): http://example.com/callback")
    _ -> panic as "expected ConfigError"
  }
}

pub fn append_query_params_preserves_existing_query_test() {
  provider_support.append_query_params("https://example.com/auth?existing=1", [
    #("prompt", "consent"),
  ])
  |> expect.to_equal("https://example.com/auth?existing=1&prompt=consent")
}

pub fn append_query_params_encodes_values_test() {
  provider_support.append_query_params("https://example.com/auth", [
    #("state", "a&b=c"),
  ])
  |> expect.to_equal("https://example.com/auth?state=a%26b%3Dc")
}
```

- [ ] **Step 2: Run tests and verify they fail before implementation**

```bash
gleam test -- --test-name-filter provider_support
```

Expected: FAIL because `vestibule/provider_support` does not exist.

- [ ] **Step 3: Implement `src/vestibule/provider_support.gleam`**

Move the implementation currently in `src/vestibule/internal/http.gleam` into a public module with the same function names. Add a shared token parser API:

```gleam
pub type ScopeParsing {
  RequiredScope(separator: String)
  OptionalScope(separator: String)
  NoScope
}

pub fn parse_oauth_token_response(
  body: String,
  scope_parsing: ScopeParsing,
) -> Result(Credentials, AuthError(e))
```

The parser must:

- call `check_token_error(body)` first;
- require `access_token` and `token_type`;
- decode optional `refresh_token` and optional `expires_in`;
- decode scope according to `ScopeParsing`;
- normalize `""` scope to `[]`;
- return `Credentials(token:, refresh_token:, token_type:, expires_in:, scopes:)`.

- [ ] **Step 4: Keep internal compatibility wrapper**

Replace `src/vestibule/internal/http.gleam` with imports and public forwarding functions to `provider_support`. This keeps root code compiling while provider packages migrate:

```gleam
import vestibule/provider_support

pub fn check_response_status(response) {
  provider_support.check_response_status(response)
}
```

Repeat for `require_https`, `fetch_json_with_auth`, `check_token_error`, `parse_redirect_uri`, and `append_query_params`.

- [ ] **Step 5: Run provider-support tests**

```bash
gleam test -- --test-name-filter provider_support
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/vestibule/provider_support.gleam src/vestibule/internal/http.gleam test/vestibule/provider_support_test.gleam
git commit -m "feat: add stable provider support helpers" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Rename credential expiration semantics to `expires_in`

**Files:**
- Modify: `src/vestibule/credentials.gleam`
- Modify: `src/vestibule.gleam`
- Modify: `src/vestibule/oidc.gleam`
- Modify: `src/vestibule/strategy/github.gleam`
- Modify: `packages/vestibule_google/src/vestibule_google.gleam`
- Modify: `packages/vestibule_microsoft/src/vestibule_microsoft.gleam`
- Modify: `packages/vestibule_apple/src/vestibule_apple.gleam`
- Modify: tests and docs that reference `expires_at`

- [ ] **Step 1: Find current references**

```bash
rg "expires_at|expires_in" src test packages docs README.md DEV.md
```

Expected: existing uses of `expires_at` and token parsing of `expires_in`.

- [ ] **Step 2: Update the credentials type**

Change `src/vestibule/credentials.gleam`:

```gleam
pub type Credentials {
  Credentials(
    token: String,
    refresh_token: Option(String),
    token_type: String,
    /// Seconds until the access token expires, as returned by the provider's
    /// `expires_in` field. This is not an absolute timestamp.
    expires_in: Option(Int),
    scopes: List(String),
  )
}
```

- [ ] **Step 3: Update all constructors and field reads**

Replace every `expires_at:` constructor field with `expires_in:`. Replace every `credentials.expires_at` field read with `credentials.expires_in`.

- [ ] **Step 4: Update tests**

Update test expectations to use `expires_in`. Keep existing numeric expectations unchanged because semantics are still relative seconds.

- [ ] **Step 5: Run root and package checks**

```bash
just check-all
just test-all
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src test packages docs README.md DEV.md
git commit -m "feat!: rename credential expiration field" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Migrate providers to provider support and normalize scopes

**Files:**
- Modify: `src/vestibule/strategy/github.gleam`
- Modify: `src/vestibule/oidc.gleam`
- Modify: `packages/vestibule_google/src/vestibule_google.gleam`
- Modify: `packages/vestibule_microsoft/src/vestibule_microsoft.gleam`
- Modify: `packages/vestibule_apple/src/vestibule_apple.gleam`
- Modify: `packages/vestibule_apple/src/vestibule_apple/jwks.gleam`
- Modify: provider tests

- [ ] **Step 1: Write empty-scope tests**

Add tests in provider test files that parse token responses with an empty `scope` string and expect `scopes: []`:

```gleam
pub fn parse_token_response_empty_scope_test() {
  let body = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"scope\":\"\"}"
  let assert Ok(credentials) = parse_token_response(body)
  credentials.scopes |> expect.to_equal([])
}
```

Use the provider-specific parser name in each package.

- [ ] **Step 2: Run provider tests and verify at least one fails**

```bash
just test-pkg vestibule_google
just test-pkg vestibule_microsoft
gleam test -- --test-name-filter empty_scope
```

Expected: FAIL where scope currently becomes `[""]`.

- [ ] **Step 3: Replace provider imports**

Replace imports of `vestibule/internal/http as internal_http` in provider packages with:

```gleam
import vestibule/provider_support
```

Then replace `internal_http.` calls with `provider_support.` calls.

- [ ] **Step 4: Use shared token parser where behavior matches**

For Google and Microsoft, replace local common credential decoding with:

```gleam
provider_support.parse_oauth_token_response(
  body,
  provider_support.RequiredScope(separator: " "),
)
```

For GitHub, use:

```gleam
provider_support.parse_oauth_token_response(
  body,
  provider_support.RequiredScope(separator: ","),
)
```

For OIDC and refresh parsing, use:

```gleam
provider_support.parse_oauth_token_response(
  body,
  provider_support.OptionalScope(separator: " "),
)
```

Keep Apple-specific parsing where it needs `id_token`, but call `provider_support.check_token_error` and normalize empty scopes.

- [ ] **Step 5: Convert static URL parsing panics to errors**

In provider authorization/exchange/JWKS code, replace `let assert Ok(site) = uri.parse("https://...")` with `result.try` and `error.ConfigError(reason:)`.

- [ ] **Step 6: Run provider tests**

```bash
just test-all
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src packages test
git commit -m "refactor: use provider support across strategies" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: Validate OIDC config construction

**Files:**
- Modify: `src/vestibule/oidc.gleam`
- Modify: `test/vestibule/oidc_test.gleam`
- Modify: docs using `OidcConfig(...)` directly if any

- [ ] **Step 1: Add validation tests**

Add tests to `test/vestibule/oidc_test.gleam`:

```gleam
pub fn new_config_rejects_http_authorization_endpoint_test() {
  let result =
    oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "http://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile"],
    )

  let _ = result |> expect.to_be_error()
  Nil
}

pub fn strategy_from_config_accepts_valid_config_test() {
  let assert Ok(config) =
    oidc.new_config(
      issuer: "https://issuer.example.com",
      authorization_endpoint: "https://issuer.example.com/auth",
      token_endpoint: "https://issuer.example.com/token",
      userinfo_endpoint: "https://issuer.example.com/userinfo",
      scopes_supported: ["openid", "profile", "email"],
    )

  let strategy = oidc.strategy_from_config(config, "issuer")
  strategy.default_scopes |> expect.to_equal(["openid", "profile", "email"])
}
```

- [ ] **Step 2: Run OIDC tests and verify failure**

```bash
gleam test -- --test-name-filter config
```

Expected: FAIL because `oidc.new_config` does not exist or `OidcConfig` remains publicly constructible.

- [ ] **Step 3: Make `OidcConfig` opaque and add constructor/accessors as needed**

Change `pub type OidcConfig` to `pub opaque type OidcConfig`. Add:

```gleam
pub fn new_config(
  issuer issuer: String,
  authorization_endpoint authorization_endpoint: String,
  token_endpoint token_endpoint: String,
  userinfo_endpoint userinfo_endpoint: String,
  scopes_supported scopes_supported: List(String),
) -> Result(OidcConfig, AuthError(e))
```

Inside `new_config`, call `provider_support.require_https` for issuer and all endpoints, then return `Ok(OidcConfig(...))`.

- [ ] **Step 4: Route discovery parsing through the constructor**

After JSON decoding in `parse_discovery_document`, call `new_config(...)` instead of returning the raw constructor. Preserve existing parse error messages for malformed JSON.

- [ ] **Step 5: Run OIDC and full tests**

```bash
gleam test -- --test-name-filter oidc
just test-all
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/vestibule/oidc.gleam test/vestibule/oidc_test.gleam docs README.md
git commit -m "feat!: validate oidc configuration construction" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: Add checked Wisp state-store APIs

**Files:**
- Modify: `packages/vestibule_wisp/src/vestibule_wisp/state_store.gleam`
- Modify: `packages/vestibule_wisp/test/vestibule_wisp_test.gleam`
- Modify: `packages/vestibule_wisp/README.md`
- Modify: `README.md`

- [ ] **Step 1: Add tests for checked init and store**

Add tests:

```gleam
pub fn try_init_named_returns_error_for_duplicate_table_test() {
  let name = "vestibule_wisp_duplicate_test"
  let assert Ok(_) = state_store.try_init_named(name)
  let result = state_store.try_init_named(name)
  let _ = result |> expect.to_be_error()
  Nil
}

pub fn try_store_returns_session_id_test() {
  let assert Ok(store) = state_store.try_init_named("vestibule_wisp_try_store_test")
  let assert Ok(session_id) = state_store.try_store(store, "state", "verifier")
  session_id == "" |> expect.to_equal(False)
}
```

- [ ] **Step 2: Run Wisp tests and verify failure**

```bash
just test-pkg vestibule_wisp
```

Expected: FAIL because checked APIs do not exist.

- [ ] **Step 3: Implement checked APIs**

Add:

```gleam
pub type StateStoreError {
  TableCreateFailed
  InsertFailed
}

pub fn try_init() -> Result(StateStore, StateStoreError)
pub fn try_init_named(name: String) -> Result(StateStore, StateStoreError)
pub fn try_store(
  table: StateStore,
  state: String,
  code_verifier: String,
) -> Result(String, StateStoreError)
```

Update `init`, `init_named`, and `store` to call checked variants and unwrap with clear messages. Keep existing names for compatibility but document once-per-VM behavior.

- [ ] **Step 4: Update Wisp request phase**

In `packages/vestibule_wisp/src/vestibule_wisp.gleam`, call `state_store.try_store`. If storage fails, return `error_response(error.ConfigError(reason: "Failed to store OAuth session state"))`.

- [ ] **Step 5: Run Wisp tests**

```bash
just test-pkg vestibule_wisp
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/vestibule_wisp README.md
git commit -m "feat: add checked wisp state store APIs" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 7: Add checked Apple cache APIs

**Files:**
- Modify: `packages/vestibule_apple/src/vestibule_apple/id_token_cache.gleam`
- Modify: `packages/vestibule_apple/src/vestibule_apple/jwks.gleam`
- Modify: `packages/vestibule_apple/src/vestibule_apple.gleam`
- Modify: `packages/vestibule_apple/test/vestibule_apple_test.gleam`
- Modify: `packages/vestibule_apple/README.md`

- [ ] **Step 1: Add duplicate-init tests**

Add tests that call new checked cache initializers twice with the same name and assert the second call returns `Error`.

- [ ] **Step 2: Run Apple tests and verify failure**

```bash
just test-pkg vestibule_apple
```

Expected: FAIL because checked cache APIs do not exist.

- [ ] **Step 3: Implement checked cache APIs**

Add result-returning variants:

```gleam
pub fn try_init() -> Result(Cache, CacheError)
pub fn try_init_named(name: String) -> Result(Cache, CacheError)
pub fn try_store(cache: Cache, key: String, value: String) -> Result(Nil, CacheError)
```

Use equivalent names for JWKS cache. Keep existing `init` wrappers documented as once-per-VM convenience APIs.

- [ ] **Step 4: Update `vestibule_apple.init`**

Add a checked top-level initializer:

```gleam
pub fn try_init() -> Result(AppleSupport, AppleInitError)
```

Keep `init()` as a wrapper over `try_init()` for existing examples, with explicit docs about startup-only usage.

- [ ] **Step 5: Run Apple tests**

```bash
just test-pkg vestibule_apple
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/vestibule_apple
git commit -m "feat: add checked apple cache initialization" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 8: Add structured Wisp callback errors

**Files:**
- Modify: `packages/vestibule_wisp/src/vestibule_wisp.gleam`
- Modify: `packages/vestibule_wisp/test/vestibule_wisp_test.gleam`
- Modify: `packages/vestibule_wisp/README.md`

- [ ] **Step 1: Add structured error tests**

Add tests for unknown provider and missing session cookie using a new structured API:

```gleam
pub fn callback_phase_auth_result_unknown_provider_test() {
  let result =
    vestibule_wisp.callback_phase_auth_result(
      req,
      registry.new(),
      "unknown",
      state_store,
    )

  result |> expect.to_equal(Error(vestibule_wisp.UnknownProvider("unknown")))
}
```

Use existing Wisp test request helpers or create a minimal request fixture in the test file.

- [ ] **Step 2: Run Wisp tests and verify failure**

```bash
just test-pkg vestibule_wisp
```

Expected: FAIL because `CallbackError` and `callback_phase_auth_result` do not exist.

- [ ] **Step 3: Add error type and structured API**

Add:

```gleam
pub type CallbackError(e) {
  UnknownProvider(provider: String)
  MissingSessionCookie
  SessionExpired
  InvalidCallbackParams
  AuthFailed(error.AuthError(e))
}
```

Add:

```gleam
pub fn callback_phase_auth_result(
  req: Request,
  reg: Registry(e),
  provider: String,
  state_store: StateStore,
) -> Result(Auth, CallbackError(e))
```

Update `callback_phase` and `callback_phase_result` to call the structured function and convert errors to responses with a dedicated renderer.

- [ ] **Step 4: Run Wisp tests**

```bash
just test-pkg vestibule_wisp
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/vestibule_wisp
git commit -m "feat: expose structured wisp callback errors" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 9: Add public strategy helper and refresh tests

**Files:**
- Modify: `test/vestibule_test.gleam`
- Modify: `test/vestibule/refresh_test.gleam`
- Modify: `test/vestibule/strategy_test.gleam` or create `test/vestibule/strategy_test.gleam`
- Modify: `src/vestibule/strategy.gleam` if tests expose behavior gaps
- Modify: `src/vestibule.gleam` if refresh parser migrates to provider support

- [ ] **Step 1: Add strategy helper tests**

Create `test/vestibule/strategy_test.gleam`:

```gleam
import gleam/http/request
import gleam/option
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule/strategy

pub fn authorization_header_accepts_mixed_case_bearer_test() {
  Credentials(
    token: "abc",
    refresh_token: option.None,
    token_type: "BeArEr",
    expires_in: option.None,
    scopes: [],
  )
  |> strategy.authorization_header()
  |> expect.to_equal(Ok("Bearer abc"))
}

pub fn append_code_verifier_encodes_special_chars_test() {
  let assert Ok(req) = request.to("https://example.com/token")

  req
  |> request.set_body("grant_type=authorization_code")
  |> strategy.append_code_verifier(option.Some("a+b/c="))
  |> fn(req) { req.body }
  |> expect.to_equal("grant_type=authorization_code&code_verifier=a%2Bb%2Fc%3D")
}
```

- [ ] **Step 2: Add refresh parser and request-shape tests**

Extend `test/vestibule/refresh_test.gleam` to assert missing scope is accepted, empty scope becomes `[]`, and refresh-token rotation behavior preserves `refresh_token: None` when the provider omits it.

- [ ] **Step 3: Run targeted tests**

```bash
gleam test -- --test-name-filter authorization_header
gleam test -- --test-name-filter refresh
```

Expected: PASS after implementation from previous tasks; if failures appear, fix the helper/parser behavior directly.

- [ ] **Step 4: Commit**

```bash
git add test src/vestibule.gleam src/vestibule/strategy.gleam
git commit -m "test: cover strategy helpers and refresh parsing" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 10: Update documentation for breaking changes and setup gaps

**Files:**
- Modify: `README.md`
- Modify: `DEV.md`
- Modify: `example/README.md`
- Modify: `docs/guides/writing-a-custom-strategy.md`
- Modify: `packages/vestibule_apple/README.md`
- Modify: `packages/vestibule_google/README.md`
- Modify: `packages/vestibule_microsoft/README.md`
- Modify: `packages/vestibule_wisp/README.md`
- Modify: package changelogs if current release process expects entries

- [ ] **Step 1: Fix opaque `Config` examples**

In `docs/guides/writing-a-custom-strategy.md`, replace direct field access with accessor calls:

```gleam
config.client_id(cfg)
config.client_secret(cfg)
config.redirect_uri(cfg)
```

Also replace the local `append_code_verifier` helper with:

```gleam
import vestibule/strategy

let req = strategy.append_code_verifier(req, code_verifier)
```

- [ ] **Step 2: Fix Microsoft avatar docs**

Replace the Gravatar claim with:

```md
Microsoft Graph `/me` does not return profile photos without additional
permissions. The built-in strategy sets `UserInfo.image` to `None`; fetch photos
separately from Microsoft Graph if your app needs them.
```

- [ ] **Step 3: Add Apple client-secret JWT setup**

In `packages/vestibule_apple/README.md`, add a section covering Team ID, Key ID, Services ID/client ID, `.p8` private key, ES256 header, and claims `iss`, `iat`, `exp`, `aud`, and `sub`.

- [ ] **Step 4: Add provider setup notes**

Document:

- Google refresh token params: `access_type=offline`, `prompt=consent`.
- Microsoft `/common` tenant implications and OIDC/custom-strategy alternative for tenant-restricted apps.
- Wisp `vestibule_session` signed cookie TTL of 600 seconds.
- Wisp and Apple once-per-VM init behavior for convenience wrappers.

- [ ] **Step 5: Fix contributor and example docs**

In `DEV.md`, replace unsupported Startest flags with:

```bash
gleam test -- --test-name-filter "test_name"
gleam test -- test/vestibule_test.gleam
```

In `example/README.md`, make `.env` the primary setup path, explain shell exports as an alternative, and note Apple is omitted from the example because it requires a generated client-secret JWT and cache initialization.

- [ ] **Step 6: Add migration notes**

Document breaking changes:

- `Credentials.expires_at` is now `Credentials.expires_in`.
- OIDC configs must be created through `oidc.new_config` or discovery.
- Wisp has a structured callback error API.
- Provider-support helpers are public for custom strategy authors.

- [ ] **Step 7: Commit**

```bash
git add README.md DEV.md example/README.md docs/guides/writing-a-custom-strategy.md packages/*/README.md packages/*/CHANGELOG.md
git commit -m "docs: update review fix guidance and migration notes" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 11: Final validation and PR

**Files:**
- No planned source edits unless validation reveals issues.

- [ ] **Step 1: Run full validation**

```bash
just format-check-all
just check-all
just test-all
just build-strict-all
```

Expected: all commands PASS.

- [ ] **Step 2: Inspect branch diff**

```bash
git --no-pager status --short
git --no-pager diff --stat main...HEAD
git --no-pager log --oneline main..HEAD
```

Expected: clean worktree and commits corresponding to the implementation tasks.

- [ ] **Step 3: Push branch**

```bash
git push -u origin review-fixes-comprehensive
```

Expected: branch pushed.

- [ ] **Step 4: Open PR**

```bash
gh pr create \
  --title "feat!: address comprehensive review findings" \
  --body "## Summary
- add stable provider-support helpers and migrate provider packages away from root internals
- rename credential expiration semantics to expires_in and validate OIDC config construction
- add checked initialization paths and structured Wisp callback errors
- expand tests and update docs for provider setup, migration, and contributor workflows

## Validation
- just format-check-all
- just check-all
- just test-all
- just build-strict-all"
```

Expected: GitHub returns a PR URL.
