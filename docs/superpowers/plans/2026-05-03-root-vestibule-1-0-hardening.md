# Root Vestibule 1.0 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the root `vestibule` package ready for a 1.0 release by finalizing public API boundaries, tightening OAuth/security behavior, and updating root documentation/release artifacts.

**Architecture:** Move provider-specific refresh and user enrichment into the `Strategy` contract, add a structured `UserResult` so `Auth.extra` can be populated intentionally, and replace coarse string errors with pattern-matchable variants. Keep version bumping in release automation, but make docs, changelog path, tests, and generated docs 1.0-ready.

**Tech Stack:** Gleam 1.14, BEAM/Erlang, `gleam_httpc`, `gleam_json`, `glow_auth`, `startest`, existing `gleam`/`just` commands.

---

## File structure

- Modify `src/vestibule/error.gleam`: add structured callback, HTTP, decode, and provider-error fields while preserving custom-error mapping.
- Modify `src/vestibule/strategy.gleam`: add `UserResult` and make `Strategy.fetch_user` receive `Config`; add strategy-owned `refresh_token`.
- Modify `src/vestibule.gleam`: use structured callback errors, delegate refresh to strategy, populate `Auth.extra`, and append PKCE params structurally.
- Modify `src/vestibule/config.gleam`: validate/reject reserved extra authorization params.
- Modify `src/vestibule/provider_support.gleam`: require HTTPS URLs to have hosts, return structured HTTP/decode errors, add safe token-refresh helper for strategies.
- Modify `src/vestibule/oidc.gleam`: use `UserResult`, fix OIDC default scopes, construct path-based discovery URLs correctly, and update parser helper policy.
- Modify `src/vestibule/strategy/github.gleam`: implement the new strategy contract and provider-owned refresh.
- Modify `src/vestibule/user_info.gleam`, `src/vestibule/credentials.gleam`, `src/vestibule/pkce.gleam`, `src/vestibule/state.gleam`, `src/vestibule/authorization_request.gleam`: update module/field docs where needed.
- Modify root tests under `test/**`: add failing tests for each API/security behavior before implementation, then update existing tests for the new public API.
- Modify `README.md`, `CHANGELOG.md`, and `docs/guides/writing-a-custom-strategy.md`: update root 1.0 readiness guidance.

---

### Task 1: Establish baseline and formatting

**Files:**
- Modify: `src/vestibule.gleam`
- Modify: `src/vestibule/internal/http.gleam`
- Modify: `src/vestibule/provider_support.gleam`
- Modify: `src/vestibule/state.gleam`

- [ ] **Step 1: Run root baseline checks**

```bash
gleam format --check src test
gleam check
gleam test
gleam docs build
```

Expected: format check fails for currently unformatted root files; check/test/docs pass.

- [ ] **Step 2: Apply formatting**

```bash
gleam format src test
```

Expected: root source/test files are formatted.

- [ ] **Step 3: Verify formatting**

```bash
gleam format --check src test
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src test
git commit -m "style: format root vestibule sources" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Add structured errors

**Files:**
- Modify: `src/vestibule/error.gleam`
- Modify: `test/vestibule/security_test.gleam`
- Modify: `test/vestibule/provider_support_test.gleam`
- Modify: `test/vestibule/refresh_test.gleam`
- Modify: `test/vestibule/oidc_test.gleam`

- [ ] **Step 1: Write failing tests for structured errors**

Add tests that assert the stable error shape:

```gleam
pub fn missing_callback_state_is_structured_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "https://localhost/cb")
  let result =
    vestibule.handle_callback(strat, conf, dict.new(), "expected", "verifier")

  result
  |> expect.to_equal(Error(error.MissingCallbackParam("state")))
}

pub fn http_error_preserves_status_without_full_body_test() {
  let result =
    response.Response(status: 500, headers: [], body: string.repeat("x", 200))
    |> provider_support.check_response_status()

  case result {
    Error(error.HttpError(status:, body:)) -> {
      status |> expect.to_equal(500)
      { string.length(body) <= 120 } |> expect.to_be_true()
    }
    _ -> panic as "expected HttpError"
  }
}

pub fn malformed_token_response_returns_decode_error_test() {
  provider_support.parse_oauth_token_response(
    "not json",
    provider_support.OptionalScope(" "),
  )
  |> expect.to_be_error()
  |> expect.to_equal(error.DecodeError(context: "token response", reason: "UnexpectedByte(\"0x6F\")"))
}
```

- [ ] **Step 2: Run targeted tests to verify failure**

```bash
gleam test -- --test-name-filter "structured|http_error|decode_error|missing_callback"
```

Expected: FAIL because the new error constructors do not exist yet.

- [ ] **Step 3: Implement structured errors**

Update `src/vestibule/error.gleam`:

```gleam
pub type AuthError(e) {
  StateMismatch
  MissingCallbackParam(name: String)
  CodeExchangeFailed(reason: String)
  UserInfoFailed(reason: String)
  ProviderError(code: String, description: String, uri: option.Option(String))
  NetworkError(reason: String)
  HttpError(status: Int, body: String)
  DecodeError(context: String, reason: String)
  ConfigError(reason: String)
  Custom(e)
}
```

Update `map_custom` to copy all variants unchanged except `Custom(e)`.

- [ ] **Step 4: Update error construction sites**

Change:

```gleam
error.ProviderError(code: code, description: description)
```

to:

```gleam
error.ProviderError(code: code, description: description, uri: option.None)
```

Change malformed JSON parser failures in token/refresh response parsers to:

```gleam
error.DecodeError(context: "token response", reason: string.inspect(err))
```

Keep semantic failures such as code exchange network/provider failures under their existing high-level variants.

- [ ] **Step 5: Run root tests**

```bash
gleam test
```

Expected: PASS after updating existing tests for the new `ProviderError(..., uri:)` and structured decode/http variants.

- [ ] **Step 6: Commit**

```bash
git add src/vestibule/error.gleam src/vestibule.gleam src/vestibule/provider_support.gleam src/vestibule/oidc.gleam src/vestibule/strategy/github.gleam test
git commit -m "feat: add structured auth errors" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Finalize strategy-owned user and refresh contracts

**Files:**
- Modify: `src/vestibule/strategy.gleam`
- Modify: `src/vestibule.gleam`
- Modify: `src/vestibule/strategy/github.gleam`
- Modify: `src/vestibule/oidc.gleam`
- Modify: `test/vestibule_test.gleam`
- Modify: `test/vestibule/strategy_test.gleam`
- Modify: `test/vestibule/refresh_test.gleam`
- Modify: `test/vestibule/oidc_test.gleam`
- Modify: `test/vestibule/strategy/github_test.gleam`

- [ ] **Step 1: Write failing tests for `Auth.extra` and strategy-owned refresh**

In `test/vestibule_test.gleam`, update the fake strategy to return extra data:

```gleam
fetch_user: fn(_config, _creds) {
  Ok(strategy.UserResult(
    uid: "user123",
    info: UserInfo(
      name: Some("Test User"),
      email: Some("test@example.com"),
      nickname: None,
      image: None,
      description: None,
      urls: dict.new(),
    ),
    extra: dict.from_list([#("raw_id", dynamic.string("user123"))]),
  ))
},
refresh_token: fn(_config, refresh_token) {
  Ok(Credentials(
    token: "new_" <> refresh_token,
    refresh_token: Some(refresh_token),
    token_type: "bearer",
    expires_in: None,
    scopes: [],
  ))
},
```

Add assertions:

```gleam
pub fn handle_callback_populates_strategy_extra_test() {
  let strat = test_strategy()
  let conf = config.new("id", "secret", "https://localhost/cb")
  let state = "state"
  let params = dict.from_list([#("code", "valid_code"), #("state", state)])
  let assert Ok(auth) =
    vestibule.handle_callback(strat, conf, params, state, "verifier")

  dict.has_key(auth.extra, "raw_id") |> expect.to_be_true()
}

pub fn refresh_token_delegates_to_strategy_test() {
  vestibule.refresh_token(test_strategy(), config.new("id", "secret", "https://localhost/cb"), "refresh")
  |> expect.to_equal(Ok(Credentials(
    token: "new_refresh",
    refresh_token: Some("refresh"),
    token_type: "bearer",
    expires_in: None,
    scopes: [],
  )))
}
```

- [ ] **Step 2: Run targeted tests to verify failure**

```bash
gleam test -- --test-name-filter "extra|refresh_token_delegates"
```

Expected: FAIL because `strategy.UserResult` and `Strategy.refresh_token` do not exist.

- [ ] **Step 3: Implement `UserResult` and new `Strategy` fields**

Update `src/vestibule/strategy.gleam`:

```gleam
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}

pub type UserResult {
  UserResult(uid: String, info: UserInfo, extra: Dict(String, Dynamic))
}

pub type Strategy(e) {
  Strategy(
    provider: String,
    default_scopes: List(String),
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError(e)),
    exchange_code: fn(Config, String, Option(String)) ->
      Result(Credentials, AuthError(e)),
    refresh_token: fn(Config, String) -> Result(Credentials, AuthError(e)),
    fetch_user: fn(Config, Credentials) -> Result(UserResult, AuthError(e)),
  )
}
```

Remove `token_url` from the public strategy record. Token URLs become provider implementation details.

- [ ] **Step 4: Update root flow**

In `src/vestibule.gleam`, change user fetch:

```gleam
use user <- result.try(strategy.fetch_user(cfg, credentials))

Ok(Auth(
  uid: user.uid,
  provider: strategy.provider,
  info: user.info,
  credentials: credentials,
  extra: user.extra,
))
```

Change refresh:

```gleam
pub fn refresh_token(
  strategy: Strategy(e),
  cfg: Config,
  refresh_tok: String,
) -> Result(Credentials, AuthError(e)) {
  strategy.refresh_token(cfg, refresh_tok)
}
```

- [ ] **Step 5: Update GitHub and OIDC strategies**

For strategies that have no extra data, return `dict.new()`:

```gleam
Ok(strategy.UserResult(uid: uid, info: info, extra: dict.new()))
```

Add provider-owned refresh implementations using provider-specific token parsing and HTTPS-known endpoints. For OIDC, use the discovered token endpoint. For GitHub, use the existing GitHub token endpoint and existing GitHub parser.

- [ ] **Step 6: Run root tests**

```bash
gleam test
```

Expected: PASS after updating all fake strategies and strategy tests for the new record fields.

- [ ] **Step 7: Commit**

```bash
git add src/vestibule/strategy.gleam src/vestibule.gleam src/vestibule/strategy/github.gleam src/vestibule/oidc.gleam test
git commit -m "feat: stabilize strategy extension contract" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Harden config params, URL validation, and PKCE appending

**Files:**
- Modify: `src/vestibule/config.gleam`
- Modify: `src/vestibule/provider_support.gleam`
- Modify: `src/vestibule.gleam`
- Modify: `test/vestibule/config_test.gleam`
- Modify: `test/vestibule/provider_support_test.gleam`
- Modify: `test/vestibule/security_test.gleam`

- [ ] **Step 1: Write failing tests**

Add tests:

```gleam
pub fn with_extra_params_rejects_reserved_oauth_params_test() {
  let c = config.new("id", "secret", "https://localhost/callback")

  config.with_extra_params(c, [#("prompt", "consent"), #("state", "evil")])
  |> expect.to_equal(Error(error.ConfigError(reason: "Reserved authorization parameter: state")))
}

pub fn require_https_rejects_https_without_host_test() {
  provider_support.require_https("https:path")
  |> expect.to_equal(Error(error.ConfigError(reason: "URL must include a host: https:path")))
}

pub fn parse_redirect_uri_rejects_https_without_host_test() {
  provider_support.parse_redirect_uri("https:path")
  |> expect.to_equal(Error(error.ConfigError(reason: "Redirect URI must include a host: https:path")))
}

pub fn authorize_url_appends_pkce_before_fragment_test() {
  let strat =
    Strategy(
      provider: "fragment",
      default_scopes: [],
      authorize_url: fn(_, _, _) { Ok("https://example.com/auth#frag") },
      exchange_code: fn(_, _, _) { Error(error.CodeExchangeFailed("unused")) },
      refresh_token: fn(_, _) { Error(error.CodeExchangeFailed("unused")) },
      fetch_user: fn(_, _) { Error(error.UserInfoFailed("unused")) },
    )

  let assert Ok(req) =
    vestibule.authorize_url(strat, config.new("id", "secret", "https://localhost/cb"))

  string.contains(req.url, "code_challenge=") |> expect.to_be_true()
  string.ends_with(req.url, "#frag") |> expect.to_be_true()
}
```

- [ ] **Step 2: Run targeted tests to verify failure**

```bash
gleam test -- --test-name-filter "reserved|without_host|fragment"
```

Expected: FAIL because existing APIs allow reserved params, hostless HTTPS, and string-based fragment appending.

- [ ] **Step 3: Change `Config.with_extra_params` to return `Result`**

Update signature:

```gleam
pub fn with_extra_params(
  config: Config,
  params: List(#(String, String)),
) -> Result(Config, AuthError(e))
```

Reject reserved keys:

```gleam
const reserved_authorization_params = [
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
]
```

Return `Ok(Config(..config, extra_params: dict.from_list(params)))` when all keys are safe.

- [ ] **Step 4: Require URL hosts**

In `provider_support.require_https` and `provider_support.parse_redirect_uri`, after parsing HTTPS URLs require `parsed.host` to be `Some(_)`; return `ConfigError` when missing.

- [ ] **Step 5: Append PKCE params structurally**

Replace string concatenation in `append_pkce_params` with URI parsing:

```gleam
fn append_pkce_params(url: String, code_challenge: String) -> Result(String, AuthError(e)) {
  use parsed <- result.try(uri.parse(url) |> result.replace_error(error.ConfigError(reason: "Invalid authorization URL: " <> url)))
  let existing = parsed.query |> option.unwrap("")
  let pkce_query = uri.query_to_string([
    #("code_challenge", code_challenge),
    #("code_challenge_method", "S256"),
  ])
  let query = case existing {
    "" -> pkce_query
    existing -> existing <> "&" <> pkce_query
  }
  Ok(uri.to_string(uri.Uri(..parsed, query: option.Some(query))))
}
```

Update `authorize_url` to use `result.try(append_pkce_params(...))`.

- [ ] **Step 6: Update callers of `with_extra_params`**

Change examples/tests from:

```gleam
config.new("id", "secret", "https://localhost/cb")
|> config.with_extra_params([#("prompt", "consent")])
```

to:

```gleam
let assert Ok(conf) =
  config.new("id", "secret", "https://localhost/cb")
  |> config.with_extra_params([#("prompt", "consent")])
```

- [ ] **Step 7: Run root tests**

```bash
gleam test
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/vestibule/config.gleam src/vestibule/provider_support.gleam src/vestibule.gleam test
git commit -m "feat: harden authorization URL inputs" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: Fix OIDC discovery defaults and path handling

**Files:**
- Modify: `src/vestibule/oidc.gleam`
- Modify: `test/vestibule/oidc_test.gleam`

- [ ] **Step 1: Write failing OIDC tests**

Add tests:

```gleam
pub fn filter_default_scopes_defaults_to_openid_when_metadata_missing_test() {
  oidc.filter_default_scopes([])
  |> expect.to_equal(["openid"])
}

pub fn strategy_from_config_defaults_to_openid_when_scopes_missing_test() {
  let assert Ok(oidc_config) =
    oidc.new_config(
      issuer: "https://accounts.example.com",
      authorization_endpoint: "https://accounts.example.com/authorize",
      token_endpoint: "https://accounts.example.com/token",
      userinfo_endpoint: "https://accounts.example.com/userinfo",
      scopes_supported: [],
    )

  let strat = oidc.strategy_from_config(oidc_config, "example")
  strat.default_scopes |> expect.to_equal(["openid"])
}

pub fn discovery_url_places_well_known_before_path_test() {
  oidc.discovery_url("https://example.com/tenant")
  |> expect.to_equal("https://example.com/.well-known/openid-configuration/tenant")
}
```

- [ ] **Step 2: Run targeted tests to verify failure**

```bash
gleam test -- --test-name-filter "openid|discovery_url"
```

Expected: FAIL because empty supported scopes currently produce `[]`, and `discovery_url` is not public/implemented.

- [ ] **Step 3: Implement OIDC defaults**

Update `filter_default_scopes`:

```gleam
pub fn filter_default_scopes(scopes_supported: List(String)) -> List(String) {
  case scopes_supported {
    [] -> ["openid"]
    scopes_supported -> {
      let desired = ["openid", "profile", "email"]
      let filtered = list.filter(desired, fn(scope) {
        list.contains(scopes_supported, scope)
      })
      case filtered {
        [] -> ["openid"]
        scopes -> scopes
      }
    }
  }
}
```

- [ ] **Step 4: Implement spec-compliant discovery URL helper**

Add public helper for testability and custom callers:

```gleam
pub fn discovery_url(issuer_url: String) -> Result(String, AuthError(e)) {
  use parsed <- result.try(
    uri.parse(strip_trailing_slash(issuer_url))
    |> result.replace_error(error.ConfigError(reason: "Invalid issuer URL: " <> issuer_url)),
  )
  let issuer_path = parsed.path
  let well_known_path = case issuer_path {
    "" | "/" -> "/.well-known/openid-configuration"
    path -> "/.well-known/openid-configuration" <> path
  }
  Ok(uri.to_string(uri.Uri(..parsed, path: well_known_path, query: option.None, fragment: option.None)))
}
```

Update `fetch_configuration` to call `discovery_url(issuer_url)`.

- [ ] **Step 5: Run OIDC tests**

```bash
gleam test -- --test-name-filter oidc
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/vestibule/oidc.gleam test/vestibule/oidc_test.gleam
git commit -m "fix: harden oidc discovery defaults" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: Decide parser helper visibility and docs

**Files:**
- Modify: `src/vestibule.gleam`
- Modify: `src/vestibule/oidc.gleam`
- Modify: `src/vestibule/strategy/github.gleam`
- Modify: `src/vestibule/provider_support.gleam`
- Modify: `test/vestibule/refresh_test.gleam`
- Modify: `test/vestibule/oidc_test.gleam`
- Modify: `test/vestibule/strategy/github_test.gleam`

- [ ] **Step 1: Choose the stable parser policy**

Use this policy:

- `provider_support.parse_oauth_token_response` remains public and stable for custom strategy authors.
- Provider-specific parser helpers remain public when they are useful compatibility/support helpers, but docs must describe them as supported parsing helpers rather than “Exported for testing.”
- Root `vestibule.parse_refresh_response` is removed or deprecated from public docs because refresh is strategy-owned.

- [ ] **Step 2: Update tests to call supported helpers**

Where refresh parser tests currently call:

```gleam
vestibule.parse_refresh_response(body)
```

change them to:

```gleam
provider_support.parse_oauth_token_response(
  body,
  provider_support.OptionalScope(" "),
)
```

- [ ] **Step 3: Update parser helper docs**

Replace comments like:

```gleam
/// Exported for testing.
```

with:

```gleam
/// Parse a provider token response.
///
/// This helper is public so custom strategy authors and tests can reuse the
/// same parsing behavior as the built-in strategy.
```

- [ ] **Step 4: Run root tests**

```bash
gleam test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src test
git commit -m "docs: clarify supported parser helpers" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 7: Update root docs and changelog readiness

**Files:**
- Create: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `docs/guides/writing-a-custom-strategy.md`
- Modify: public module docs in `src/vestibule*.gleam` and `src/vestibule/**/*.gleam`

- [ ] **Step 1: Create root changelog skeleton**

Create `CHANGELOG.md`:

```markdown
# Changelog

All notable changes to the root `vestibule` package are documented here.

This file is managed by changie during releases. Unreleased changes are stored
in `.changes/unreleased/`.
```

- [ ] **Step 2: Update README stability statement**

Replace the pre-1.0 warning with:

```markdown
> [!NOTE]
> Vestibule follows semantic versioning. The 1.0 release stabilizes the root
> package API for strategy-based OAuth flows. Security-sensitive behavior such
> as redirect URI validation, state handling, and PKCE defaults is documented
> below and covered by tests.
```

- [ ] **Step 3: Add quickstart security guidance**

Add after the low-level quickstart:

```markdown
For production, redirect URIs must use HTTPS. `http://localhost` and
`http://127.0.0.1` are accepted only for local development. Store the generated
state and PKCE verifier server-side, bind them to the user session, expire them,
and delete them after a successful callback.
```

- [ ] **Step 4: Document `UserInfo.email` semantics**

Add field docs in `src/vestibule/user_info.gleam`:

```gleam
/// Email address when the strategy considers it verified.
///
/// This field is provider-dependent and may be `None` when the provider did
/// not return an email, the required scope was missing, the email was
/// unverified, or a best-effort secondary email request failed.
email: Option(String),
```

- [ ] **Step 5: Convert module introductions to module docs**

Use `////` module docs at the top of public modules currently using top-level `///` introductions, including `src/vestibule.gleam`, `src/vestibule/oidc.gleam`, `src/vestibule/provider_support.gleam`, and `src/vestibule/pkce.gleam`.

- [ ] **Step 6: Update custom strategy guide**

Update `docs/guides/writing-a-custom-strategy.md` to:

- use a 1.0-compatible dependency range;
- use `provider_support.parse_redirect_uri`;
- use `provider_support.check_response_status`;
- use `strategy.authorization_header`;
- use the final `Strategy` record shape with `refresh_token` and `fetch_user(Config, Credentials)`;
- describe public parser helpers as supported helpers, not test-only exports.

- [ ] **Step 7: Build docs**

```bash
gleam docs build
```

Expected: PASS and generated docs show module-level descriptions.

- [ ] **Step 8: Commit**

```bash
git add README.md CHANGELOG.md docs/guides/writing-a-custom-strategy.md src
git commit -m "docs: prepare root vestibule for 1.0" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 8: Final root validation and review

**Files:**
- Modify only files required by failures found in this task.

- [ ] **Step 1: Run root validation**

```bash
gleam format --check src test
gleam check
gleam test
gleam docs build
```

Expected: PASS.

- [ ] **Step 2: Inspect root-only diff**

```bash
git --no-pager diff --stat HEAD~7..HEAD
git --no-pager diff -- src test README.md CHANGELOG.md docs/guides/writing-a-custom-strategy.md
```

Expected: diff is limited to root package hardening scope and root-linked docs.

- [ ] **Step 3: Request code review**

Dispatch a code-review agent with this scope:

```text
Review only the root vestibule 1.0 hardening changes. Focus on public API stability, OAuth/security behavior, docs accuracy, and whether the implementation matches docs/superpowers/specs/2026-05-03-root-vestibule-1-0-hardening-design.md.
```

- [ ] **Step 4: Fix any Critical or Important review findings**

For each valid finding, add a focused test if behavior-related, implement the fix, rerun:

```bash
gleam format --check src test
gleam check
gleam test
gleam docs build
```

Expected: PASS.

- [ ] **Step 5: Commit final fixes if needed**

```bash
git add src test README.md CHANGELOG.md docs/guides/writing-a-custom-strategy.md
git commit -m "fix: address root vestibule 1.0 review feedback" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Only run this commit if Step 4 produced changes.
