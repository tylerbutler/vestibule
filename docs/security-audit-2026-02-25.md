# Vestibule Security Audit Report

**Date:** 2026-02-25
**Scope:** Full security audit of vestibule OAuth2 library (core, all providers, dependencies)
**Version:** 0.1.0 (pre-release)

## Executive Summary

Vestibule demonstrates solid security fundamentals: PKCE is always-on with S256, CSRF state uses 256-bit entropy with constant-time comparison, and the overall architecture follows OAuth2 best practices. However, several issues were found that should be addressed before production use.

**Finding Summary:** 1 Critical, 1 High, 9 Medium, 9 Low, 13 Info

## Findings by Severity

### CRITICAL

#### C1. Apple JWT ID Token Accepted Without Signature Verification
- **File:** `packages/vestibule_apple/src/vestibule_apple.gleam:148-166`
- **Description:** `decode_id_token` splits the JWT, base64url-decodes the payload, and parses claims but never verifies the signature against Apple's JWKS (`https://appleid.apple.com/auth/keys`).
- **Attack scenario:** An attacker who can modify the token response (MITM, logging proxy, compromised intermediary) can forge arbitrary JWT payloads -- impersonating any Apple user, spoofing emails as verified, or performing account takeover.
- **Mitigating factor:** The token exchange happens over TLS to `appleid.apple.com`, limiting the attack surface.
- **Recommendation:** Implement JWT signature verification against Apple's published JWKS. At minimum, verify `iss`, `aud`, `exp`, and `iat` claims. Also verify `iss == "https://appleid.apple.com"` and `aud == client_id`.

### HIGH

#### H1. Apple ETS Cache TOCTOU Race Condition with Public Access
- **File:** `packages/vestibule_apple/src/vestibule_apple/id_token_cache.gleam:23-31`
- **FFI:** `vestibule_apple_id_token_cache_ffi.erl:8`
- **Description:** The `retrieve` function performs lookup-then-delete as two separate ETS operations. The table is created with `public` access, allowing any BEAM process to read/write/delete.
- **Attack scenario:** (a) Two concurrent callbacks with the same access token could both retrieve the ID token before either deletes it, breaking one-time-use. (b) Any process on the same BEAM node can inject/read/delete cache entries.
- **Recommendation:** Use Erlang's `ets:take/2` for atomic retrieve-and-delete. Change table access from `public` to `protected`.

### MEDIUM

#### M1. Missing URL-Encoding in `refresh_token` Body
- **File:** `src/vestibule.gleam:117-124`
- **Description:** The refresh token request body is built via string concatenation without URL-encoding `refresh_tok`, `client_id`, or `client_secret`.
- **Attack scenario:** If any value contains `&`, `=`, or `+`, the form body is malformed. A refresh token containing `&grant_type=client_credentials` would alter the grant type (parameter injection).
- **Recommendation:** Use `uri.percent_encode()` or `uri.query_to_string()` (already used correctly in `oidc.gleam:352`).

#### M2. No HTTPS Enforcement on URLs
- **Files:** `src/vestibule.gleam`, `src/vestibule/oidc.gleam`, all strategies
- **Description:** Neither config validation nor URL construction checks that endpoints use HTTPS.
- **Recommendation:** Validate HTTPS in `config.new()` for redirect_uri and at strategy construction for token/authorize/userinfo URLs. Allow explicit opt-out for localhost development.

#### M3. HTTP Response Status Code Not Checked
- **Files:** `src/vestibule.gleam:141`, `src/vestibule/oidc.gleam:369-370,396-397`
- **Description:** HTTP responses are parsed regardless of status code. A 500 HTML error or 302 redirect would be fed to the JSON parser.
- **Recommendation:** Check for 2xx status before parsing. Map non-2xx to appropriate error variants.

#### M4. Provider Error Masked by Missing Code Check
- **File:** `src/vestibule.gleam:69-83`
- **Description:** `handle_callback` requires `code` parameter before checking for provider errors. When a provider returns an error (e.g., user denied consent), `code` is absent, so the user sees "Missing code parameter" instead of the actual error.
- **Recommendation:** Check for provider errors before extracting `code`.

#### M5. No State Expiration/Single-Use Enforcement
- **File:** `src/vestibule/state.gleam`
- **Description:** State tokens have no TTL. If a state is captured (browser history, logs), it can be replayed. The wisp middleware's `uset.take` provides one-time use, but the core library doesn't.
- **Recommendation:** Document this as a caller responsibility. Consider adding `state_issued_at` to `AuthorizationRequest`.

#### M6. OIDC Discovery: No URL Scheme Validation (SSRF Potential)
- **File:** `src/vestibule/oidc.gleam:57-62`
- **Description:** `fetch_configuration` accepts any URL, including `http://` or internal addresses. Discovered endpoint URLs are used as-is without HTTPS validation.
- **Recommendation:** Validate HTTPS on issuer URL and all discovered endpoints.

#### M7. Microsoft UPN Fallback as Email Without Verification
- **File:** `packages/vestibule_microsoft/src/vestibule_microsoft.gleam:105-108`
- **Description:** When `mail` is `None`, `userPrincipalName` is used as email. UPNs are not verified email addresses.
- **Recommendation:** Don't use UPN as email, or document that Microsoft emails are unverified. Consider adding `email_verified` to `UserInfo`.

#### M8. Wisp Error Page XSS
- **File:** `packages/vestibule_wisp/src/vestibule_wisp.gleam:134-138`
- **Description:** Error messages from providers are embedded in HTML without escaping. A provider returning `<script>alert(1)</script>` in `error_description` would execute.
- **Recommendation:** HTML-escape all content before embedding.

#### M9. Apple ETS Cache Key is Access Token
- **File:** `packages/vestibule_apple/src/vestibule_apple.gleam:294`
- **Description:** The ID token cache uses the access token as key. Combined with public ETS access, anyone knowing the token can manipulate the cache.
- **Recommendation:** Use a cryptographically random session-scoped key.

### LOW

#### L1. Empty State Bypass (both sides empty)
- **File:** `src/vestibule/state.gleam:18`
- **Description:** `secure_compare("", "")` returns `True`. Only exploitable if the application framework stores empty state.
- **Recommendation:** Add a guard for empty strings.

#### L2. Client Secret in Body Instead of HTTP Basic Auth
- **Files:** `src/vestibule.gleam:117-124`, `src/vestibule/oidc.gleam:340-345`
- **Description:** RFC 6749 prefers HTTP Basic Auth for confidential clients.

#### L3. Credentials Type Exposes Secrets via Debug
- **File:** `src/vestibule/credentials.gleam`
- **Description:** `Credentials` is a plain public record; `io.debug()` would expose tokens.
- **Recommendation:** Consider opaque type or document the risk.

#### L4. No Token Type Validation
- **File:** All strategies
- **Description:** `token_type` is stored but never validated; non-bearer tokens would be incorrectly used with `"Bearer "` prefix.

#### L5. Error Decoder Requires `error_description`
- **File:** `src/vestibule.gleam:155-158`, `packages/vestibule_google/src/vestibule_google.gleam:37-39`
- **Description:** Some providers send errors without `error_description`. The decoder fails, losing the error detail.
- **Recommendation:** Use `decode.optional_field` for `error_description`.

#### L6. Gravatar URL Information Disclosure
- **File:** `packages/vestibule_microsoft/src/vestibule_microsoft.gleam:210-219`
- **Description:** Email hash sent to Gravatar third-party servers by default.

#### L7. Apple form_post Callback Not Handled by Wisp Middleware
- **File:** `packages/vestibule_wisp/src/vestibule_wisp.gleam:110`
- **Description:** `wisp.get_query(req)` only reads URL query params, not POST body. Apple's `response_mode=form_post` sends data in POST body.

#### L8. OIDC Discovery: No HTTP Status Code Check
- **File:** `src/vestibule/oidc.gleam:73-94`

#### L9. Wisp State Store Uses Public ETS
- **File:** `packages/vestibule_wisp/src/vestibule_wisp/state_store.gleam:14`
- **Description:** Uses `bravo.Public`. Should be `bravo.Protected`.

## Dependency Risk Assessment

| Dependency | Version | Risk | Key Concern |
|---|---|---|---|
| **bravo** (git fork) | @ c9e8314 | **HIGH** | Public ETS, git-pinned fork, no TTL, supply chain risk |
| **glow_auth** | 1.0.1 | **MEDIUM** | Single maintainer, no security audit |
| **gleam_httpc** | 5.0.0 | **MEDIUM** | No response size limits; TLS good (verify_peer default) |
| **gleam_crypto** | 1.5.1 | **LOW** | Sound: OpenSSL CSPRNG, constant-time compare |
| **gleam_json** | 3.1.0 | **LOW** | Battle-tested Erlang JSON, trusted inputs |
| **gleam_stdlib** | 0.68.1 | **LOW** | Well-maintained |

**Note:** CVE-2025-32433 (Erlang/OTP SSH RCE, CVSS 10.0) affects OTP's SSH application, not HTTP/BEAM runtime. Ensure deployment uses OTP >= 27.3.3.

## Recommended Security Testing Tools

| Tool | Use Case | Priority |
|---|---|---|
| **Renovate** | Automated dependency updates (has Gleam support) | HIGH |
| **Dialyzer** | BEAM type analysis (via `gleam check`) | HIGH |
| **qcheck** | Property-based testing for Gleam | HIGH |
| **PEST** | Erlang security scanning on BEAM files | MEDIUM |
| **OWASP ZAP** | Dynamic testing of example app | MEDIUM |

### CI Pipeline Additions

1. **Renovate** for dependency updates (native Gleam support)
2. **Property-based tests** with qcheck for crypto operations
3. **OWASP ZAP baseline scan** against example app
4. **EEF Security WG compliance** audit

## Test Coverage Gaps

The following security-focused test file has been added to address gaps:
- `test/vestibule/security_test.gleam` - Core flow security tests
- Provider test files already have good coverage of email verification logic

## Priority Remediation Order

1. **C1** - Apple JWT signature verification
2. **H1** - Apple ETS cache: use `ets:take/2`, change to `protected`
3. **M1** - URL-encode refresh token body
4. **M8** - HTML-escape Wisp error page
5. **M4** - Reorder callback: check provider errors before `code`
6. **M2** - HTTPS enforcement
7. **M3** - HTTP status code checks
8. **M6** - OIDC issuer HTTPS validation
9. **L9** - Wisp state store: change to `bravo.Protected`
