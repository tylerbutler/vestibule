# Root vestibule 1.0 hardening design

## Problem

The root `vestibule` package is close to functional readiness, but the 1.0 review found release-blocking issues in public API boundaries, OAuth/security semantics, documentation, and release metadata. The root package should not publish a 1.0 release while accidental test-only helpers, coarse errors, narrow strategy hooks, generic refresh behavior, and pre-1.0 documentation remain part of the public story.

## Scope

This work targets only the root `vestibule` package:

- Root package code in `src/vestibule*.gleam` and `src/vestibule/**`.
- Root tests in `test/**`.
- Root README/API docs and the root-linked custom strategy guide where it teaches root package usage.
- Root changelog readiness.

Sub-packages under `packages/` are out of scope unless a root-linked document references them. The implementation should not release or publish any package.

## Decisions

- Stabilize aggressively before 1.0. Breaking changes are acceptable when they prevent accidental or unsafe contracts from becoming stable.
- Keep the actual `gleam.toml` version bump under the release workflow. This branch should make the package 1.0-ready without manually publishing or tagging a release.
- Implement the changes as one focused root-package hardening pass with tests and docs updated together.

## Proposed architecture

Make the root public API boundary explicit before 1.0:

- Treat `Strategy` as the provider extension contract and adjust it so providers can participate in user-info enrichment, provider extras, and refresh behavior without root hardcoding provider-specific assumptions.
- Replace coarse stringly errors with structured variants for callback parameter failures, HTTP failures, decoding failures, and provider errors that need stable consumer handling.
- Stop exposing functions as public only because tests need them. Parser helpers should either be intentionally supported public helpers or moved behind internal/public-support boundaries with clear documentation.
- Preserve simple data-carrier records only where the fields are intended to be stable.

## Security and correctness behavior

The root OAuth flow should be misuse-resistant:

- Refresh token handling must not send client secrets or refresh tokens to unvalidated token URLs. Provider-specific refresh behavior should live in strategy-controlled code or be explicitly constrained and validated.
- Extra authorization parameters must not duplicate reserved OAuth/PKCE parameters such as `state`, `redirect_uri`, `client_id`, `response_type`, `code_challenge`, or `code_challenge_method`.
- URL validation must require hosts for HTTPS URLs and continue to allow HTTP only for local development hosts.
- OIDC discovery must default to an OIDC-safe scope set when `scopes_supported` is absent and must construct well-known discovery URLs correctly for path-based issuers.
- Error values should avoid encouraging consumers to log raw token/userinfo response bodies.

## Documentation and release readiness

Root documentation should communicate 1.0 readiness without performing the release:

- Replace the README pre-1.0 warning with a stability/support statement suitable for the release branch.
- Add or prepare the root `CHANGELOG.md` path so changie has a durable root changelog target for release entries.
- Convert intended module introductions to Gleam module docs so generated HexDocs have useful module descriptions.
- Update quickstart security guidance for HTTPS redirect URIs, server-side state storage, one-time-use state, and state expiration.
- Document `UserInfo.email` verification semantics.
- Update the root-linked custom strategy guide to match the final 1.0 extension contract.

## Testing and validation

Use test-driven changes for behavior and API semantics:

- Add focused root tests before changing behavior.
- Cover URL validation, reserved extra params, refresh behavior, structured callback errors, OIDC discovery defaults/path handling, parser visibility/support decisions, and provider extra data behavior.
- Run root validation after implementation: `gleam format --check src test`, `gleam check`, `gleam test`, and `gleam docs build`.

## Non-goals

- Publishing a 1.0 release.
- Changing sub-package runtime behavior.
- Rewriting all provider packages.
- Adding new tools or test frameworks.
- Preserving accidental public APIs solely for backward compatibility with pre-1.0 versions.
