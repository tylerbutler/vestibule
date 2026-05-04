# Comprehensive review fixes design

## Problem

The comprehensive review found production-safety, API clarity, module-boundary, test coverage, and documentation issues across the Vestibule core package and provider packages. Some fixes are intentionally breaking because they correct misleading contracts or expose currently implicit behavior.

## Goals

- Restore repository health by fixing formatting failures.
- Replace panic-prone public initialization paths with recoverable or idempotent APIs.
- Stop independently published provider packages from depending on root internal modules.
- Make token expiration semantics clear and type/API names accurate.
- Enforce OIDC discovery/security invariants when creating OIDC strategies.
- Reduce provider drift by centralizing reusable OAuth token/query helpers where practical.
- Improve Wisp callback error handling with a structured lower-level API.
- Add targeted tests for public helpers, refresh behavior, HTTP helpers, OIDC validation, provider edge cases, and Wisp middleware behavior.
- Update user and contributor documentation that is stale, incomplete, or currently compile-breaking.

## Non-goals

- Rewriting every provider from scratch.
- Adding new third-party tools or test frameworks.
- Changing provider behavior unrelated to the review findings.
- Publishing a release from this branch.

## Proposed architecture

Introduce a stable provider-support surface in the root package for helpers that provider packages need. Provider packages should import this public module instead of `vestibule/internal/*`. Internals remain available only for root implementation details.

Refine public APIs that currently hide important behavior:

- Initialization APIs should expose `Result`-returning variants, with convenience wrappers retained only where they are explicitly documented as startup-only.
- Token expiration should be represented as `expires_in` or otherwise clearly documented as relative seconds.
- OIDC configuration should be validated at construction or before strategy creation so callers cannot bypass discovery safety checks with manually constructed values.
- Wisp should expose a structured callback-result API beneath the current rendered-response convenience path.

Where provider flows duplicate the same OAuth mechanics, extract shared pure helpers for token response parsing and query parameter construction. Keep provider-specific behavior explicit through configuration or small provider-local wrappers.

## Components

1. **Provider support module**
   - Public helper module for response-status checks, token-error checks, authenticated JSON fetch, redirect URI parsing, query parameter appending, and shared token parsing.
   - Provider packages migrate from root internals to this module.

2. **Credentials model**
   - Rename or replace the misleading `expires_at` field with relative expiration semantics.
   - Update parser code, tests, docs, and examples.

3. **Initialization and caches**
   - Add recoverable initialization APIs for Wisp state store and Apple caches.
   - Document once-per-VM behavior for any retained assert-based convenience wrappers.

4. **OIDC validation**
   - Prevent unvalidated `OidcConfig` values from producing strategies.
   - Preserve discovery as the preferred safe path.

5. **Wisp callback errors**
   - Add a structured error type for callback failures.
   - Keep existing response-rendering helpers as wrappers.

6. **Tests**
   - Cover public strategy helpers, shared HTTP/provider-support helpers, refresh behavior, OIDC validation, provider scope parsing, Apple JWT edge cases where feasible, and Wisp callback/session/error behavior.

7. **Documentation**
   - Fix compile-breaking custom strategy guide snippets.
   - Document Apple client-secret JWT setup.
   - Document Google refresh-token parameters and Microsoft tenant limitations.
   - Clarify Wisp/Apple initialization behavior and Wisp callback cookie TTL.
   - Fix stale Startest command examples in `DEV.md`.
   - Clarify example app setup and Apple omission.

## Error handling

Fallible operations should return `Result` with project-specific error types or existing `AuthError` variants. Public functions should not use `let assert` for runtime-dependent operations such as ETS table creation, cache insertions, request construction, or URL parsing unless they are explicitly convenience wrappers over checked APIs.

## Testing and validation

Use existing repository commands only:

- `just format-check-all`
- `just check-all`
- `just test-all`
- `just build-strict-all`

Run targeted package tests while iterating, then the full monorepo checks before opening the PR.

## Compatibility notes

This PR may contain breaking public API changes. Documentation should call out migration points for renamed credential fields, OIDC construction changes, and any Wisp callback API additions or replacements.
