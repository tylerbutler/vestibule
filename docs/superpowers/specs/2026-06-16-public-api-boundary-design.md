# Public API boundary design

## Problem

The root `vestibule` package exposes more public modules than it intends to
support for 1.0. Gleam treats every non-internal module as importable API, and
the root `gleam.toml` currently hides only `vestibule/internal` and
`vestibule/internal/*`. That leaves application API, provider-authoring helpers,
OAuth primitives, and transport plumbing in the same public surface.

Issue #79 narrows that surface before users depend on it.

## Goals

- Publish a clear 1.0 boundary for the root package.
- Keep third-party provider authors as a first-class stable audience.
- Avoid creating a stable transport-integration SDK in 1.0.
- Make generated docs match the intended public API.
- Keep this change focused; do not redesign strategy, errors, config, OIDC, or
  provider-support helper shape in this issue.

## Public surfaces for 1.0

Root `vestibule` should expose two stable surfaces.

### Application API

The application API is for apps that run OAuth flows directly or through the
middleware packages. These modules remain public:

- `vestibule`
- `vestibule/auth`
- `vestibule/authorization_request`
- `vestibule/config`
- `vestibule/credentials`
- `vestibule/error`
- `vestibule/oidc`
- `vestibule/registry`
- `vestibule/state_store`
- `vestibule/user_info`

This issue does not change their signatures. Follow-up issues may still make
some data types more opaque or split config types before 1.0.

### Temporary transport plumbing

`vestibule/transport_flow` remains public for now because `vestibule_wisp` and
`vestibule_mist` are separate packages that import the root package as a
dependency. Marking it internal would break those packages unless this issue also
refactored their callback/request flow code.

Do not bless `transport_flow` as a 1.0 transport SDK in this issue. Instead,
document it as shared middleware plumbing whose final public/internal status is
tracked by issue #85.

### Provider SDK

The provider SDK is for third-party packages that implement OAuth or OIDC
provider strategies. These modules remain public:

- `vestibule/strategy`
- `vestibule/provider_support`

The docs should state that these modules form the supported provider-authoring
surface. `provider_support` remains public for now, but this issue should not
expand or reshape it. Issue #89 can later refine its helper set.

## Internal modules for 1.0

These modules should become internal:

- `vestibule/state`
- `vestibule/pkce`

`state` and `pkce` are primitives used by the root flow, not intended extension
points.

## Documentation changes

The README's API notes should describe the two public surfaces:

- app API for direct flows, registry, state store, OIDC, and result types;
- provider SDK for custom strategy authors.

The README should also state that `transport_flow` is not a finalized public
transport SDK. It remains visible only because the shipped middleware packages
need the shared flow helpers today; issue #85 will decide whether to hide it or
promote it with a stable shape.

The custom strategy guide should stop implying that every visible helper is
general app API. It should import from the provider SDK modules deliberately.
Known stale examples that construct opaque types directly can be fixed in a
follow-up documentation issue if they require broader edits, but this issue
should at least align the guide's boundary language.

## Out of scope

This issue should not:

- make `Auth` or `UserInfo` opaque;
- redesign `Strategy.new`;
- restructure `AuthError`;
- split `Config` into client config and request options;
- move or redesign OIDC discovery;
- rename `provider_support`;
- add a public transport SDK.

Those changes belong to the follow-up issues already filed from the API review.

## Implementation plan

1. Add `vestibule/state` and `vestibule/pkce` to root `internal_modules`.
2. Update README API notes to name the application API and provider SDK.
3. Document `transport_flow` as shared middleware plumbing pending #85, not as a
   stable transport SDK.
4. Update provider-authoring docs enough to reflect the intended module
   boundary.
5. Verify generated docs no longer include the internal primitive modules.
6. Verify root code and Wisp/Mist path-dependency consumers still build.

## Validation

Run:

- `gleam docs build`
- `gleam check`
- `gleam test`
- `cd packages/vestibule_wisp && gleam check`
- `cd packages/vestibule_mist && gleam check`

Success means generated docs exclude `vestibule/state` and `vestibule/pkce`,
while the root package and middleware packages still compile.
