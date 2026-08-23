---
title: Installation
description: Install Vestibule packages from GitHub with Gleam 1.18 or later.
nav:
  group: Start
  groupOrder: 0
  order: 5
  label: Installation
toc:
  - href: "#packages"
    label: Packages
  - href: "#requirements"
    label: Requirements
  - href: "#why-gleam-118"
    label: Why Gleam 1.18?
  - href: "#choosing-a-ref"
    label: Choosing a ref
searchTerms:
  - install
  - installation
  - GitHub
  - Hex
  - git dependency
  - path dependency
  - Gleam 1.18
---

# Installation

> **Pre-1.0:** Vestibule is not yet version 1.0. Minor releases can change the
> API. Review release notes before updating the tag used by your application.

Install Vestibule packages from
[GitHub](https://github.com/tylerbutler/vestibule). **None of the packages are
published on Hex.** Add them as Git dependencies in `gleam.toml`:

```toml
[dependencies]
vestibule = { git = "https://github.com/tylerbutler/vestibule.git", ref = "vestibule-v0.0" }
vestibule_github = { git = "https://github.com/tylerbutler/vestibule.git", ref = "vestibule-v0.0", path = "packages/vestibule_github" }
vestibule_wisp = { git = "https://github.com/tylerbutler/vestibule.git", ref = "vestibule-v0.0", path = "packages/vestibule_wisp" }
```

Then download the dependencies:

```bash
gleam deps download
```

`gleam add` installs Hex packages, so it cannot install Vestibule. Add the Git
dependency entries by hand.

## Packages

A typical application needs `vestibule`, one provider strategy, and optionally
one middleware integration.

| Package | Add it when |
|---|---|
| `vestibule` | Always — core OAuth2 flow, shared types, PKCE, state validation, and token refresh |
| `vestibule_github` | Users sign in with GitHub |
| `vestibule_google` | Users sign in with Google |
| `vestibule_microsoft` | Users sign in with Microsoft |
| `vestibule_apple` | Users sign in with Apple |
| `vestibule_indieauth` | Users sign in through IndieAuth |
| `vestibule_oidc` | You discover an OpenID Connect provider from its issuer |
| `vestibule_wisp` | Your application uses Wisp |
| `vestibule_mist` | Your application uses Mist directly |

For a companion package, use the same `git` and `ref` values shown above and
set `path` to `packages/<package_name>`.

## Requirements

- **Gleam:** 1.18.0 or later for installation
- **Target:** Erlang (BEAM)

### Why Gleam 1.18?

Vestibule is a monorepo. Companion packages live in subdirectories such as
`packages/vestibule_github` and `packages/vestibule_wisp`. Git dependencies use
the `path` field to select one of those subdirectories, and Gleam added Git path
dependencies in version 1.18. Older Gleam versions cannot install the companion
packages.

This requirement applies to the Gleam version that resolves the dependencies.
The packages themselves declare support for older compiler versions, but you
need Gleam 1.18 or later to use the Git dependency entries above.

## Choosing a ref

The examples use the moving `vestibule-v0.0` series tag. It tracks the newest
compatible release in the 0.0 series. Use the same ref for every Vestibule
package in your application; do not mix package versions.

See [GitHub Releases](https://github.com/tylerbutler/vestibule/releases) for
immutable release tags and release notes.
