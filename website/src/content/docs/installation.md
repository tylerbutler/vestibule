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

> **Pre-1.0:** Vestibule has not reached version 1.0. A minor release can change
> the API. Read the release notes before you update your application's tag.

Install Vestibule packages from
[GitHub](https://github.com/tylerbutler/vestibule). **The packages are not
available on Hex.** Add these Git dependencies to `gleam.toml`:

```toml
[dependencies]
vestibule = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0" }
vestibule_github = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_github" }
vestibule_wisp = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_wisp" }
```

Download the dependencies:

```bash
gleam deps download
```

`gleam add` installs packages from Hex. It cannot install Vestibule. Add the Git
dependency entries to `gleam.toml`.

## Packages

A typical application requires `vestibule` and one provider strategy. Add one
middleware integration if your application uses Wisp or Mist.

| Package | Add it when |
|---|---|
| `vestibule` | Always: core OAuth2 flow, shared types, PKCE, state validation, and token refresh |
| `vestibule_github` | Users sign in with GitHub |
| `vestibule_google` | Users sign in with Google |
| `vestibule_microsoft` | Users sign in with Microsoft |
| `vestibule_apple` | Users sign in with Apple |
| `vestibule_indieauth` | Users sign in through IndieAuth |
| `vestibule_oidc` | You discover an OpenID Connect provider from its issuer |
| `vestibule_wisp` | Your application uses Wisp |
| `vestibule_mist` | Your application uses Mist directly |

For each companion package, use the same `git` and `ref` values. Set `path` to
`packages/<package_name>`.

## Requirements

- **Gleam:** 1.18.0 or later for installation
- **Target:** Erlang (BEAM)

### Why Gleam 1.18?

Vestibule is a monorepo. Companion packages are in subdirectories such as
`packages/vestibule_github` and `packages/vestibule_wisp`. The `path` field
selects a package subdirectory. Gleam added this field for Git dependencies in
version 1.18. Older Gleam versions cannot install companion packages.

This requirement applies when Gleam resolves the dependencies. The packages
support older compiler versions. However, you must use Gleam 1.18 or later to
install them from this monorepo.

## Choosing a ref

The examples use the moving `v0` major tag. This tag points to the newest
pre-1.0 release. Because minor releases can contain breaking changes before
1.0, read the release notes when the tag moves. Use the same ref for all
Vestibule packages in your application. Do not mix package versions.

See [GitHub Releases](https://github.com/tylerbutler/vestibule/releases) for
immutable release tags and release notes.
