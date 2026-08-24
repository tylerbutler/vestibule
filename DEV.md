# Development Guide

This document provides detailed instructions for developing and contributing to this project.

## Prerequisites

Ensure you have the following installed:

| Tool | Version | Purpose |
|------|---------|---------|
| Erlang/OTP | 27.2.1+ | BEAM runtime |
| Gleam | 1.16.0+ | Compiler and tooling |
| just | 1.38.0+ | Task runner |

**Recommended:** Use [mise](https://mise.jdx.dev/) or [asdf](https://asdf-vm.com/) with the provided `.tool-versions` file.

```bash
# With mise
mise install

# With asdf
asdf install
```

## Getting Started

```bash
# Clone the repository
git clone https://github.com/tylerbutler/vestibule.git
cd vestibule

# Install dependencies
just deps

# Run the same checks expected before a PR
just ci
```

## Development Workflow

### Daily Development

```bash
# Check every package compiles
just check

# Run all package tests
just test

# Format code (do this before committing)
just format
```

### Before Committing

```bash
# Run full CI checks locally
just pr
```

### Before Merging to Main

```bash
# Run extended checks
just main
```

## Project Structure

```
.
├── src/
│   ├── vestibule.gleam               # Main public API
│   └── vestibule/                    # Submodules
│       ├── auth.gleam                # Authentication result types
│       ├── config.gleam              # OAuth provider config
│       ├── credentials.gleam         # Token/expiry data
│       ├── error.gleam               # Shared error variants
│       ├── oidc.gleam                # OIDC discovery + generic strategy
│       ├── pkce.gleam                # PKCE utilities
│       ├── registry.gleam            # Multi-provider registry
│       ├── state.gleam               # CSRF state generation/validation
│       ├── strategy.gleam            # Strategy interface
│       ├── user_info.gleam           # Normalized user profile
│       └── strategy/                 # Built-in strategies
│           └── github.gleam          # GitHub OAuth strategy
├── test/
│   └── vestibule/                    # Tests
├── packages/
│   ├── vestibule_apple/              # Apple Sign In strategy
│   ├── vestibule_google/             # Google OAuth strategy
│   ├── vestibule_microsoft/          # Microsoft OAuth strategy
│   ├── vestibule_wisp/               # Wisp middleware
│   └── vestibule_mist/               # Mist middleware
├── example/                          # Example OAuth app
├── .github/
│   ├── actions/setup/                # Reusable CI setup
│   └── workflows/                    # CI/CD pipelines
├── gleam.toml                        # Package configuration
├── justfile                          # Task definitions
└── .tool-versions                    # Tool version pinning
```

## Code Style

### Formatting

This project uses Gleam's built-in formatter. Format your code before committing:

```bash
just format
```

### Error Handling

Always use Result types for fallible operations:

```gleam
// Good
pub fn parse(input: String) -> Result(Value, ParseError)

// Avoid: functions that can fail but don't return Result
pub fn parse(input: String) -> Value  // Don't do this
```

### Pattern Matching

Gleam enforces exhaustive pattern matching. Handle all cases:

```gleam
case result {
  Ok(value) -> handle_success(value)
  Error(ParseError(msg)) -> handle_parse_error(msg)
  Error(ValidationError(field)) -> handle_validation_error(field)
}
```

### Documentation

Document all public functions with `///` comments:

```gleam
/// Parses the input string into a Value.
///
/// ## Examples
///
/// ```gleam
/// parse("hello")
/// // -> Ok(Value("hello"))
/// ```
///
/// ## Errors
///
/// Returns `ParseError` if the input is malformed.
pub fn parse(input: String) -> Result(Value, ParseError)
```

## Testing

### Running Tests

```bash
# Run all package tests
just test

# Backwards-compatible alias for all package tests
just test-all
```

### Writing Tests

Tests use the `startest` framework:

```gleam
import startest/expect

pub fn my_feature_test() {
  my_function("input")
  |> expect.to_equal(expected_output)
}
```

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Code style (formatting) |
| `refactor` | Code refactoring |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `build` | Build system changes |
| `ci` | CI/CD changes |
| `chore` | Maintenance tasks |

### Examples

```bash
feat(parser): add support for nested objects
fix(validation): handle empty strings correctly
docs: update installation instructions
test: add edge case tests for unicode handling
```

## Release Process

This is a multi-package repository. Trellis independently versions, tags, and
releases the releasable packages. The `example` app and the `vestibule_apple`,
`vestibule_google`, `vestibule_microsoft`, and `vestibule_oidc` providers stay
full workspace members — normal tasks still build and test them — but their
paths are listed under `exclude."@release"` in the root `gleam.toml`, so they
are never versioned or tagged. That leaves a release set of `vestibule`,
`vestibule_github`, `vestibule_indieauth`, `vestibule_mist`, and
`vestibule_wisp`; `trellis doctor` prints the split.

### Adding Changelog Entries

Changelog entries are TOML fragments in `.changes/unreleased/`, managed by
[trellis](https://trellis.tylerbutler.com/docs/changelog/). `trellis changelog
new` is non-interactive, so the package, kind, and body are all arguments:

```bash
# just change <package> <kind> "What changed"
just change vestibule Added "Add a nonce to the authorization request"
just change vestibule_apple Fixed "Refresh the JWKS cache on a key rotation"

# Preview the version bumps the pending fragments imply
just changelog-preview

# Validate the workspace: membership, fragments, versions, lockfiles
just doctor
```

Kinds are configured under `[tools.trellis.changelog]` in the root `gleam.toml`:
`Breaking`, `Added`, `Changed`, `Deprecated`, `Fixed`, `Performance`, `Removed`,
`Reverted`, `Dependencies`, `Security`. `Breaking` is a minor bump while the
packages are pre-1.0; `Added` is a minor and everything else a patch. Override a
derived version for one release with `trellis version apply --bump <pkg>=major`
or `--set <pkg>=1.0.0` rather than editing the config.

Each `CHANGELOG.md` is a **generated** file — the source of truth is the version
sections under `.changes/<package>/`, which `trellis version apply` reassembles.
Edit fragments, not changelogs.

### Release Flow

1. Make changes following the commit message convention
2. Add a changelog entry for each affected package (`just change ...`)
3. Push to a feature branch and create a PR
4. After merge to main, the **Release** workflow runs `trellis release pr`,
   batching every package with pending fragments into a single release PR
5. The release PR bumps versions in each package's `gleam.toml`, regenerates the
   per-package `CHANGELOG.md` files, and patches the locked workspace versions in
   every `manifest.toml`. Packages that path-depend on a bumped package are
   bumped too, with a generated `Dependencies` entry
6. Merge the release PR → the **Release** workflow records the release with
   `trellis tag create --github-release`. Nothing is uploaded to Hex; see
   [Publishing](#publishing)

### Tags

A release writes three kinds of tag, all configured under
`[tools.trellis.publish]`:

| Tag | Scope | Lifecycle |
| --- | --- | --- |
| `vestibule-v0.0.1` | One per releasable package (`package_tags = ["exact"]`) | Immutable. Created once, never rewritten, carries the GitHub Release bodied from the matching CHANGELOG section. |
| `v0.0` | One minor tag for the whole repository (`repository_tags = ["major", "minor"]`, keyed to `vestibule`'s version) | Moving. Force-moved to the newest release in that minor series. Carries no GitHub Release. |
| `v0` | One major tag for the whole repository | Moving. Force-moved to the newest release in that major series. Carries no GitHub Release. |

There are no per-package *series* tags: `package_tags = ["exact"]` writes only
exact-version package tags. The repo-wide `v{series}` tags provide both major
and minor moving refs for all packages.

The tag values are derived from the version: `0.0.1` moves both `v0` and
`v0.0`, while `0.1.0` moves `v0` and `v0.1`. A prerelease moves no repository
tag.

`trellis tag plan` lists the tags the current versions call for and don't have
yet, both kinds included.

### Publishing

**Releases are git-only.** `[tools.trellis.publish.lifecycle]` in the root
`gleam.toml` sets `default = "git_only"`, putting every package on the git
lifecycle: a release is tags plus GitHub Releases, and nothing is uploaded to
Hex. The Release workflow has no publish step at all, because `trellis publish`
only ever selects `hex`-lifecycle packages and there are none.

Turning Hex publishing on means moving the packages to the `hex` lifecycle,
adding a `trellis publish --all-untagged` step with `HEXPM_API_KEY`, and
restoring a lockfile refresh — the note at the top of
`.github/workflows/publish.yml` spells it out.

Once it is on: sub-packages depend on `vestibule` via path references during
development, and `trellis publish` walks the dependency graph itself. Packages
publish in topological order, so `vestibule` reaches Hex before anything that
depends on it, and each path dependency is rewritten to a Hex requirement
derived from the dependency's current version (`>= X.Y.Z and < (X+1).0.0`) at
publish time. The original `gleam.toml` is restored afterwards, even on failure.
Every step checks Hex first and skips what's already there, so re-running the
workflow is the way to recover from a partial failure.

### Workspace Membership

There is no workspace file. Trellis discovers members by finding every
`gleam.toml` git knows about outside `build/`, and the `[tools.trellis]` table in
the root `gleam.toml` marks the workspace root. Adding a package under `packages/` is enough for it to be discovered, built,
and tested. Unless its path is listed under `exclude."@release"`, it is also
versioned and tagged. `just doctor` validates the result.

## Troubleshooting

### Build Errors

```bash
# Clean build artifacts and rebuild
just clean
just deps
just build
```

### Test Failures

```bash
# Run a specific test by name
gleam test -- --test-name-filter "test_name"

# Run tests from one file
gleam test -- test/vestibule_test.gleam
```

### Dependency Issues

```bash
# Update dependencies
gleam deps update

# Check for outdated dependencies
gleam deps list
```

## Getting Help

- Check the [Gleam documentation](https://gleam.run/documentation/)
- Join the [Gleam Discord](https://discord.gg/Fm8Pwmy)
- Open an issue on GitHub
