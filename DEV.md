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

This is a multi-package repository. Each package (`vestibule`, `vestibule_apple`,
`vestibule_google`, `vestibule_microsoft`, `vestibule_wisp`, and
`vestibule_mist`) is independently versioned and published to Hex.pm.

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
6. Merge the release PR → the **Publish** workflow runs
   `trellis publish --all-untagged`, which validates and publishes every package
   whose version isn't on Hex yet
7. It then runs `trellis tag create --github-release` to record what shipped as
   per-package tags (e.g., `vestibule-v0.2.0`, `vestibule_apple-v0.1.1`) with a
   GitHub Release each, and opens a follow-up PR refreshing the lockfiles

### Publishing Order

Sub-packages depend on `vestibule` via path references during development.
`trellis publish` walks the dependency graph itself: packages publish in
topological order, so `vestibule` reaches Hex before anything that depends on
it, and each path dependency is rewritten to a Hex requirement derived from the
dependency's current version (`>= X.Y.Z and < (X+1).0.0`) at publish time. The
original `gleam.toml` is restored afterwards, even on failure.

Tags are written **after** a successful publish, so a tag means "this version is
on Hex". Every step checks Hex first and skips what's already there, so
re-running the Publish workflow is the way to recover from a partial failure.

### Workspace Membership

There is no workspace file. Trellis discovers members by finding every
`gleam.toml` git knows about outside `build/`, and the `[tools.trellis]` table in
the root `gleam.toml` marks the workspace root. Adding a package under
`packages/` is enough for it to be built, tested, released, and published —
nothing else needs updating. `just doctor` validates the result.

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
