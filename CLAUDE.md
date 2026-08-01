# vestibule

## Project Overview

A Gleam library/application targeting the Erlang (BEAM) runtime.

## Build Commands

```bash
gleam build              # Compile project
gleam test               # Run tests
gleam check              # Type check without building
gleam format src test    # Format code
gleam docs build         # Generate documentation
gleam run                # Run (if executable)
```

## Just Commands

```bash
just deps              # Download dependencies
just build             # Build all packages
just test              # Run tests for all packages
just test-all          # Alias for all package tests
just test-pkg <pkg>    # Run tests for a specific sub-package
just format            # Format code
just format-check      # Check formatting
just check             # Type check all packages
just docs              # Build documentation for all packages
just ci                # Run all CI checks (format, check, test, build)
just pr                # Alias for ci (use before PR)
just main              # Extended checks for main branch
just change <pkg> <kind> <body>  # Create a changelog entry
just changelog-preview # Show the version bumps the pending fragments imply
just changelog-apply   # Apply the release locally (bump, render, patch lockfiles)
just doctor            # Validate workspace invariants
just clean             # Remove build artifacts
```

## Project Structure

```
src/
├── vestibule.gleam                   # Main public API
└── vestibule/                        # Submodules
    ├── auth.gleam                    # Authentication result types
    ├── config.gleam                  # OAuth provider config
    ├── strategy.gleam                # Strategy interface
    └── internal/                     # Private implementation
packages/
├── vestibule_apple/                  # Apple Sign In strategy
├── vestibule_github/                 # GitHub OAuth strategy
├── vestibule_google/                 # Google OAuth strategy
├── vestibule_indieauth/             # IndieAuth strategy (decentralized identity)
├── vestibule_microsoft/              # Microsoft OAuth strategy
├── vestibule_wisp/                   # Wisp middleware
└── vestibule_mist/                   # Mist middleware
example/                              # Example OAuth app
test/
└── vestibule_test.gleam
```

## Architecture

### Module Organization

- **Main module** (`vestibule.gleam`): Public API, re-exports from submodules
- **Submodules** (`vestibule/*.gleam`): Feature-specific implementations
- **Internal modules**: Mark with `internal_modules` in `gleam.toml`

### Error Handling

Use Result types for all fallible operations:

```gleam
pub fn parse(input: String) -> Result(Value, ParseError) {
  // ...
}
```

### Pattern Matching

Gleam enforces exhaustive pattern matching. Always handle all cases:

```gleam
case result {
  Ok(value) -> handle_success(value)
  Error(err) -> handle_error(err)
}
```

## Dependencies

### Runtime
- `gleam_stdlib` - Standard library

### Development
- `startest` - Testing framework

## Testing

Tests use `startest` framework:

```gleam
import startest/expect

pub fn example_test() {
  some_function()
  |> expect.to_equal(expected_value)
}
```

Run tests:
```bash
just test
# or
gleam test
```

## Tool Versions

Managed via `.tool-versions` (source of truth for CI):
- Erlang 27.2.1
- Rebar3 3.24.0 (required by vestibule_wisp's transitive deps)
- Gleam 1.16.0
- just 1.38.0

Local development can use `.mise.toml` for flexible versions.

## CI/CD

### Workflows
- **ci.yml**: Split format, type check, build, test, and docs jobs across all packages
- **pr.yml**: PR title validation (commitlint) and changelog entry check
- **release.yml**: `trellis release pr` — batches all packages with pending fragments into a single release PR
- **publish.yml**: On the release PR merging — publishes to Hex.pm in dependency order, then records per-package tags (e.g., `vestibule-v0.2.0`) and GitHub Releases

### Release Flow
1. Push commits with conventional commit messages
2. Add changelog entries with `just change <package> <kind> "What changed"`
3. `trellis release pr` batches all packages with pending fragments into a single release PR
4. Release PR bumps each package's `gleam.toml` version, regenerates per-package `CHANGELOG.md`, and patches the locked workspace versions in every `manifest.toml`
5. Merge PR → `trellis publish --all-untagged` validates and publishes each package in dependency order, skipping versions Hex already has
6. `trellis tag create --github-release` then records what shipped, and the lockfiles are refreshed in a follow-up PR

### Publishing Details
- Sub-packages use `vestibule = { path = "../.." }` during development
- `trellis publish` rewrites this to `vestibule = ">= X.Y.Z and < (X+1).0.0"` before publishing and restores the original `gleam.toml` afterwards, deriving the requirement from the graph rather than a hand-maintained list
- Ordering is topological, so vestibule reaches Hex before the packages that depend on it
- Every step is idempotent: re-run the Publish workflow to recover from a partial failure

### Workspace membership
Trellis auto-discovers members — every `gleam.toml` git knows about, outside `build/`.
There is no workspace file; the `[tools.trellis]` table's presence in the root `gleam.toml`
is what marks the workspace root.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(parser): add support for nested objects
fix(validation): handle empty strings correctly
docs: update installation instructions
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`

See `.commitlintrc.json` for configuration.

## Changelog

Managed with [trellis](https://trellis.tylerbutler.com/docs/changelog/), whose changelog
engine is native — no second binary in CI:
- **`[tools.trellis.changelog]` in the root `gleam.toml`**: kinds, the bump each implies, and the `CHANGELOG.md` header
- Fragments are TOML files in `.changes/unreleased/` with `package`, `kind`, and `body` keys
- Per-package version sections stored in `.changes/<package>/v*.md`; each `CHANGELOG.md` is **generated** by reassembling them
- Each package has its own `CHANGELOG.md` (root for vestibule, `packages/<pkg>/CHANGELOG.md` for sub-packages)
- Add an entry with `just change <package> <kind> "What changed"` (`trellis changelog new` under the hood — non-interactive)
- `just changelog-preview` (`trellis version plan`) shows the bumps the pending fragments imply
- Packages that path-depend on a bumped package are bumped too, with a generated `Dependencies` entry
- The `example` app is a workspace member but is excluded from releases via `exclude.@release`

## Conventions

- Use Result types over exceptions
- Exhaustive pattern matching
- Follow `gleam format` output
- Keep public API minimal
- Document public functions with `///` comments

## Additional Documentation

- **DEV.md**: Detailed development workflows and guidelines
