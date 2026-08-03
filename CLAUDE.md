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
- **ci.yml**: One job per task (format, check, lint, build, test, docs), each `trellis run <task>` fanning across all packages graph-parallel
- **pr.yml**: PR title validation (commitlint) and changelog entry check
- **release.yml**: `trellis release pr` — batches all packages with pending fragments into a single release PR
- **publish.yml** (workflow name: Release): On the release PR merging — records per-package tags and GitHub Releases. **Publishing to Hex is off** while the packages are pre-release

### Release Flow
1. Push commits with conventional commit messages
2. Add changelog entries with `just change <package> <kind> "What changed"`
3. `trellis release pr` batches all packages with pending fragments into a single release PR
4. Release PR bumps each package's `gleam.toml` version, regenerates per-package `CHANGELOG.md`, and patches the locked workspace versions in every `manifest.toml`
5. Merge PR → `trellis publish --all-untagged --dry-run` reports what *would* ship, then `trellis tag create --github-release` records it

### Tags
Every releasable package writes two tags per release, via `tag_mode = "both"`:
- **`{name}-v{version}`** (e.g. `vestibule-v0.0.1`) — immutable, created once, carries the GitHub Release bodied from the matching CHANGELOG section
- **`{name}-v{series}`** (e.g. `vestibule-v0.0`) — moving; force-moved to the newest release in its series so consumers can pin a series instead of chasing patches. Carries no GitHub Release, since it would silently retarget on the next move

The series is derived from the version, never configured: `major.minor` while the major is 0 (every minor bump being breaking), the major alone from 1.0 on. Prereleases belong to no series and move no tag.

### Publishing Details
Publishing is **disabled**: the release workflow runs `trellis publish --all-untagged --dry-run`, which resolves what would ship without contacting Hex. To enable it, drop `--dry-run`, add `HEXPM_API_KEY`, and restore a lockfile refresh — see the note at the top of `publish.yml`. When it is on:
- Sub-packages use `vestibule = { path = "../.." }` during development
- `trellis publish` rewrites this to `vestibule = ">= X.Y.Z and < (X+1).0.0"` before publishing and restores the original `gleam.toml` afterwards, deriving the requirement from the graph rather than a hand-maintained list
- Ordering is topological, so vestibule reaches Hex before the packages that depend on it
- Every step is idempotent: re-run the Release workflow to recover from a partial failure

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
- The `example` app and the Apple, Google, Microsoft, and OIDC providers are workspace members but are excluded from releases via `exclude.@release`

## Conventions

- Use Result types over exceptions
- Exhaustive pattern matching
- Follow `gleam format` output
- Keep public API minimal
- Document public functions with `///` comments

## Additional Documentation

- **DEV.md**: Detailed development workflows and guidelines
