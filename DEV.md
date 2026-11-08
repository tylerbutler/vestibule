# Development Guide

This document provides detailed instructions for developing and contributing to this project.

## Prerequisites

Ensure you have the following installed:

| Tool | Version | Purpose |
|------|---------|---------|
| Erlang/OTP | 27.2.1+ | BEAM runtime |
| Gleam | 1.18.1+ | Compiler and tooling |
| just | 1.38.0+ | Task runner |

**Recommended:** Use [mise](https://mise.jdx.dev/) with the provided
`.mise.toml` and `mise.lock` files.

```bash
mise install --locked
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

### Agent Package Manager

This repository is also an [APM package](https://microsoft.github.io/apm/).
It ships two agents (`monorepo-test-runner` and `oauth-security-reviewer`)
and two skills (`gleam-review` and `publish-check`). These are development
tools; their output does not make Vestibule audited or production-ready.
The `publish-check` skill is only for an explicitly requested future Hex
release. Current releases remain git-only.

With APM installed, run:

```bash
apm install
```

Edit agent and skill sources under `.apm/`, then run `apm install` again.
Commit the sources, `apm.lock.yaml`, and generated runtime files together:

| Content | Claude output | Copilot output |
|---------|---------------|----------------|
| Agents | `.claude/agents/` | `.github/agents/` |
| Skills | `.claude/skills/` | `.agents/skills/` |

The manifest selects both targets. Existing Claude hooks and `CLAUDE.md`
remain separate from the APM package. Do not use `apm compile` to replace
the hand-maintained project instructions. To validate the package without
generating root instructions, use `apm compile --validate`.

Agent tool lists use names supported by both runtimes. No model is pinned;
each agent inherits the runtime's model selection. Shell access is retained
for tests and source inspection, so read-only review instructions are not
a filesystem sandbox.

Other repositories can install this package with
`apm install tylerbutler/vestibule --target claude,copilot`.
The test and OAuth agents expect the Vestibule repository layout.
The APM manifest version is maintained separately from Gleam package releases.

### Daily Development

```bash
# Check every package compiles
just check

# Run all package tests, including the example app
just test

# Format code (do this before committing)
just format
```

### Before Committing

```bash
# Run full local checks
just pr
```

CI runs security-policy, dependency, and combined format/lint/test/docs jobs.
The combined job checks formatting, lints, runs tests, and builds documentation
in order with one environment setup and dependency restore. Tests compile all
packages, so CI has no separate check or build job.
`just pr` retains the separate local check and strict build commands.

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
├── .mise.toml                        # Tool version configuration
└── mise.lock                         # Locked tool downloads and checksums
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

Tests use the `gleeunit` framework with the `assert` keyword:

```gleam
pub fn my_feature_test() {
  assert my_function("input") == expected_output
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
releases every package. The `example` app stays a full workspace member —
normal tasks still build and test it — but its path is listed under
`exclude."@release"` in the root `gleam.toml`, so it is never versioned or
tagged. `trellis doctor` prints the split.

### Adding Changelog Entries

CI-only changes do not require changelog fragments. This includes workflow
configuration, dependency-download pacing, and related CI documentation.
Add fragments for package API or behavior changes included in the same PR.

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
2. Add a changelog entry for each affected package (`just change ...`), except for CI-only changes
3. Push to a feature branch and create a PR
4. After merge to main, **Prepare release** runs `trellis release pr` with native
   intent resumption, candidate continuation, and unchanged-content checks.
   It creates or updates one `release/pending` PR for the affected packages
5. The release PR bumps versions in each package's `gleam.toml`, regenerates the
   per-package `CHANGELOG.md` files, and patches the locked workspace versions in
   every `manifest.toml`. Packages that path-depend on a bumped package are
   bumped too, with a generated `Dependencies` entry
6. Merge the release PR. After trusted push CI passes for that exact merge,
   approve the `release` environment in **Tag and release**. Trellis records
   the package tags and GitHub Releases with `trellis tag create --github-release`.
   Nothing is uploaded to Hex; see [Publishing](#publishing)

### Candidates and promotion

The locked toolchain uses Trellis 1.3.0. Release preparation uses
`[tools.trellis.release]` settings `resume`, `auto_pre`, and `skip_unchanged`.
Automatic runs preserve a pending PR's mode and package targets. After a
candidate merges, new release content continues its candidate label. An
automatic run does not promote a candidate to stable.

Run **Prepare release** manually on `main` to change the request:

| Input | Meaning |
| --- | --- |
| `pre` empty | Retain pending intent or the committed candidate label; use stable preparation outside a candidate cycle |
| `pre` = `rc` | Start or continue a candidate cycle |
| `pre` = `none` | Promote candidates to their stable target versions |
| `targets` | Optional space-separated `package=X.Y.Z` targets, for example `vestibule=0.2.0 vestibule_github=0.3.0` |

Packages retain separate version bases. Explicit inputs override the supplied
part of a pending request; empty inputs do not reset that request. Trellis
rejects unknown packages, invalid versions, conflicting labels, and inconsistent
release state. No-change outcomes skip preparation; errors fail the workflow.

Preview local version plans without creating a PR or tags:

```bash
just changelog-preview
just changelog-preview rc "vestibule=0.2.0 vestibule_github=0.3.0"
just changelog-preview none
# The native CLI also accepts repeated per-package overrides.
trellis version plan --pre rc --set vestibule=0.2.0 --set vestibule_github=0.3.0
```

These previews use local versions and fragments, not a pending PR's stored
intent. Review the prepared release PR before merging.

Trellis commits `.changes/release.toml` to record native release intent.
Each candidate moves its fragments into `.changes/<package>/v<prerelease>.toml`
archives beside its Markdown notes. Include those archives in the release PR.
Later candidates include new changes only; `--pre none` combines candidate
archives and remaining fragments for the stable release notes.

### Recovery and prerequisites

Preparation and tagging each run in a serialized workflow. Preparation requires
the current package versions to have their tags and published GitHub Releases
with the correct prerelease flags. If tagging fails or awaits approval,
preparation stops before obtaining write credentials. Retry **Tag and release**
on `main` with `release_sha` set to the full reviewed release merge SHA, then
rerun **Prepare release**. The retry requires a merged same-repository
`release/pending` PR, the latest successful trusted CI push attempt for that SHA,
and environment approval. Do not tag the current `main` tip as a substitute.

Set repository secrets `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` for an App
installed on this repository. Preparation requests Contents write and Pull
requests write; tagging requests Contents write. The gate uses Actions read
and Pull requests read. Keep the default token read-only, the `release`
environment's reviewer and `main` restriction, and the package-tag and moving-tag
rules described in [CI security](docs/ci-security.md). Git-only releases do not
need a Hex publication key. The existing Hex read key serves dependency downloads.

During migration, a legacy pending PR without `.changes/release.toml` cannot
resume. Replace it through an explicit native request with `--no-resume`,
`--no-skip-unchanged`, and the intended mode and targets; review that replacement
before merging. Legacy candidate continuation needs full, consistent manifest
and changelog history. If verification fails, fetch complete history or make
an explicit candidate preparation to establish native state. Do not rewrite
historical releases or edit release intent by hand.

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
