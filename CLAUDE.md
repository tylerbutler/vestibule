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
just build             # Build project
just test              # Run all tests (root + sub-packages)
just test-root         # Run tests for root package only
just test-pkg <pkg>    # Run tests for a specific sub-package
just format            # Format code
just format-check      # Check formatting
just check             # Type check
just docs              # Build documentation
just ci                # Run all CI checks (format, check, test, build)
just pr                # Alias for ci (use before PR)
just main              # Extended checks for main branch
just change            # Create a new changelog entry (interactive project selection)
just change-pkg <pkg>  # Create changelog entry for a specific package
just changelog-preview <pkg>  # Preview unreleased changelog for a package
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
├── vestibule_google/                 # Google OAuth strategy
├── vestibule_microsoft/              # Microsoft OAuth strategy
└── vestibule_wisp/                   # Wisp middleware
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
- Gleam 1.14.0
- just 1.38.0

Local development can use `.mise.toml` for flexible versions.

## CI/CD

### Workflows
- **ci.yml**: Format check, type check, build, test (root + all sub-packages)
- **pr.yml**: PR title validation (commitlint) and changelog entry check
- **release.yml**: Multi-project changie-release — batches all packages with changes into a single release PR
- **auto-tag.yml**: Creates per-package tags (e.g., `vestibule-v0.2.0`, `vestibule_apple-v0.1.1`) when release PR merges
- **publish.yml**: Publishes individual packages to Hex.pm on tag push; rewrites path deps to Hex version ranges for sub-packages

### Release Flow
1. Push commits with conventional commit messages
2. Add changelog entries with `just change` (changie prompts for project selection)
3. changie-release batches all projects with changes, creates a single release PR
4. Release PR bumps each package's `gleam.toml` version and updates per-package `CHANGELOG.md`
5. Merge PR → auto-tag creates per-package tags and GitHub Releases
6. Each tag triggers publish.yml → publishes that specific package to Hex.pm

### Publishing Details
- Sub-packages use `vestibule = { path = "../.." }` during development
- The publish workflow rewrites this to `vestibule = ">= X.Y.Z and < (X+1).0.0"` before publishing
- If releasing vestibule core + sub-packages together, vestibule is tagged/published first

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

Managed with [changie](https://changie.dev/) using the **projects** feature for multi-package support:
- **`.changie.yaml`**: Configures 5 projects (vestibule + 4 provider packages) with `projectsVersionSeparator: "-"`
- Each package has its own `CHANGELOG.md` (root for vestibule, `packages/<pkg>/CHANGELOG.md` for sub-packages)
- Fragments go in `.changes/unreleased/`, prefixed by project name
- Per-project version files stored in `.changes/<project>/v*.md`
- Use `just change` for interactive project selection, or `just change-pkg <name>` for direct

## Conventions

- Use Result types over exceptions
- Exhaustive pattern matching
- Follow `gleam format` output
- Keep public API minimal
- Document public functions with `///` comments

## Additional Documentation

- **DEV.md**: Detailed development workflows and guidelines
