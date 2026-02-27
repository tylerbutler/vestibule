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
just deps         # Download dependencies
just build        # Build project
just test         # Run tests
just format       # Format code
just format-check # Check formatting
just check        # Type check
just docs         # Build documentation
just ci           # Run all CI checks (format, check, test, build)
just pr           # Alias for ci (use before PR)
just main         # Extended checks for main branch
just change       # Create a new changelog entry
just clean        # Remove build artifacts
```

## Project Structure

```
src/
├── vestibule.gleam         # Main public API
└── vestibule/              # Submodules (if needed)
    └── internal/           # Private implementation (mark in gleam.toml)
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
- **ci.yml**: Format check, type check, build, test
- **pr.yml**: PR title validation (commitlint) and changelog entry check
- **release.yml**: Automated versioning via changie-release
- **auto-tag.yml**: Auto-tag releases on PR merge
- **publish.yml**: Publish to Hex.pm on tag push

### Release Flow
1. Push commits with conventional commit messages
2. Add changelog entries with `just change` (changie)
3. changie-release creates a PR with version bump and changelog
4. Merge PR → auto-tag creates a GitHub release
5. publish.yml triggers → publishes to Hex.pm

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

Managed with [changie](https://changie.dev/):
- **`.changie.yaml`** (default): Uses kinds (Added, Changed, Fixed, etc.) to categorize entries
- **`.changie.no-kinds.yaml`**: Simpler changelog without kind categorization
- To switch: `mv .changie.no-kinds.yaml .changie.yaml`
- To keep default: `rm .changie.no-kinds.yaml`

## Conventions

- Use Result types over exceptions
- Exhaustive pattern matching
- Follow `gleam format` output
- Keep public API minimal
- Document public functions with `///` comments

## Additional Documentation

- **DEV.md**: Detailed development workflows and guidelines
