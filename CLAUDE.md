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
- `gleeunit` - Testing framework

## Testing

Tests use `gleeunit` framework:

```gleam
import gleeunit/should

pub fn example_test() {
  some_function()
  |> should.equal(expected_value)
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
- **release.yml**: Automated versioning via release-please
- **publish.yml**: Publish to Hex.pm on release

### Release Flow
1. Push commits with conventional commit messages
2. release-please creates a PR with version bump
3. Merge PR → GitHub creates release
4. publish.yml triggers → publishes to Hex.pm

## Conventions

- Use Result types over exceptions
- Exhaustive pattern matching
- Follow `gleam format` output
- Keep public API minimal
- Document public functions with `///` comments
