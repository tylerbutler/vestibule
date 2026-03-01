# Development Guide

This document provides detailed instructions for developing and contributing to this project.

## Prerequisites

Ensure you have the following installed:

| Tool | Version | Purpose |
|------|---------|---------|
| Erlang/OTP | 27.2.1+ | BEAM runtime |
| Gleam | 1.14.0+ | Compiler and tooling |
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

# Verify everything works
just ci
```

## Development Workflow

### Daily Development

```bash
# Check your code compiles
just check

# Run tests
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
│       ├── strategy.gleam            # Strategy interface
│       └── strategy/                 # Built-in strategies
│           └── github.gleam          # GitHub OAuth strategy
├── test/
│   └── vestibule/                    # Tests
├── packages/
│   ├── vestibule_apple/              # Apple Sign In strategy
│   ├── vestibule_google/             # Google OAuth strategy
│   ├── vestibule_microsoft/          # Microsoft OAuth strategy
│   └── vestibule_wisp/              # Wisp middleware
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
# Run all tests
just test

# Run with verbose output
gleam test -- --verbose
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
`vestibule_google`, `vestibule_microsoft`, `vestibule_wisp`) is independently
versioned and published to Hex.pm.

### Adding Changelog Entries

```bash
# Interactive — prompts for project selection and kind
just change

# Direct — specify the package
just change-pkg vestibule
just change-pkg vestibule_apple

# Preview what would be released for a package
just changelog-preview vestibule
```

### Release Flow

1. Make changes following the commit message convention
2. Add a changie changelog entry for each affected package (`just change`)
3. Push to a feature branch and create a PR
4. After merge to main, the **Changie Release** workflow batches all projects
   with unreleased changes and creates a single release PR
5. The release PR bumps versions in each package's `gleam.toml` and updates
   per-package `CHANGELOG.md` files
6. Merge the release PR → **Auto-tag** creates per-package tags
   (e.g., `vestibule-v0.2.0`, `vestibule_apple-v0.1.1`)
7. Each tag triggers the **Publish** workflow, which publishes that package
   to Hex.pm

### Publishing Order

Sub-packages depend on `vestibule` via path references during development.
When publishing to Hex.pm, the publish workflow rewrites path dependencies
to Hex version ranges automatically. If releasing `vestibule` core alongside
a sub-package, ensure `vestibule` is published to Hex.pm first (the tags are
created in the order listed in the workflow).

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
# Run a specific test
gleam test -- --filter "test_name"

# Run with more output
gleam test -- --verbose
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
