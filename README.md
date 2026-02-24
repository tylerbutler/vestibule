# vestibule

[![Package Version](https://img.shields.io/hexpm/v/vestibule)](https://hex.pm/packages/vestibule)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/vestibule/)

A Gleam project.

## Installation

```sh
gleam add vestibule
```

## Usage

```gleam
import vestibule

pub fn main() {
  vestibule.hello("World")
  // -> "Hello, World!"
}
```

## Development

### Setup Options

This template includes two CI options:

1. **Local setup action** (default): Self-contained, no external dependencies
   - Uses `.github/actions/setup/action.yml`

2. **Shared actions**: Uses [tylerbutler/actions](https://github.com/tylerbutler/actions)
   - Rename `ci-shared-actions.yml.template` to `ci.yml`
   - Delete `.github/actions/` directory

### Prerequisites

- [Erlang](https://www.erlang.org/) 27+
- [Gleam](https://gleam.run/) 1.7+
- [just](https://github.com/casey/just) (task runner)

Install tools via [mise](https://mise.jdx.dev/) or [asdf](https://asdf-vm.com/):

```sh
mise install
# or
asdf install
```

### Commands

```sh
just deps      # Download dependencies
just build     # Build the project
just test      # Run tests
just format    # Format code
just check     # Type check
just docs      # Build documentation
just ci        # Run all CI checks
```

### CI/CD

This project uses GitHub Actions for CI and automated releases:

- **CI**: Runs on every push/PR to main
- **Release**: Uses [release-please](https://github.com/googleapis/release-please) for automated versioning
- **Publish**: Automatically publishes to [Hex.pm](https://hex.pm) on release

### GitHub Secrets Required

| Secret | Description |
|--------|-------------|
| `RELEASE_TOKEN` | GitHub PAT with `contents:write` and `pull-requests:write` permissions |
| `HEXPM_API_KEY` | API key from [hex.pm](https://hex.pm) for publishing |

### Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New features (minor version bump)
- `fix:` - Bug fixes (patch version bump)
- `docs:` - Documentation changes
- `chore:` - Maintenance tasks
- `BREAKING CHANGE:` in commit body - Major version bump

## License

MIT - see [LICENSE](LICENSE) for details.
