# Vestibule Monorepo Tasks
#
# Packages are built/tested in dependency order:
#   vestibule → provider packages and middleware packages

set dotenv-load := true
set dotenv-path := "example/.env"

# === ALIASES ===
alias b := build
alias t := test
alias f := format
alias l := lint
alias c := check
alias d := docs
alias cl := change
alias cp := change-pkg

default:
    @just --list

# Packages in topological (dependency) order. "." is the root vestibule package.
packages := ". vestibule_apple vestibule_github vestibule_google vestibule_microsoft vestibule_wisp vestibule_mist"

# === DEPENDENCIES ===

# Download dependencies for all packages
deps:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: downloading deps"
        ( cd "$dir" && gleam deps download )
    done

# === BUILD ===

# Build all packages (Erlang target)
build:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: building"
        ( cd "$dir" && gleam build )
    done

# Build all packages with warnings as errors
build-strict:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: building (strict)"
        ( cd "$dir" && gleam build --warnings-as-errors )
    done

# === TESTING ===

# Run tests for all packages (Erlang target)
test:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: testing (erlang)"
        ( cd "$dir" && gleam test )
    done

# Backwards-compatible alias for all tests
test-all: test

# Run tests for a specific sub-package
test-pkg pkg:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{ pkg }}" = "." ]; then
        gleam test
    else
        cd packages/{{ pkg }} && gleam test
    fi

# === CODE QUALITY ===

# Format source code in all packages
format:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        ( cd "$dir" && gleam format src test )
    done

# Check formatting without changes
format-check:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: format check"
        ( cd "$dir" && gleam format --check src test )
    done

# Type check all packages
check:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: type check"
        ( cd "$dir" && gleam check )
    done

# Lint all packages with glinter
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: linting"
        ( cd "$dir" && gleam run -m glinter )
    done
    echo "==> example: linting"
    ( cd example && gleam run -m glinter )

# Lint a single package: just lint-pkg vestibule_google
lint-pkg pkg:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{ pkg }}" = "." ]; then
        gleam run -m glinter
    elif [ "{{ pkg }}" = "example" ]; then
        cd example && gleam run -m glinter
    else
        cd packages/{{ pkg }} && gleam run -m glinter
    fi

# === EXAMPLE APP ===

# Start the example OAuth app (requires at least one configured provider)
serve:
    cd example && gleam run

# === DOCUMENTATION ===

# Build documentation for all packages
docs:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        echo "==> $pkg: building docs"
        ( cd "$dir" && gleam docs build )
    done

# Install documentation website dependencies
website-deps:
    cd website && pnpm install

# Start the Astro documentation website
website-dev:
    cd website && pnpm dev

# Generate website reference docs from Gleam docs JSON
website-reference: docs
    cd website && pnpm generate:reference

# Build the Astro documentation website
website-build: website-reference
    cd website && pnpm build

# === CHANGELOG ===

# Create a new changelog entry (interactive project selection)
change:
    changie new

# Create a changelog entry for a specific package
change-pkg pkg:
    changie new --project {{pkg}}

# Preview unreleased changelog for a project
changelog-preview pkg:
    changie batch auto --project {{pkg}} --dry-run

# Generate CHANGELOG.md for a project
changelog pkg:
    changie merge --project {{pkg}}

# === MAINTENANCE ===

# Remove build artifacts from all packages
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in {{ packages }}; do
        dir="packages/$pkg"
        if [ "$pkg" = "." ]; then dir="."; fi
        rm -rf "$dir/build"
    done
    rm -rf example/build

# === PER-PACKAGE TARGETS ===

# Build a single package: just build-pkg vestibule_google
build-pkg pkg:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "{{ pkg }}" = "." ]; then
        gleam build
    else
        cd packages/{{ pkg }} && gleam build
    fi

# === CI ===

# Run all CI checks (format, lint, check, test, build strict)
ci: format-check lint check test build-strict

# Alias for PR checks
alias pr := ci

# Run extended checks for main branch
main: ci docs
