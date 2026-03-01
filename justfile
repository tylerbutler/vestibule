# Gleam Project Tasks

set dotenv-load := true
set dotenv-path := "example/.env"

# === ALIASES ===
alias b := build
alias t := test
alias f := format
alias c := check
alias d := docs
alias cl := change

default:
    @just --list

# === DEPENDENCIES ===

# Download project dependencies
deps:
    gleam deps download

# === BUILD ===

# Build project (Erlang target)
build:
    gleam build

# Build with warnings as errors
build-strict:
    gleam build --warnings-as-errors

# === TESTING ===

# Run tests for root package
test:
    gleam test

# Run tests for all sub-packages
test-packages:
    #!/usr/bin/env bash
    set -euo pipefail
    for pkg in packages/vestibule_*/; do
        echo "=== Testing $pkg ==="
        (cd "$pkg" && gleam test)
    done

# Run all tests (root + sub-packages)
test-all: test test-packages

# Run tests for a specific sub-package
test-pkg pkg:
    cd packages/{{pkg}} && gleam test

# === CODE QUALITY ===

# Format source code
format:
    gleam format src test

# Check formatting without changes
format-check:
    gleam format --check src test

# Type check without building
check:
    gleam check

# === EXAMPLE APP ===

# Start the example OAuth app (requires GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)
serve:
    cd example && gleam run

# === DOCUMENTATION ===

# Build documentation
docs:
    gleam docs build

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

# Generate CHANGELOG.md
changelog:
    changie merge

# === MAINTENANCE ===

# Remove build artifacts
clean:
    rm -rf build

# === CI ===

# Run all CI checks (format, check, test, build)
ci: format-check check test build-strict

# Alias for PR checks
alias pr := ci

# Run extended checks for main branch
main: ci docs

# =============================================================================
# MULTI-TARGET SUPPORT (Uncomment if targeting JavaScript)
# =============================================================================

# # Build for JavaScript target
# build-js:
#     gleam build --target javascript

# # Build all targets
# build-all: build build-js

# # Build JavaScript with warnings as errors
# build-strict-js:
#     gleam build --target javascript --warnings-as-errors

# # Build all targets strictly
# build-strict-all: build-strict build-strict-js

# # Test on Erlang target
# test-erlang:
#     gleam test

# # Test on JavaScript target
# test-js:
#     gleam test --target javascript

# # Test on all targets
# test-all: test-erlang test-js

# =============================================================================
# JAVASCRIPT INTEGRATION TESTS (Uncomment if needed)
# =============================================================================

# # Run integration tests with Node.js
# test-integration-node: build-js
#     node --test test/integration/test_runner.mjs

# # Run integration tests with Deno
# test-integration-deno: build-js
#     deno test --allow-read --allow-env test/integration/test_runner.mjs

# # Run integration tests with Bun
# test-integration-bun: build-js
#     bun test test/integration/test_runner.mjs

# =============================================================================
# COVERAGE (Uncomment if needed)
# =============================================================================

# # Run tests with coverage (requires setup - see README)
# coverage:
#     @echo "Coverage requires additional setup. See README.md"
