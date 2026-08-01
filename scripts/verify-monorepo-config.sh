#!/usr/bin/env bash
set -euo pipefail

failures=0

check() {
    local description=$1
    shift

    if "$@"; then
        printf 'ok - %s\n' "$description"
    else
        printf 'not ok - %s\n' "$description"
        failures=$((failures + 1))
    fi
}

contains() {
    local file=$1
    local pattern=$2
    grep -Fq -- "$pattern" "$file"
}

matches() {
    local file=$1
    local pattern=$2
    grep -Eq -- "$pattern" "$file"
}

not_contains() {
    local file=$1
    local pattern=$2
    ! grep -Fq -- "$pattern" "$file"
}

not_matches() {
    local file=$1
    local pattern=$2
    ! grep -Eq -- "$pattern" "$file"
}

# Membership is derived, not declared: trellis auto-discovers every gleam.toml
# git knows about, so there is no workspace file to drift from the packages.
check "workspace membership is not declared in a workspace file" \
    test ! -e workspace.toml
check "the trellis table marks the workspace root" \
    contains gleam.toml "[tools.trellis]"
check "membership stays auto-discovered" \
    not_matches gleam.toml '^members = \['

check "justfile uses an explicit topological package list" \
    contains justfile 'packages := ". vestibule_apple vestibule_github vestibule_google vestibule_indieauth vestibule_microsoft vestibule_oidc vestibule_wisp vestibule_mist"'
check "justfile loops over packages for deps" \
    matches justfile 'for pkg in \{\{ packages \}\}; do[[:space:]]*$'
check "justfile no longer delegates package checks to scripts" \
    not_contains justfile "scripts/check-packages.sh"
check "justfile no longer delegates package tests to scripts" \
    not_contains justfile "scripts/test-packages.sh"
check "justfile omits JavaScript tests while Vestibule is Erlang-only" \
    not_contains justfile "test-js:"
check "justfile CI matches lattice shape" \
    contains justfile "ci: format-check lint check test build-strict"

for job in format check build test docs; do
    check "CI has $job job" \
        matches .github/workflows/ci.yml "^  $job:"
done
check "CI has no grouped checks job" \
    not_contains .github/workflows/ci.yml "  checks:"
check "CI fans tasks out with trellis" \
    contains .github/workflows/ci.yml "trellis run"
check "CI needs no package matrix" \
    not_contains .github/workflows/ci.yml "matrix:"
check "CI omits JavaScript tests while Vestibule is Erlang-only" \
    not_contains .github/workflows/ci.yml "test-js"

check "release batches fragments into a PR with trellis" \
    contains .github/workflows/release.yml "trellis release pr --base main"
check "release no longer shells out to changie" \
    not_contains .github/workflows/release.yml "changie"
check "release does not refresh lockfiles by hand (version apply patches them)" \
    not_contains .github/workflows/release.yml "gleam update"

# Tags as record: the release PR merging publishes, and tags are written after
# Hex has the packages. There is no separate auto-tag workflow.
check "tagging is not a workflow of its own" \
    test ! -e .github/workflows/auto-tag.yml
check "release triggers on the release PR merging" \
    contains .github/workflows/publish.yml "github.event.pull_request.head.ref == 'release/pending'"
check "release walks the dependency graph itself" \
    contains .github/workflows/publish.yml "trellis publish --all-untagged"
check "release names no packages by hand" \
    not_contains .github/workflows/publish.yml "packages/vestibule_"
check "release records both tag lifecycles" \
    contains .github/workflows/publish.yml "trellis tag create --github-release"
check "release omits JavaScript tests while Vestibule is Erlang-only" \
    not_contains .github/workflows/publish.yml "gleam test --target javascript"

# Publishing stays off until the packages leave pre-release. Both halves matter:
# the dry run, and the absence of the Hex credential that would let an upload
# succeed if the flag were ever dropped by accident.
check "publishing to Hex is disabled" \
    contains .github/workflows/publish.yml "trellis publish --all-untagged --dry-run"
check "no Hex credential is wired into the release workflow" \
    not_matches .github/workflows/publish.yml '^ +HEXPM_API_KEY:'

# A moving series tag per package, alongside the immutable per-version tag.
check "series tags are enabled" \
    contains gleam.toml 'tag_mode = "both"'

check "PR gate checks changelog fragments with trellis" \
    contains .github/workflows/pr.yml "trellis changelog check"
check "PR gate skips the release branch" \
    contains .github/workflows/pr.yml "github.head_ref != 'release/pending'"

check "changelog config lives in gleam.toml" \
    contains gleam.toml "[tools.trellis.changelog]"
check "the example app is excluded from releases" \
    contains gleam.toml '"@release" = ["example"]'
check "changie config is gone" \
    test ! -e .changie.yaml
check "no changie fragments remain" \
    test -z "$(find .changes/unreleased -name '*.yaml' -print -quit)"

# Trellis derives versioning from each package's gleam.toml, so every releasable
# package needs a generated CHANGELOG.md to assemble into.
for path in \
    CHANGELOG.md \
    packages/vestibule_apple/CHANGELOG.md \
    packages/vestibule_github/CHANGELOG.md \
    packages/vestibule_google/CHANGELOG.md \
    packages/vestibule_indieauth/CHANGELOG.md \
    packages/vestibule_microsoft/CHANGELOG.md \
    packages/vestibule_oidc/CHANGELOG.md \
    packages/vestibule_wisp/CHANGELOG.md \
    packages/vestibule_mist/CHANGELOG.md
do
    check "trellis has a changelog to render for $path" \
        test -f "$path"
done

if [ "$failures" -ne 0 ]; then
    printf '\n%s monorepo config check(s) failed.\n' "$failures"
    exit 1
fi

printf '\nAll monorepo config checks passed.\n'
