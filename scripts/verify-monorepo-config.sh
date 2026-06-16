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

check "workspace includes root and vestibule packages" \
    contains workspace.toml 'members = [".", "packages/vestibule_*"]'
check "workspace has no package excludes" \
    not_contains workspace.toml "exclude = ["

check "justfile uses an explicit topological package list" \
    contains justfile 'packages := ". vestibule_apple vestibule_github vestibule_google vestibule_microsoft vestibule_wisp vestibule_mist"'
check "justfile loops over packages for deps" \
    matches justfile 'for pkg in \{\{ packages \}\}; do[[:space:]]*$'
check "justfile no longer delegates package checks to scripts" \
    not_contains justfile "scripts/check-packages.sh"
check "justfile no longer delegates package tests to scripts" \
    not_contains justfile "scripts/test-packages.sh"
check "justfile omits JavaScript tests while Vestibule is Erlang-only" \
    not_contains justfile "test-js:"
check "justfile CI matches lattice shape" \
    contains justfile "ci: format-check check test build-strict"

for job in format check build test docs; do
    check "CI has $job job" \
        matches .github/workflows/ci.yml "^  $job:"
done
check "CI has no grouped checks job" \
    not_contains .github/workflows/ci.yml "  checks:"
check "CI omits JavaScript tests while Vestibule is Erlang-only" \
    not_contains .github/workflows/ci.yml "test-js"

check "release PR title matches lattice" \
    contains .github/workflows/release.yml "pr-title-template: 'chore(release): {version}'"
check "release updates local vestibule path deps after version bumps" \
    contains .github/workflows/release.yml "gleam update \$deps"
check "release does not refresh every lockfile unconditionally" \
    not_contains .github/workflows/release.yml "gleam deps download"

check "auto-tag uses workspace-file input" \
    contains .github/workflows/auto-tag.yml "workspace-file: workspace.toml"
check "auto-tag waits for publish" \
    contains .github/workflows/auto-tag.yml "wait-for-publish: true"
check "auto-tag identifies publish workflow" \
    contains .github/workflows/auto-tag.yml "publish-workflow-name: Publish"

check "publish validates tagged package only" \
    contains .github/workflows/publish.yml 'PACKAGE: ${{ steps.ws.outputs.tag-package-path }}'
check "publish reads tag metadata from workspace" \
    contains .github/workflows/publish.yml 'tag: ${{ github.ref_name }}'
check "publish exposes tagged package path" \
    contains .github/workflows/publish.yml 'package-path: ${{ steps.ws.outputs.tag-package-path }}'
check "publish omits JavaScript tests while Vestibule is Erlang-only" \
    not_contains .github/workflows/publish.yml "gleam test --target javascript"
check "publish publishes tagged package only" \
    contains .github/workflows/publish.yml 'packages: ${{ needs.test.outputs.package-path }}'
check "publish rewrites vestibule path dependency" \
    contains .github/workflows/publish.yml "vestibule:gleam.toml"

for path in \
    gleam.toml \
    packages/vestibule_apple/gleam.toml \
    packages/vestibule_github/gleam.toml \
    packages/vestibule_google/gleam.toml \
    packages/vestibule_microsoft/gleam.toml \
    packages/vestibule_wisp/gleam.toml \
    packages/vestibule_mist/gleam.toml
do
    check "changie updates $path" \
        contains .changie.yaml "path: $path"
done

if [ "$failures" -ne 0 ]; then
    printf '\n%s monorepo config check(s) failed.\n' "$failures"
    exit 1
fi

printf '\nAll monorepo config checks passed.\n'
