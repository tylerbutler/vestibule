#!/usr/bin/env bash
set -euo pipefail

for pkg in packages/vestibule_*/; do
    [ -f "$pkg/gleam.toml" ] || continue
    echo "=== Building $pkg (strict) ==="
    (cd "$pkg" && gleam build --warnings-as-errors)
done
