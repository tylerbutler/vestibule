#!/usr/bin/env bash
set -euo pipefail

for pkg in packages/vestibule_*/; do
    [ -f "$pkg/gleam.toml" ] || continue
    echo "=== Formatting $pkg ==="
    (cd "$pkg" && gleam format src test)
done
