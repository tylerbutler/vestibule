#!/usr/bin/env bash
set -euo pipefail

for pkg in packages/vestibule_*/; do
    [ -f "$pkg/gleam.toml" ] || continue
    echo "=== Checking format: $pkg ==="
    (cd "$pkg" && gleam format --check src test)
done
