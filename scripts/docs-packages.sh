#!/usr/bin/env bash
set -euo pipefail

for pkg in packages/vestibule_*/; do
    [ -f "$pkg/gleam.toml" ] || continue
    echo "=== Building docs: $pkg ==="
    (cd "$pkg" && gleam docs build)
done
