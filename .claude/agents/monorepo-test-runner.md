---
name: monorepo-test-runner
description: Run all package tests across the vestibule monorepo and report unified results
tools:
  - Bash
  - Read
  - Glob
---

# Monorepo Test Runner

Run `gleam test` in the root package and every package under `packages/*/`. Report a unified summary.

## Process

1. Run `gleam test` in the project root
2. Run `gleam test` in each directory under `packages/*/`
3. Collect pass/fail counts from each package
4. Report a summary table:

```
Package              Tests   Status
vestibule            60      PASS
vestibule_apple      20      PASS
vestibule_google     6       PASS
vestibule_microsoft  6       PASS
vestibule_wisp       3       PASS
─────────────────────────────────
Total                95      ALL PASS
```

5. If any package fails, include the failure output
