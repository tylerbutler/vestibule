---
name: publish-check
description: Validate all vestibule packages are ready for hex.pm publishing
disable-model-invocation: true
---

# Publish Readiness Check

Validate that all packages in the vestibule monorepo are ready for hex.pm publishing.

## Checks to perform

For each `gleam.toml` in the root and `packages/*/`:

1. **Required fields present**: `name`, `version`, `description`, `licences`, `repository`
2. **Description is meaningful**: Not the default "A Gleam project"
3. **Version is set**: Not `0.0.0` or `0.1.0` (unless intentional pre-release)
4. **Repository links correct**: Points to `github.com/tylerbutler/vestibule`
5. **License is set**: Should be `MIT`

## Additional checks

- All packages build cleanly: `gleam build` in each package
- All packages pass tests: `gleam test` in each package
- Format check passes: `gleam format --check src test` in each package
- No git dep references that should be hex deps before publishing (e.g., bravo fork)
- `internal_modules` configured if needed

## Output

Report a table of packages with pass/fail for each check. Flag any blockers for publishing.
