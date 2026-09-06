# CI and release security

This document records the CI trust model and the dependency review performed on
2026-09-05. It is a point-in-time review, not a complete security audit.

## Trigger trust

| Workflow | Trigger | Trust and credentials |
| --- | --- | --- |
| `ci.yml` | `pull_request` | Untrusted fork or same-repository content. The token has `contents: read`, checkout credentials are not persisted, no repository secret is provided, and the job cannot save dependency caches. |
| `ci.yml` | `push` to `main` | Repository content on `main`. The token has `contents: read`. This is the only trigger that can save the Gleam dependency cache. |
| `ci.yml` | `workflow_call` | Trust is set by the caller. The called workflow requests only `contents: read`, receives no secret, and cannot save the dependency cache. |
| `pr.yml` | `pull_request` | Untrusted content. The token has `contents: read`; the workflow does not comment on the PR or persist checkout credentials. Event text is passed through environment variables, not inserted into shell source. |
| `release.yml` | `push` to `main` | Intended for reviewed `main` content. Tools and the release plan run before the GitHub App token is created. The token is passed only to `trellis release pr`. |
| `publish.yml` | successful `workflow_run` for CI on `main` | The gate uses the successful CI commit SHA and requires it to belong to a merged `release/pending` PR. The release job checks out that SHA, verifies `HEAD`, and only then creates the GitHub App token. |
| `publish.yml` | `workflow_dispatch` | A retry path. It requires a full commit SHA, the same merged release-PR association, all seven CI checks on that SHA, and the `release` environment. |

No workflow uses `pull_request_target`, downloads another workflow's artifact, or
passes a secret to pull-request code. The dependency cache contains downloaded
Gleam packages only. Pull requests can restore a base-branch cache, but only a
trusted `push` job can save a cache that `main` or a release can restore.

## Executable inputs

All active third-party actions and committed workflow templates use full,
verified upstream commit SHAs. `scripts/check_ci_security.py` enforces full SHA
pins, read-only `GITHUB_TOKEN` permissions, non-persisted checkout credentials,
safe expression handling, locked tools, secret-free PR CI, trusted cache saves,
and release-SHA binding.

The repository installs mise `2026.8.3` with the SHA-256 published in its signed
checksum list. `.mise.toml` pins Erlang, Rebar3, Gleam, Just, and Trellis.
`mise.lock` records platform URLs and SHA-256 values. Mise installs from this
lock in CI. The Erlang checksums were computed directly from the exact upstream
archives because the backend did not supply checksums. Gleam and Trellis expose
GitHub artifact attestations; the lock records verification where mise verified
it on the review host. A checksum mismatch fails installation.

CI excludes `.tool-versions` from mise discovery. That file remains available
for asdf users, but its `just` and `rebar` aliases differ from the locked mise
backend names. For a local locked install, use
`MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES= mise install --locked`.

Upstream Just and Trellis releases are not immutable. Their locked checksums
prevent silent replacement, but availability still depends on the upstream
release assets. GitHub attestations establish build provenance only where the
lock says they were verified; they do not prove source safety.

## Dependency inventory and advisory results

The review covered the root, example, and eight package `gleam.toml` files and
their ten `manifest.toml` lockfiles, plus `website/package.json`,
`website/pnpm-lock.yaml`, `.tool-versions`, `.mise.toml`, `mise.lock`, all
workflows, composite actions, and workflow templates.

- The Gleam lockfiles contain 48 distinct Hex package/version pairs. The Hex API
  reported no retired locked release and no unresolved lookup.
- The shared verifier additions `ywt_core` 1.2.0 and `bigi` 4.1.1 are included
  in that inventory. Neither locked release is retired, and Dependabot reported
  no open alert for either package at review time.
- `bravo` is the only external Git dependency. It is pinned to commit
  `0f49223187fe57f646642ad0be12468c400401a2`; its repository was active and not
  archived, but the commit has no verified GitHub signature.
- `pnpm audit` initially reported 12 advisories: seven high, four moderate, and
  one low. The website lock was updated within its declared dependency ranges.
  A second audit reported zero known advisories.
- Dependabot can continue to show the old npm alerts until this lock reaches the
  default branch and GitHub refreshes the dependency graph.

Hex does not provide an advisory database equivalent to npm audit. Retirement
metadata is not proof that a package is maintained or safe. This review did not
run a universal multi-ecosystem advisory scanner because none is installed.
These are unresolved coverage limits, not a claim that the Gleam graph has no
vulnerabilities.

## Repository protections

The repository owner approved these settings during this review. The GitHub API
confirmed that they are active:

| Control | Applied setting |
| --- | --- |
| Workflow defaults | `GITHUB_TOKEN` defaults to read; workflow approval of pull requests is disabled |
| `main` ruleset `13298556` | Pull request with one approval, stale approvals dismissed, last-push approval, resolved review threads, squash-only linear history, no deletion or force push, and no bypass actors |
| Required checks | CI Security Policy, Format, Check, Lint, Build, Test, and Docs from GitHub Actions, with strict up-to-date checks |
| `release` environment | `tylerbutler` must approve; only the `main` branch can deploy; administrators cannot bypass approval |
| Package-tag creation ruleset `22369321` | Only the configured release App can create `vestibule-v*` and `vestibule_*-v*` tags |
| Package-tag immutability ruleset `22369322` | No actor, including the release App, can update or delete those tags |
| Moving-tag ruleset `22369319` | Only the release App can create, update, or delete `v[0-9]*` tags |
| Immutable GitHub Releases | Enabled for future published releases |

The `release` environment permits its designated reviewer to approve their own
dispatch. Approval is still an explicit human step, not an automatic or admin
bypass. Repository-level App secrets remain available to the reviewed
release-PR workflow; their values were not read or copied during this work.

Existing releases do not become immutable retroactively. Their tags are now
covered by the tag rules, but historical release assets retain their original
mutability. No release was deleted or republished to change that history.

These settings change the contributor workflow: direct pushes to `main` are
blocked, and an author cannot approve their own pull request. An emergency
change requires an administrator to make an explicit, recorded ruleset change,
then restore the protections. There is no standing administrator or release-App
bypass for `main` or immutable package tags.

Repository settings can drift independently of committed files. Recheck these
controls after an administrative change. The implementation follow-ups are
[#179](https://github.com/tylerbutler/vestibule/issues/179),
[#180](https://github.com/tylerbutler/vestibule/issues/180), and
[#181](https://github.com/tylerbutler/vestibule/issues/181).
