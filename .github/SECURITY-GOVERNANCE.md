# Repository security governance

This repository uses read-only workflow credentials by default:

```yaml
permissions:
  contents: read
```

Workflows must request additional permissions only at the job or step that
needs them. Release writes use the Release App token, not the default
`GITHUB_TOKEN`.

## Protected `main`

The `main` branch ruleset must enforce:

- pull requests with at least one approving review;
- no stale approval after new commits;
- resolved review threads;
- required checks for the exact merge commit:
  - `CI Security Policy`;
  - `Format`;
  - `Check`;
  - `Lint`;
  - `Build`;
  - `Test`;
  - `Docs`;
- no deletion or force-push;
- squash merges only.

The ruleset has no bypass actors. Repository administrators must use the
documented break-glass process below for an emergency.

## Break-glass process

Use a break-glass bypass only for an active incident or an urgent recovery
that cannot wait for normal review. Record the reason, approver, actor,
commit SHA, and follow-up remediation in a private incident record. Restore
the ruleset immediately after the action and open a public follow-up issue.
