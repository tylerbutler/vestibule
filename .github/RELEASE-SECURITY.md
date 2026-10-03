# Release security

Releases are created only by the Release App after the reviewed merge commit
passes the trusted CI gate in `.github/workflows/release.yml`.

## Tag rules

Use separate repository tag rulesets:

| Tag pattern | Allowed operations | Bypass |
| --- | --- | --- |
| `vestibule-v*`, `vestibule_*-v*` | create by the Release App; no update or deletion | Release App only |
| `v<major>`, `v<major>.<minor>` | create, update, or delete by the Release App | Release App only |

Exact package tags are immutable after creation. Moving series tags are
mutable only because the Release App advances them for a newer release.
Administrators must not bypass these rules during normal release work.

## GitHub Releases

Enable immutable releases in the repository settings. Verify the setting and
the published release state before a release window:

```sh
gh api repos/tylerbutler/vestibule \
  --jq '.security_and_analysis'
gh api repos/tylerbutler/vestibule/releases \
  --jq '.[] | {tag_name, immutable}'
```

An immutable release must not allow an existing release body or asset to be
replaced. A failed release must create a new version rather than rewriting
the old tag or release.
