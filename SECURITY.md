# Security

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is intended for demos and prototypes that need real OAuth flows — do not
> use it in production.

## What that means

- No independent security audit or professional review has been performed.
- The security mechanisms vestibule implements (PKCE, CSRF state, HTTPS
  enforcement, JWT verification, OIDC nonce) are real code, but none of it has
  been vetted. Treat them as implemented mechanisms, not as assurance.
- The only review to date is an internal,
  [historical audit of v0.1.0](docs/security-audit-2026-02-25.md), which itself
  found issues. It is audit history, not a statement of current behavior.
- There are no security guarantees, no supported-versions policy, and no
  response SLA.

## Reporting issues

Security issues are still welcome — please open a
[GitHub issue](https://github.com/tylerbutler/vestibule/issues) (or a private
security advisory on the repository if the issue is sensitive). Reports will be
read with interest, but there is no committed response or fix timeline.
