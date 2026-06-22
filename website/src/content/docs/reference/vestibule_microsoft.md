---
title: "vestibule_microsoft"
description: "Microsoft Identity Platform (v2.0) strategy."
nav:
  group: Reference
  groupOrder: 20
  order: 28
  label: "vestibule_microsoft"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_microsoft
---

# `vestibule_microsoft`

Microsoft Identity Platform (v2.0) strategy.

Requests `User.Read` by default. Tokens are exchanged against
`/oauth2/v2.0/token`; user info comes from Microsoft Graph `/me`.

## Tenant isolation

`strategy()` uses the `/common` authority, which accepts personal Microsoft
accounts and work/school accounts from **any** Microsoft Entra tenant that
can consent to the app. It does **not** restrict logins to one organization
and performs no tenant validation — use it only for explicitly multi-tenant
apps.

For single-organization apps use `strategy_for_tenant(tenant_id)`. It targets
the tenant-specific authority endpoints and additionally verifies the `tid`
(tenant id) claim in the returned OpenID Connect ID token, failing
authentication when the token was issued by a different tenant.

## Functions

### `id_token_tenant`

Extract the `tid` (tenant id) claim from a Microsoft ID token's payload.

Decodes the JWT payload segment (base64url) and reads the `tid` claim. Does
not verify the JWT signature — see `verify_tenant` for the trust rationale.

```gleam
pub fn id_token_tenant(String) -> Result(String, error.AuthError(a))
```

### `parse_token_response`

Parse Microsoft token response JSON.

```gleam
pub fn parse_token_response(String) -> Result(credentials.Credentials, error.AuthError(a))
```

### `parse_user_response`

Parse Microsoft Graph /me response JSON.

```gleam
pub fn parse_user_response(String) -> Result(#(String, user_info.UserInfo), error.AuthError(a))
```

### `strategy`

Create a Microsoft authentication strategy using the `/common` authority.

**Security warning:** `/common` accepts personal Microsoft accounts and
work/school accounts from any Microsoft Entra tenant that can consent to the
app, and this strategy performs **no** tenant validation. Use it only for
explicitly multi-tenant apps. For single-organization apps, use
`strategy_for_tenant` so logins are restricted to one tenant and the tenant
is verified against the ID token.

```gleam
pub fn strategy() -> strategy.Strategy(a)
```

### `strategy_for_tenant`

Create a Microsoft authentication strategy locked to a single tenant.

`tenant_id` must be the tenant's directory (tenant) **GUID**, e.g.
`"72f988bf-86f1-41af-91ab-2d7cd011db47"`. The strategy uses the
tenant-specific authority endpoints
(`https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/...`) so
Microsoft itself only issues tokens for that tenant, and additionally
requests the `openid` scope and verifies that the `tid` claim in the
returned ID token equals `tenant_id` (case-insensitive). Authentication
fails if the ID token is missing or was issued by a different tenant.

Pass the tenant GUID rather than a verified domain (e.g.
`contoso.onmicrosoft.com`): the `tid` claim is always a GUID, so domain
values cannot be matched and would reject otherwise-valid logins.

```gleam
pub fn strategy_for_tenant(String) -> strategy.Strategy(a)
```

### `verify_tenant`

Verify that a Microsoft OpenID Connect ID token was issued by the expected
tenant.

Reads the `tid` (tenant id) claim from the ID token payload and compares it,
case-insensitively, against `expected_tenant`. Returns the token's `tid` on
success, or an `AuthError` when the claim is missing, malformed, or belongs
to a different tenant.

The ID token is delivered to the client over the back-channel directly from
Microsoft's token endpoint over TLS, so its payload is trusted without a
separate JWKS signature check (OpenID Connect Core 1.0, section 3.1.3.7).

```gleam
pub fn verify_tenant(
  expected_tenant: String,
  id_token: String
) -> Result(String, error.AuthError(a))
```
