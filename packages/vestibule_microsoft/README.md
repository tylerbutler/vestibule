# vestibule_microsoft

Microsoft OAuth strategy for vestibule using the `/common` tenant endpoints.

## Install

```sh
gleam add vestibule_microsoft
```

## Usage

```gleam
import vestibule/config
import vestibule_microsoft

let strategy = vestibule_microsoft.strategy()
let cfg =
  config.new(
    "microsoft-client-id",
    "microsoft-client-secret",
    "http://localhost:8000/auth/microsoft/callback",
  )
```

The strategy uses Microsoft Graph `/me` for profile data and keeps
`userPrincipalName` as the nickname rather than treating it as a verified email.

## Tenant behavior

The built-in strategy uses Microsoft Entra ID's `/common` tenant:

```text
https://login.microsoftonline.com/common/oauth2/v2.0
```

This allows both personal Microsoft accounts and work/school accounts from any
tenant that can consent to your app. It is convenient for general sign-in, but it
does not restrict authentication to one organization.

For tenant-restricted apps, use one of these alternatives:

- Build an OIDC strategy from tenant-specific endpoints, such as
  `https://login.microsoftonline.com/<tenant-id>/v2.0`.
- Write a small custom strategy that uses the same Microsoft Graph `/me` parsing
  but replaces `/common` with your tenant ID or tenant domain.

## Extra authorization parameters

Use `config.with_extra_params` for Microsoft-specific authorization options:

```gleam
let cfg =
  config.new(
    "microsoft-client-id",
    "microsoft-client-secret",
    "http://localhost:8000/auth/microsoft/callback",
  )
  |> config.with_extra_params([
    #("prompt", "select_account"),
    #("login_hint", "person@example.com"),
  ])
```

Useful parameters include `prompt=select_account` to force account selection,
`prompt=consent` to force a consent prompt, `login_hint` to pre-fill the account
identifier, and `domain_hint` to streamline home-realm discovery for a tenant.

## Profile images

Microsoft Graph `/me` does not include profile photos. The built-in strategy
sets `UserInfo.image` to `None`; if your app needs photos, request the
additional Microsoft Graph photo permissions and fetch the photo separately.
