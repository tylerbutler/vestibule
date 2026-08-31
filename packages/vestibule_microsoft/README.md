# vestibule_microsoft

Microsoft OAuth strategy for vestibule using the `/common` tenant endpoints.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is intended for demos and prototypes that need real OAuth flows — do not
> use it in production.

## Install

```sh
gleam add vestibule_microsoft
```

## Usage

```gleam
import vestibule/config
import vestibule_microsoft

let strategy = vestibule_microsoft.strategy()
let client_config =
  config.new(
    client_id: "microsoft-client-id",
    redirect_uri: "http://localhost:8000/auth/microsoft/callback",
    auth: config.ClientSecret("microsoft-client-secret"),
  )
```

The strategy uses Microsoft Graph `/me` for profile data and keeps
`userPrincipalName` as the nickname rather than treating it as a verified email.

## Default scopes

`openid User.Read`. Request different Microsoft permissions per request with
`config.with_scopes` on `AuthorizeOptions`; `openid` is still included for nonce
validation.

## Azure portal setup

1. Sign in to <https://portal.azure.com/> and open **Microsoft Entra ID
   → App registrations → New registration**.
2. **Supported account types**: pick one that matches the tenant
   behavior section below (most apps want
   *Accounts in any organizational directory and personal Microsoft
   accounts*).
3. **Redirect URI**: platform *Web*, value
   `http://localhost:8000/auth/microsoft/callback` for dev (add the
   HTTPS production URI as a second entry).
4. After creation, copy the **Application (client) ID**.
5. **Certificates & secrets → New client secret** → copy the secret
   `Value` (not the ID). It is shown once.
6. **API permissions**: the default `openid` plus `User.Read` (delegated)
   scopes are enough for nonce validation and the built-in Graph `/me` parsing;
   click **Grant admin consent** if your tenant requires it.

## Tenant behavior

By default, `vestibule_microsoft.strategy()` uses Microsoft Entra ID's `/common`
tenant:

```text
https://login.microsoftonline.com/common/oauth2/v2.0
```

This allows both personal Microsoft accounts and work/school accounts from any
tenant that can consent to your app, and it performs **no** tenant validation. It
is convenient for general sign-in, but it does **not** restrict authentication to
one organization. Use it only for explicitly multi-tenant apps.

### Restricting to a single tenant

For single-organization apps, use `strategy_for_tenant`:

```gleam
import vestibule_microsoft

// Pass your tenant's directory (tenant) GUID:
let strategy =
  vestibule_microsoft.strategy_for_tenant("72f988bf-86f1-41af-91ab-2d7cd011db47")
```

This:

- targets the tenant-specific authority endpoints
  (`https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/...`), so Microsoft
  only issues tokens for that tenant; and
- requests the `openid` scope and verifies that the `tid` (tenant id) claim in
  the returned ID token equals the configured tenant (case-insensitive), failing
  authentication when the ID token is missing or was issued by a different
  tenant.

Pass the tenant **GUID** rather than a verified domain
(e.g. `contoso.onmicrosoft.com`): the `tid` claim is always a GUID, so domain
values cannot be matched and would reject otherwise-valid logins.

If you need lower-level control, `verify_tenant(expected_tenant, id_token)` and
`id_token_tenant(id_token)` expose the tenant-claim checks directly.


## Extra authorization parameters

Use `config.with_extra_params` on per-request options for Microsoft-specific authorization options:

```gleam
let assert Ok(options) =
  config.authorize_options()
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
returns `None` from the image accessor; if your app needs photos, request the
additional Microsoft Graph photo permissions and fetch the photo separately.
