---
name: vestibule_microsoft
navLabel: Microsoft strategy
kind: Provider strategy
summary: Microsoft OAuth strategy using Microsoft Graph /me, with helpers for tenant-specific sign-in.
install:
  - gleam add vestibule_microsoft
useWhen: Use Microsoft when users authenticate with Microsoft personal, work, or school accounts.
defaultScopes: openid User.Read
setup:
  - Create a Microsoft Entra ID app registration.
  - Choose supported account types that match your tenant behavior.
  - Add Web redirect URIs for development and production.
  - Copy the Application client ID and client secret value.
highlights:
  - The default strategy uses /common and performs no tenant validation.
  - strategy_for_tenant targets tenant-specific endpoints.
  - Tenant validation checks the tid claim in the returned ID token.
  - userPrincipalName is exposed as nickname, not verified email.
code: |
  import vestibule/config
  import vestibule_microsoft

  let strategy = vestibule_microsoft.strategy()

  let tenant_strategy =
    vestibule_microsoft.strategy_for_tenant(
      "72f988bf-86f1-41af-91ab-2d7cd011db47",
    )

  let cfg =
    config.new(
      client_id: "microsoft-client-id",
      redirect_uri: "http://localhost:8000/auth/microsoft/callback",
      auth: config.ClientSecret("microsoft-client-secret"),
    )
notes:
  - Pass the tenant GUID, not a verified domain, when restricting to one tenant.
  - Microsoft Graph /me does not include profile photos; fetch photos separately if needed.
navOrder: 50
searchTerms:
  - entra
  - tenant
  - graph
  - work school accounts
---
