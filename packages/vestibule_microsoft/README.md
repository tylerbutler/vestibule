# vestibule_microsoft

Microsoft OpenID Connect strategy for vestibule.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is for demos and prototypes that need real OAuth flows. Do not use it in
> production.

## Install

```sh
gleam add vestibule vestibule_microsoft
```

Add `vestibule_wisp` or `vestibule_mist` if you use that middleware adapter.

## Register the application

1. Open **Microsoft Entra ID → App registrations → New registration**.
2. Select the supported account types. The default vestibule strategy uses the
   `/common` authority and accepts eligible personal and work/school accounts.
3. Add a **Web** redirect URI.
4. Copy the **Application (client) ID**.
5. Open **Certificates & secrets**, create a client secret, and copy its
   **Value**.
6. Add delegated permissions for `openid`, `profile`, and `User.Read`. Grant
   admin consent if the tenant requires it.

Callback examples:

- Local: `http://localhost:8000/auth/microsoft/callback`
- HTTPS deployment: `https://demo.example/auth/microsoft/callback`

The configured URI must exactly match `redirect_uri`. Vestibule permits plain
HTTP only for `localhost` and loopback addresses.

## Provider behavior

| Item | Behavior |
|---|---|
| Default scopes | `openid profile User.Read` |
| Client authentication | Client ID and secret in the token request form; use `config.client_secret_auth` |
| Callback | GET query parameters |
| Refresh | Supported; add `offline_access` to request a refresh token |
| Revocation | No revocation helper; use Microsoft account or Graph controls outside vestibule |
| Nonce | Generated and checked against the verified Microsoft ID token |
| Email | Not exposed as verified email; `userPrincipalName` is kept as the nickname |

The strategy uses Microsoft Graph `/me`. PKCE and state validation are part of
the shared vestibule flow.

## Minimal core flow

```gleam
import gleam/dict
import vestibule
import vestibule/config
import vestibule_microsoft

let strategy = vestibule_microsoft.strategy()
let client_config =
  config.new(
    client_id: "microsoft-client-id",
    redirect_uri: "http://localhost:8000/auth/microsoft/callback",
    auth: config.client_secret_auth("microsoft-client-secret"),
  )

let assert Ok(request) =
  vestibule.create_authorization_request(
    strategy,
    config: client_config,
    options: config.authorize_options(),
  )
// Store request.state, request.code_verifier, and request.nonce in the server
// session, then redirect to request.url.

let params = dict.from_list([#("state", callback_state), #("code", callback_code)])
let result =
  vestibule.handle_callback(
    strategy,
    client_config,
    params,
    expected_state,
    stored_code_verifier,
    expected_nonce: stored_nonce,
  )
```

Consume the stored state, PKCE verifier, and nonce once.

## Minimal Wisp middleware

```gleam
import gleam/http
import vestibule/config
import vestibule/registry
import vestibule/state_store
import vestibule_microsoft
import vestibule_wisp
import wisp

let assert Ok(registry) =
  registry.new()
  |> registry.register(
    vestibule_microsoft.strategy(),
    config.new(
      client_id: "microsoft-client-id",
      redirect_uri: "http://localhost:8000/auth/microsoft/callback",
      auth: config.client_secret_auth("microsoft-client-secret"),
    ),
  )
let assert Ok(store) = state_store.create()

case wisp.path_segments(request), request.method {
  ["auth", "microsoft"], http.Get ->
    vestibule_wisp.request_phase_for_client(
      request,
      registry: registry,
      provider: "microsoft",
      state_store: store,
      authorize_options: config.authorize_options(),
      client_key: client_key,
    )
  ["auth", "microsoft", "callback"], http.Get ->
    vestibule_wisp.callback_phase(
      request,
      registry,
      "microsoft",
      store,
      on_success,
    )
  _, _ -> wisp.not_found()
}
```

For Mist, use the same registry with `vestibule_mist.request_phase` and
`vestibule_mist.callback_phase`.

## Tenant choice

`strategy()` uses `/common` and does not restrict sign-in to one organization.
For one tenant, pass its directory GUID:

```gleam
let strategy =
  vestibule_microsoft.strategy_for_tenant(
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
  )
```

Do not pass a verified domain. The strategy validates the signed `tid` and
`oid` claims and checks that Graph `/me.id` matches `oid`.

To request refresh tokens, replace the defaults with all required scopes:

```gleam
let options =
  config.authorize_options()
  |> config.with_scopes(["openid", "profile", "User.Read", "offline_access"])
```

## Diagnose setup errors

- **Redirect mismatch:** compare the complete URI, including scheme, host,
  port, path, and trailing slash.
- **Secret failure:** use the client secret **Value**, not its secret ID.
- **Consent failure:** confirm delegated `User.Read` permission and tenant
  consent policy.
- **Wrong accounts:** make the Entra supported-account setting match `/common`,
  or use `strategy_for_tenant` with the tenant GUID.
- **Nonce or tenant failure:** keep the nonce from the same session and confirm
  that the selected account belongs to the expected tenant.
- **Missing email:** this strategy does not claim that
  `userPrincipalName` is a verified email.
- **No refresh token:** request `offline_access`.
