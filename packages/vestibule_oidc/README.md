# vestibule_oidc

Generic OpenID Connect discovery strategy for vestibule.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is for demos and prototypes that need real OAuth flows. Do not use it in
> production.

## Install

```sh
gleam add vestibule vestibule_oidc
```

Add `vestibule_wisp` or `vestibule_mist` if you use that middleware adapter.

## Register the client

The provider console names differ, but the required setup is the same:

1. Create an OIDC web client.
2. Add each exact redirect URI.
3. Enable authorization code flow and the `openid` scope.
4. Enable `profile` and `email` if you need those claims.
5. Copy the client ID and select an authentication method that vestibule
   supports.
6. Use the provider's exact issuer URL for discovery.

Callback examples:

- Local: `http://localhost:8000/auth/oidc/callback`
- HTTPS deployment: `https://demo.example/auth/oidc/callback`

The redirect URI may use local HTTP as shown. The issuer and all discovered
server endpoints must use public HTTPS and cannot resolve to local or private
addresses.

## Provider behavior

| Item | Behavior |
|---|---|
| Default scopes | Supported values from `openid profile email`; falls back to `openid` |
| Client authentication | Public, client secret in the form, or JWT client assertion in the form |
| Callback | GET query parameters by default; callback `iss` is required when discovery advertises RFC 9207 support |
| Refresh | Supported when the provider issues a refresh token |
| Revocation | Revocation endpoint discovery and token revocation are not implemented |
| Nonce | Generated and checked against the verified ID token |
| Email | Exposed only when UserInfo returns `email_verified: true` |

The generic strategy accepts only RS256 ID tokens. It verifies signature,
issuer, audience, authorized party, lifetime, nonce, and that UserInfo `sub`
matches the ID-token `sub`. Discovery must provide `jwks_uri`,
`userinfo_endpoint`, and supported ID-token algorithms.

Current token requests do not use HTTP Basic authentication. A confidential
client secret is sent as `client_secret` in the form. A client assertion is
sent as `client_assertion` with the JWT bearer assertion type. Confirm that the
provider accepts the selected method.

## Minimal core flow

```gleam
import gleam/dict
import vestibule
import vestibule/config
import vestibule_oidc

let issuer = "https://id.example"
let assert Ok(strategy) = vestibule_oidc.discover(issuer)
let client_config =
  config.new(
    client_id: "oidc-client-id",
    redirect_uri: "http://localhost:8000/auth/oidc/callback",
    auth: config.client_secret_auth("oidc-client-secret"),
  )

let assert Ok(request) =
  vestibule.create_authorization_request(
    strategy,
    config: client_config,
    options: config.authorize_options(),
  )
// Store state, code verifier, and nonce in the server session.

let params =
  dict.from_list([
    #("state", callback_state),
    #("code", callback_code),
    #("iss", callback_issuer),
  ])
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

Include `iss` only when the provider sends it. Consume the stored state, PKCE
verifier, and nonce once.

## Minimal Wisp middleware

Discover and register the provider once at startup:

```gleam
let issuer = "https://id.example"
let assert Ok(strategy) = vestibule_oidc.discover(issuer)
let assert Ok(registry) =
  registry.new()
  |> registry.register(
    strategy,
    config.new(
      client_id: "oidc-client-id",
      redirect_uri: "http://localhost:8000/auth/oidc/callback",
      auth: config.client_secret_auth("oidc-client-secret"),
    ),
  )
let assert Ok(store) = state_store.create()

case wisp.path_segments(request), request.method {
  ["auth", "oidc"], http.Get ->
    vestibule_wisp.request_phase_for_client(
      request,
      registry: registry,
      provider: issuer,
      state_store: store,
      authorize_options: config.authorize_options(),
      client_key: client_key,
    )
  ["auth", "oidc", "callback"], http.Get ->
    vestibule_wisp.callback_phase(request, registry, issuer, store, on_success)
  _, _ -> wisp.not_found()
}
```

The registry key is the full exact issuer, including a path, port, or trailing
slash. If the key is put in a route segment, percent-encode it. The fixed
`"oidc"` route above passes the issuer explicitly.

For Mist, use the same registry with `vestibule_mist.request_phase` and
`vestibule_mist.callback_phase`.

## Client authentication choices

```gleam
// No client credential
config.public_client()

// client_secret_post
config.client_secret_auth("client-secret")

// private_key_jwt or another accepted JWT assertion
config.client_assertion_auth(client_assertion)
```

Vestibule sends the assertion but does not build or rotate it.

## Diagnose setup errors

- **Discovery rejected:** use the provider's exact public HTTPS issuer. The
  discovery document `issuer` must match it exactly.
- **Unsupported signing algorithm:** the discovery document must advertise
  RS256.
- **Missing metadata:** `jwks_uri` and `userinfo_endpoint` are required.
- **Token endpoint rejects the client:** confirm that it accepts public,
  `client_secret_post`, or the supplied client assertion. HTTP Basic is not
  used.
- **Redirect mismatch:** compare the complete URI, including scheme, host,
  port, path, and trailing slash.
- **Nonce, issuer, or subject failure:** keep callback data with the same
  one-time session and do not combine ID-token and UserInfo data from
  different flows.
- **Missing email:** UserInfo did not mark the email as verified.
- **No refresh token:** request the provider-specific offline-access scope or
  parameter that its documentation requires.
