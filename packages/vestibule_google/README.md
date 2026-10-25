# vestibule_google

Google OpenID Connect strategy for vestibule.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is for demos and prototypes that need real OAuth flows. Do not use it in
> production.

## Install

```sh
gleam add vestibule vestibule_google
```

Add `vestibule_wisp` or `vestibule_mist` if you use that middleware adapter.

## Register the OAuth client

1. In [Google Cloud Console](https://console.cloud.google.com/), create or
   select a project.
2. Configure **Google Auth platform → Branding**, **Audience**, and **Data
   Access**. Add `openid`, `email`, and `profile`.
3. Open **Clients → Create client → Web application**.
4. Add each exact authorized redirect URI.
5. Copy the client ID and client secret.

Callback examples:

- Local: `http://localhost:8000/auth/google/callback`
- HTTPS deployment: `https://demo.example/auth/google/callback`

The configured URI must exactly match `redirect_uri`. Vestibule permits plain
HTTP only for `localhost` and loopback addresses.

## Provider behavior

| Item | Behavior |
|---|---|
| Default and required scopes | `openid profile email`; token parsing requires all three |
| Client authentication | Client ID and secret in the token request form; use `config.client_secret_auth` |
| Callback | GET query parameters |
| Refresh | Supported; request offline access as shown below |
| Revocation | No revocation helper; call Google's revocation endpoint outside vestibule if needed |
| Nonce | Generated and checked against the verified Google ID token |
| Email | Exposed only when Google returns `email_verified: true` |

The strategy verifies the Google ID token signature and identity claims. PKCE
and state validation are part of the shared vestibule flow.

## Minimal core flow

```gleam
import gleam/dict
import vestibule
import vestibule/config
import vestibule_google

let strategy = vestibule_google.strategy()
let client_config =
  config.new(
    client_id: "google-client-id",
    redirect_uri: "http://localhost:8000/auth/google/callback",
    auth: config.client_secret_auth("google-client-secret"),
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
import vestibule_google
import vestibule_wisp
import wisp

let assert Ok(registry) =
  registry.new()
  |> registry.register(
    vestibule_google.strategy(),
    config.new(
      client_id: "google-client-id",
      redirect_uri: "http://localhost:8000/auth/google/callback",
      auth: config.client_secret_auth("google-client-secret"),
    ),
  )
let assert Ok(store) = state_store.create()

case wisp.path_segments(request), request.method {
  ["auth", "google"], http.Get ->
    vestibule_wisp.request_phase_for_client(
      request,
      registry: registry,
      provider: "google",
      state_store: store,
      authorize_options: config.authorize_options(),
      client_key: client_key,
    )
  ["auth", "google", "callback"], http.Get ->
    vestibule_wisp.callback_phase(request, registry, "google", store, on_success)
  _, _ -> wisp.not_found()
}
```

For Mist, use the same registry with `vestibule_mist.request_phase` and
`vestibule_mist.callback_phase`.

## Refresh tokens

Google can omit a refresh token after the user has already approved the app.
Request offline access and, when necessary, a new consent prompt:

```gleam
let assert Ok(options) =
  config.authorize_options()
  |> config.with_extra_parameters([
    #("access_type", "offline"),
    #("prompt", "consent"),
  ])
```

Use the returned refresh token with `vestibule.refresh_token`.

## Restrict a Workspace domain

The `hd` authorization parameter is only an account-picker hint. To enforce a
domain, use:

```gleam
let strategy = vestibule_google.strategy_for_hosted_domain("corp.example")
```

This checks the signed ID token `hd` claim. A missing or different claim fails
authentication.

## Diagnose setup errors

- **Redirect mismatch:** compare the complete URI, including scheme, host,
  port, path, and trailing slash.
- **Consent or audience error:** confirm that the test user is allowed by the
  consent-screen audience and that the required scopes are configured.
- **Nonce failure:** keep the nonce from the same request-phase session and do
  not reuse it.
- **Missing email:** Google returned no verified email. Do not treat another
  profile field as verified email.
- **No refresh token:** add `access_type=offline`; use `prompt=consent` when a
  previous grant causes Google to omit the token.
- **Workspace restriction failure:** use `strategy_for_hosted_domain`; an `hd`
  query parameter alone does not enforce access.
