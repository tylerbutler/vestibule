# vestibule_github

GitHub OAuth strategy for vestibule.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is for demos and prototypes that need real OAuth flows. Do not use it in
> production.

## Install

```sh
gleam add vestibule vestibule_github
```

Add `vestibule_wisp` or `vestibule_mist` if you use that middleware adapter.

## Register the OAuth app

1. Open **GitHub → Settings → Developer settings → OAuth Apps**.
2. Select **New OAuth App**.
3. Set the homepage URL and the exact **Authorization callback URL**.
4. Copy the client ID. Generate and copy a client secret.

GitHub OAuth Apps have one callback URL. Use separate OAuth Apps for local and
deployed environments:

- Local: `http://localhost:8000/auth/github/callback`
- HTTPS deployment: `https://demo.example/auth/github/callback`

The configured URI must exactly match `redirect_uri`. Vestibule permits plain
HTTP only for `localhost` and loopback addresses.

## Provider behavior

| Item | Behavior |
|---|---|
| Default and required scope | `user:email`; the callback fails if GitHub does not grant `user:email` or `user` |
| Client authentication | Client ID and secret in the token request form; use `config.client_secret_auth` |
| Callback | GET query parameters |
| Refresh | Supported when GitHub issues a refresh token, such as for an OAuth App with expiring user tokens enabled |
| Revocation | No revocation helper; use GitHub's application authorization API or account settings outside vestibule |
| Nonce | Not used; GitHub OAuth is not OIDC |
| Email | The callback requires the primary email to be verified; an absent verified primary email fails authentication |

PKCE and state validation are part of the shared vestibule flow.

## Minimal core flow

```gleam
import gleam/dict
import gleam/option
import vestibule
import vestibule/config
import vestibule_github

let strategy = vestibule_github.strategy()
let client_config =
  config.new(
    client_id: "github-client-id",
    redirect_uri: "http://localhost:8000/auth/github/callback",
    auth: config.client_secret_auth("github-client-secret"),
  )

let assert Ok(request) =
  vestibule.create_authorization_request(
    strategy,
    config: client_config,
    options: config.authorize_options(),
  )
// Store request.state and request.code_verifier in the server session, then
// redirect to request.url.

let params = dict.from_list([#("state", callback_state), #("code", callback_code)])
let result =
  vestibule.handle_callback(
    strategy,
    client_config,
    params,
    expected_state,
    stored_code_verifier,
    expected_nonce: option.None,
  )
```

Consume the stored state and PKCE verifier once. Do not restore them after a
failed callback.

## Minimal Wisp middleware

```gleam
import gleam/http
import vestibule/config
import vestibule/registry
import vestibule/state_store
import vestibule_github
import vestibule_wisp
import wisp

let assert Ok(registry) =
  registry.new()
  |> registry.register(
    vestibule_github.strategy(),
    config.new(
      client_id: "github-client-id",
      redirect_uri: "http://localhost:8000/auth/github/callback",
      auth: config.client_secret_auth("github-client-secret"),
    ),
  )
let assert Ok(store) = state_store.create()

case wisp.path_segments(request), request.method {
  ["auth", "github"], http.Get ->
    vestibule_wisp.request_phase_for_client(
      request,
      registry: registry,
      provider: "github",
      state_store: store,
      authorize_options: config.authorize_options(),
      client_key: client_key,
    )
  ["auth", "github", "callback"], http.Get ->
    vestibule_wisp.callback_phase(request, registry, "github", store, on_success)
  _, _ -> wisp.not_found()
}
```

For Mist, use the same registry with `vestibule_mist.request_phase` and
`vestibule_mist.callback_phase`.

## Diagnose setup errors

- **Redirect mismatch:** compare the complete callback URI, including scheme,
  host, port, path, and trailing slash.
- **Bad credentials:** confirm that the client secret value, not its label, is
  loaded in the environment for the correct OAuth App.
- **Scope failure:** do not remove `user:email`. The token response must grant
  `user:email` or `user`.
- **Email failure:** the GitHub account must have a primary, verified email.
- **State or PKCE failure:** use the same server-side session for request and
  callback, and consume each flow only once.
- **No refresh token:** GitHub does not issue refresh tokens for every OAuth
  App configuration. Refresh only when the token response contains one.
