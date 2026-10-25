# vestibule_apple

Sign in with Apple strategy for vestibule.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is for demos and prototypes that need real OAuth flows. Do not use it in
> production.

## Install

```sh
gleam add vestibule vestibule_apple
```

Add `vestibule_wisp` or `vestibule_mist` if you use that middleware adapter.

## Register the service

1. In [Apple Developer](https://developer.apple.com/account), create an App ID
   and enable **Sign in with Apple**.
2. Create a Services ID. This is the OAuth client ID.
3. Configure Sign in with Apple for the Services ID. Add the domain and each
   exact return URL.
4. Create a Sign in with Apple key, associate it with the App ID, and download
   its `.p8` file. Apple offers the file once.
5. Record the Team ID and Key ID.

Apple rejects `localhost` and plain HTTP callbacks. For local work, use a stable
HTTPS tunnel:

- Local through a tunnel: `https://vestibule-demo.ngrok.app/auth/apple/callback`
- HTTPS deployment: `https://demo.example/auth/apple/callback`

Add the matching domains and return URLs in the Services ID settings.

## Provider behavior

| Item | Behavior |
|---|---|
| Default scopes | `name email` |
| Client authentication | ES256 client-secret JWT in the token request form |
| Callback | POST with `response_mode=form_post`; accept form data, not only a query string |
| Refresh | Supported when Apple issues a refresh token |
| Revocation | No revocation helper; call Apple's revoke endpoint outside vestibule if needed |
| Nonce | Generated and checked against the verified Apple ID token |
| Email | Exposed only when the verified ID token says `email_verified` is true |

Apple sends the name only on the first consent. Save it after that callback.
The strategy reads identity from the verified ID token; Apple has no userinfo
request in this flow.

## Build and rotate the client secret

Vestibule includes the current `.p8` signing helper:

```gleam
let assert Ok(client_secret) =
  vestibule_apple.build_client_secret(
    team_id: "A1B2C3D4E5",
    client_id: "com.example.demo",
    key_id: "1A2B3C4D5E",
    p8_pem: p8_pem,
    ttl: 3600,
  )
```

The helper accepts one unencrypted PKCS#8 P-256 private key and signs the Apple
client-secret JWT with ES256. The TTL must be from 1 through 15,777,000 seconds.
Prefer a short TTL and create a new JWT when needed.

Keep the `.p8` key outside the repository. For local work, load a path from an
environment variable. In a deployment, load the key from the platform secret
store. If the store supports only single-line values, store the PEM as base64
and decode it at startup.

To rotate the key:

1. Create a new Apple key and deploy its `.p8` file and Key ID.
2. Confirm that code exchange works with the new key.
3. Revoke the old key only after all running instances use the new key.

## Minimal core flow

```gleam
import gleam/dict
import vestibule
import vestibule/config
import vestibule_apple

let assert Ok(apple) = vestibule_apple.initialize()
let strategy = vestibule_apple.strategy(apple)
let assert Ok(client_secret) =
  vestibule_apple.build_client_secret(
    team_id: "A1B2C3D4E5",
    client_id: "com.example.demo",
    key_id: "1A2B3C4D5E",
    p8_pem: p8_pem,
    ttl: 3600,
  )
let client_config =
  config.new(
    client_id: "com.example.demo",
    redirect_uri: "https://vestibule-demo.ngrok.app/auth/apple/callback",
    auth: config.client_secret_auth(client_secret),
  )

let assert Ok(request) =
  vestibule.create_authorization_request(
    strategy,
    config: client_config,
    options: config.authorize_options(),
  )
// Store state, code verifier, and nonce in the server session. Parse the
// callback parameters from the POST form body.

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

Call `initialize()` once per BEAM VM. Consume the stored state, PKCE verifier,
and nonce once.

## Minimal Wisp middleware

```gleam
let assert Ok(apple) = vestibule_apple.initialize()
let assert Ok(registry) =
  registry.new()
  |> registry.register(
    vestibule_apple.strategy(apple),
    config.new(
      client_id: "com.example.demo",
      redirect_uri: "https://vestibule-demo.ngrok.app/auth/apple/callback",
      auth: config.client_secret_auth(client_secret),
    ),
  )
let assert Ok(store) = state_store.create()

case wisp.path_segments(request), request.method {
  ["auth", "apple"], http.Get ->
    vestibule_wisp.request_phase_for_client(
      request,
      registry: registry,
      provider: "apple",
      state_store: store,
      authorize_options: config.authorize_options(),
      client_key: client_key,
    )
  ["auth", "apple", "callback"], http.Post ->
    vestibule_wisp.callback_phase(request, registry, "apple", store, on_success)
  _, _ -> wisp.not_found()
}
```

The Wisp and Mist callback helpers parse form-post callbacks and reject
duplicate parameters. For Mist, use `vestibule_mist.request_phase` and
`vestibule_mist.callback_phase`.

## Diagnose setup errors

- **Invalid redirect:** Apple requires an allowed HTTPS return URL and domain.
  It does not accept `localhost`.
- **Invalid client:** make the Services ID, Team ID, Key ID, and `.p8` key come
  from the same Apple Developer setup.
- **Invalid private key:** load the complete unencrypted PKCS#8 P-256 PEM,
  including line breaks.
- **Expired client secret:** create a new JWT. Check the host clock if a new
  token is rejected.
- **GET callback handler:** Apple posts form data. Add a POST route and let the
  middleware parse the body.
- **Missing name:** Apple sends it only on the first consent.
- **Cache initialization failure:** call `initialize()` once at application
  startup and reuse the returned handle.
- **Nonce or state failure:** keep all values in the same one-time session.
