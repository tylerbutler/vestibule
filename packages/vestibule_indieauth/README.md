# vestibule_indieauth

IndieAuth strategy for vestibule. Users sign in with a URL that they control.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is for demos and prototypes that need real OAuth flows. Do not use it in
> production.

## Install

```sh
gleam add vestibule vestibule_indieauth
```

Add `vestibule_wisp` or `vestibule_mist` if you use that middleware adapter.

## Register the client

IndieAuth has no common provider console. Your app's `client_id` is a URL. The
user's profile points to an authorization server, and vestibule discovers its
authorization, token, and optional userinfo endpoints.

Publish client metadata at the client ID URL when the authorization server
requires it. Configure the callback with that server as required.

Callback examples:

- Local: `http://localhost:8000/auth/indieauth/callback`
- HTTPS deployment: `https://demo.example/auth/indieauth/callback`

For a local callback, keep a stable HTTPS client ID, such as
`https://demo.example/`, if the authorization server must fetch client
metadata. User profile URLs and discovered endpoints must be public HTTPS.
They cannot use localhost, private, link-local, or `.local` hosts.

## Provider behavior

| Item | Behavior |
|---|---|
| Default scope | `profile`; add `email` only when the authorization server supports it |
| Client authentication | Public client; use `config.public_client()` |
| Callback | GET query parameters; metadata-based servers can also require an exact callback `iss` |
| Refresh | Supported when the authorization server issues a refresh token |
| Revocation | No revocation discovery or helper |
| Nonce | Not used |
| Email | Optional profile data; vestibule does not claim that IndieAuth email data is verified |

State and PKCE validation are part of the shared vestibule flow. The token
response `me` URL establishes identity only after vestibule confirms it against
the authorization server used by the flow.

## Minimal core flow

```gleam
import gleam/dict
import gleam/option
import vestibule
import vestibule/config
import vestibule_indieauth

let assert Ok(#(endpoints, me)) =
  vestibule_indieauth.discover_endpoints_with_me(user_profile_url)
let strategy = vestibule_indieauth.strategy(endpoints, me)
let client_config =
  config.new(
    client_id: "https://demo.example/",
    redirect_uri: "http://localhost:8000/auth/indieauth/callback",
    auth: config.public_client(),
  )
let options =
  config.authorize_options()
  |> config.with_scopes(["profile", "email"])

let assert Ok(request) =
  vestibule.create_authorization_request(
    strategy,
    config: client_config,
    options: options,
  )
// Store state, code verifier, and
// vestibule_indieauth.serialize_endpoints(endpoints, me) in the session.

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
    expected_nonce: option.None,
  )
```

On callback, use `parse_endpoints` and `strategy` to restore the same strategy
without a second discovery request.

## Minimal Wisp middleware

The registry middleware works when one discovered IndieAuth strategy is known
before requests start. This is useful for a fixed demo identity:

```gleam
let assert Ok(strategy) =
  vestibule_indieauth.discover("https://user.example/")
let assert Ok(registry) =
  registry.new()
  |> registry.register(
    strategy,
    config.new(
      client_id: "https://demo.example/",
      redirect_uri: "http://localhost:8000/auth/indieauth/callback",
      auth: config.public_client(),
    ),
  )
let assert Ok(store) = state_store.create()

case wisp.path_segments(request), request.method {
  ["auth", "indieauth"], http.Get ->
    vestibule_wisp.request_phase_for_client(
      request,
      registry: registry,
      provider: "indieauth",
      state_store: store,
      authorize_options: config.authorize_options(),
      client_key: client_key,
    )
  ["auth", "indieauth", "callback"], http.Get ->
    vestibule_wisp.callback_phase(
      request,
      registry,
      "indieauth",
      store,
      on_success,
    )
  _, _ -> wisp.not_found()
}
```

For user-entered profile URLs, discover and persist the endpoints per session,
then use the core callback flow. A single startup registry entry cannot
represent different endpoints for each user.

## Diagnose setup errors

- **Profile rejected before discovery:** use a public HTTPS profile URL. Local
  and private network destinations are intentionally blocked.
- **Missing endpoints:** publish IndieAuth metadata or the required link
  relations on the profile page.
- **Issuer mismatch:** restore the same discovered endpoints for the callback
  and pass the callback `iss` parameter.
- **`me` mismatch:** the token or userinfo endpoint returned an identity that
  the original authorization server does not confirm.
- **Client ID error:** use an app URL, not an opaque client identifier. Publish
  metadata there if the authorization server requires it.
- **No email:** request `email` only if supported, and treat it as optional,
  unverified profile data.
- **No refresh token:** the authorization server controls whether it issues
  one.
