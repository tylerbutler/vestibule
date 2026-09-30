# vestibule_apple

Apple Sign In strategy for vestibule.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is intended for demos and prototypes that need real OAuth flows — do not
> use it in production.

## Install

```sh
gleam add vestibule_apple
```

## Usage

```gleam
import vestibule_apple

let assert Ok(apple) = vestibule_apple.initialize()
let strategy = vestibule_apple.strategy(apple)
```

`initialize()` initializes the JWKS cache used to verify Apple ID tokens. It no
longer initializes an ID-token handoff cache; the `id_token` returned by Apple
during code exchange is available through `strategy.exchange_artifacts(exchange)`
and consumed directly while resolving the user.

`initialize()` returns `Error(JwksCacheInitializationFailed(_))` when the JWKS
cache cannot be initialized, including duplicate cache initialization. Handle
the error, or assert on it at the top level of your application where failing
to start is the right outcome.

## Default scopes

`name email`. Override per request with `config.with_scopes` on `AuthorizeOptions`. Apple delivers `name`
and `email` only on the **first** consent, in the form-post callback.

## Custom HTTP clients

The strategy remains a convenient `gleam_httpc` integration. For sans-IO use,
call `build_authorization_code_request` or `build_refresh_token_request`, send
the returned `gleam_http` request with your client, then call the matching
`parse_*_response` function. Apple JWKS uses the same pattern through
`vestibule_apple/jwks.build_jwks_request` and `parse_jwks_response`; token
verification remains separate in `verify_id_token`.

## Apple Developer portal setup

1. Sign in at <https://developer.apple.com/account>.
2. **Certificates, IDs & Profiles → Identifiers**:
   - Create an **App ID** for your app, enable the
     *Sign In with Apple* capability.
   - Create a **Services ID** — this is your OAuth `client_id`.
     Enable *Sign In with Apple*, add your domain, and register the
     **return URL** (e.g. `https://example.com/auth/apple/callback`).
     Apple does **not** allow `localhost` or `http://` callbacks.
3. **Keys → register a new key**, enable *Sign In with Apple*, associate
   it with your App ID, download the `.p8` private key (one-time
   download). Note the **Key ID**.
4. Note your **Team ID** (top-right of the developer portal).
5. Use these to generate the signed JWT `client_secret` (see below).

## Client-secret JWT setup

Apple does not use a static client secret. Build its signed JWT from your Apple
Developer account details:

- **Team ID**: your Apple Developer team identifier; use this as the JWT `iss`.
- **Key ID**: the identifier for the Sign in with Apple private key; include it
  in the JWT header as `kid`.
- **Services ID / client ID**: the Services ID registered for your web app; use
  this as both the OAuth client ID and the JWT `sub`.
- **Private key**: the `.p8` key downloaded from Apple. Store it securely and do
  not commit it to your repository.

Load the `.p8` file with your application's file or secret-store library, then
build the JWT and pass it as `config.client_secret_auth(jwt)`:

```gleam
let assert Ok(client_secret) =
  vestibule_apple.build_client_secret(
    team_id: "A1B2C3D4E5",
    client_id: "com.example.service-id",
    key_id: "1A2B3C4D5E",
    p8_pem: p8_pem,
    ttl: 3600,
  )

let client_config =
  config.new(
    client_id: "com.example.service-id",
    redirect_uri: "https://example.com/auth/apple/callback",
    auth: config.client_secret_auth(client_secret),
  )
```

The generated token uses ES256 and has this header and claim shape:

```json
{
  "alg": "ES256",
  "kid": "1A2B3C4D5E"
}
```

```json
{
  "iss": "A1B2C3D4E5",
  "iat": 1710000000,
  "exp": 1710604800,
  "aud": "https://appleid.apple.com",
  "sub": "com.example.service-id"
}
```

`ttl` is in seconds. It must be positive and no more than Apple's six-month
limit of 15,777,000 seconds. Prefer a short lifetime such as one hour and
generate a new token when needed.

Keep the `.p8` key outside the repository. For local demos, read it from a file
whose path is in an environment variable. In deployed environments, load it
from the platform secret store. If the store only exposes environment
variables, store the PEM as base64 and decode it at startup so its line breaks
are preserved.

To rotate the key, create and deploy a new Sign in with Apple key and Key ID,
confirm that token exchange works with the new key, then revoke the old key in
the Apple Developer portal. Do not revoke the old key before all running
instances use the replacement.

## Notes

- Apple requires `response_mode=form_post`, which this strategy adds for you.
- The JWT passed to `config.client_secret_auth(jwt)` can be generated with
  `build_client_secret`.
- Apple user info comes from the verified `id_token`, not a userinfo endpoint.

## Migration note

`AppleCache` now contains only the JWKS cache. Code that constructed
`AppleCache(id_tokens: ..., jwks: ...)` must change to `AppleCache(jwks: ...)`.
The `vestibule_apple/id_token_cache` module has been removed because ID tokens
are no longer passed between exchange and fetch through an implicit cache.
