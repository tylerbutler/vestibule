# vestibule_google

Google OAuth strategy for vestibule.

## Install

```sh
gleam add vestibule_google
```

## Usage

```gleam
import vestibule/config
import vestibule_google

let strategy = vestibule_google.strategy()
let cfg =
  config.new(
    "google-client-id",
    "google-client-secret",
    "http://localhost:8000/auth/google/callback",
  )
```

Google userinfo only populates `UserInfo.email` when `email_verified` is true.

## Refresh tokens

Google only returns a refresh token on the first user consent for a given
client/user/scope combination. To request offline access, add the provider-
specific authorization parameters:

```gleam
let cfg =
  config.new(
    "google-client-id",
    "google-client-secret",
    "http://localhost:8000/auth/google/callback",
  )
  |> config.with_extra_params([
    #("access_type", "offline"),
    #("prompt", "consent"),
  ])
```

`access_type=offline` asks Google for a refresh token. `prompt=consent` forces
the consent screen to appear again, which is useful if the user already approved
the app and Google would otherwise omit `refresh_token` from the token response.
