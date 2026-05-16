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

## Default scopes

`openid email profile`. Override with `config.with_scopes`.

## Google Cloud Console setup

1. Create or select a project at <https://console.cloud.google.com/>.
2. **APIs & Services → OAuth consent screen**: configure the consent
   screen (User Type, app name, support email, scopes
   `openid`, `email`, `profile`).
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**.
4. Application type: *Web application*.
5. Add your redirect URI exactly, e.g.
   `http://localhost:8000/auth/google/callback` for development and
   the HTTPS production URI.
6. Copy the **Client ID** and **Client secret** into your environment.

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
