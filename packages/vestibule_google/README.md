# vestibule_google

Google OAuth strategy for vestibule.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is intended for demos and prototypes that need real OAuth flows — do not
> use it in production.

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
    client_id: "google-client-id",
    redirect_uri: "http://localhost:8000/auth/google/callback",
    auth: config.ClientSecret("google-client-secret"),
  )
```

Google userinfo only makes the email accessor for `auth.info(auth_result)`
return `Some(email)` when `email_verified` is true.

## Hosted-domain (Workspace) enforcement

`strategy()` does **not** restrict sign-in to a Google Workspace domain. Setting
`hd` via `config.authorize_options() |> config.with_extra_params([#("hd", "corp.example")])` only pre-selects
the account picker — it is a UI hint and **must not** be relied on for
authorization, because a user can still authenticate with an account outside
that domain.

To actually restrict sign-in to a single Workspace domain, use
`strategy_for_hosted_domain`:

```gleam
let strategy = vestibule_google.strategy_for_hosted_domain("corp.example")
```

This validates Google's `hd` (hosted-domain) claim from the userinfo response.
Authentication fails with a `UserInfoKind` `AuthError` (see `error.kind`) when
the claim is missing
(e.g. a consumer `gmail.com` account) or does not match `"corp.example"`. The
validated domain is surfaced under the `"hd"` key of `UserResult`'s `extra`
dict. The domain is also added to the authorization URL as an account-picker
hint, but enforcement always happens server-side when the userinfo response is
validated.

## Default scopes

`openid email profile`. Override per request with `config.with_scopes` on `AuthorizeOptions`.

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
let assert Ok(options) =
  config.authorize_options()
  |> config.with_extra_params([
    #("access_type", "offline"),
    #("prompt", "consent"),
  ])
```

`access_type=offline` asks Google for a refresh token. `prompt=consent` forces
the consent screen to appear again, which is useful if the user already approved
the app and Google would otherwise omit `refresh_token` from the token response.
