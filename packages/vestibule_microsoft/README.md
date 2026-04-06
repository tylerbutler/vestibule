# vestibule_microsoft

Microsoft OAuth strategy for vestibule using the `/common` tenant endpoints.

## Install

```sh
gleam add vestibule_microsoft
```

## Usage

```gleam
import vestibule/config
import vestibule_microsoft

let strategy = vestibule_microsoft.strategy()
let cfg =
  config.new(
    "microsoft-client-id",
    "microsoft-client-secret",
    "http://localhost:8000/auth/microsoft/callback",
  )
```

The strategy uses Microsoft Graph `/me` for profile data and keeps
`userPrincipalName` as the nickname rather than treating it as a verified email.
