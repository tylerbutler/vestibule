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
