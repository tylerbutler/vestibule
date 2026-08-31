# vestibule_oidc

OpenID Connect discovery for vestibule — auto-configure strategies from an
issuer URL.

> [!WARNING]
> Vestibule has not been security audited and must not be considered secure.
> It is intended for demos and prototypes that need real OAuth flows — do not
> use it in production.

## Install

```sh
gleam add vestibule_oidc
```

## Usage

```gleam
import vestibule_oidc

let assert Ok(strategy) = vestibule_oidc.discover("https://accounts.google.com")
```

See the [vestibule README](../../README.md) for wiring the discovered strategy
into the two-phase flow.
