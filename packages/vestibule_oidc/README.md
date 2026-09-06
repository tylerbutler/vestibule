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

## ID-token verification

Discovery now requires `jwks_uri` and
`id_token_signing_alg_values_supported`. The generic strategy accepts only
RS256 ID tokens. It verifies the signature, issuer, audience, `azp`,
expiration, optional `nbf` and `iat`, and the callback nonce before it accepts
an identity. The UserInfo `sub` must equal the verified ID-token `sub`.

JWKS responses use Vestibule's public HTTPS transport and its 256 KiB response
limit. The package caches at most 64 issuer key sets for one hour. If a token
uses an unknown `kid`, the strategy fetches the JWKS one more time and retries
once.

For manual configuration, use `new_config_with_jwks` when the provider does
not publish keys at `<issuer>/.well-known/jwks.json`.

## Provider-key migration

`discover` now uses the full exact issuer as the strategy provider key.
For example, `https://login.example:8443/tenant` replaces the old
`login.example` key. This preserves the OIDC `(issuer, sub)` identity boundary,
including issuer paths and non-default ports.

Before deployment:

1. Change stored account provider keys from the old hostname to the exact
   discovered issuer. A trailing slash remains part of the issuer identity.
2. Update provider route parameters and links. Percent-encode the full issuer
   when a router uses one path segment.
3. Keep duplicate-registration errors enabled. Registering the same issuer
   twice still fails; entries are not replaced silently.

This identity-key change is breaking for applications that persisted the old
hostname or exposed it in routes.
