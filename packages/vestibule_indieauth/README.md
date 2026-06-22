# vestibule_indieauth

IndieAuth strategy for [vestibule](https://hex.pm/packages/vestibule) — decentralized identity authentication using your own domain.

[![Package Version](https://img.shields.io/hexpm/v/vestibule_indieauth)](https://hex.pm/packages/vestibule_indieauth)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/vestibule_indieauth/)

[IndieAuth](https://indieauth.spec.indieweb.org/) is an identity layer on top of OAuth 2.0
where users are identified by a URL they control (e.g., `https://example.com/`).
Unlike centralized providers, IndieAuth endpoints are discovered dynamically from
the user's homepage.

## Quick Start

```sh
gleam add vestibule_indieauth
```

```gleam
import gleam/dict
import vestibule
import vestibule/config
import vestibule_indieauth

// Phase 0: Discover the user's IndieAuth endpoints
// (The user provides their URL, e.g. "https://user.example.com")
let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")

// Configure your app — client_id is your app's URL, no client_secret needed
let cfg =
  config.new(
    "https://myapp.example.com/",
    "",
    "https://myapp.example.com/auth/indieauth/callback",
  )
  |> config.with_scopes(["profile", "email"])

// Phase 1: Generate authorization URL and redirect user
let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
// Store auth_request.state and auth_request.code_verifier in session
// Redirect user to auth_request.url

// Phase 2: Handle the callback
let params =
  dict.from_list([
    #("state", "state from callback"),
    #("code", "authorization code from callback"),
    #("iss", "issuer from callback"),
  ])

let assert Ok(auth) =
  vestibule.handle_callback(
    strategy,
    cfg,
    params,
    "expected state from session",
    "code verifier from session",
  )
// auth.uid is the user's canonical URL (e.g., "https://user.example.com/")
// auth.info.name, auth.info.email, auth.info.image — from profile
```

## How It Works

1. **User enters their URL** — The user provides their homepage URL
2. **Discovery** — The library fetches the URL and discovers IndieAuth endpoints via:
   - `.well-known/oauth-authorization-server` metadata (preferred)
   - HTTP `Link` headers with `rel="authorization_endpoint"`
   - HTML `<link>` tags with `rel="authorization_endpoint"`
3. **Authorization** — Standard OAuth 2.0 authorization code flow with PKCE
4. **Token exchange** — Code is exchanged at the discovered token endpoint;
   the response includes the user's canonical URL (`me`) and optional profile info

## Key Differences from Other Providers

- **No client secret** — IndieAuth clients are public; pass an empty string for `client_secret`
- **client_id is your app's URL** — Not an opaque ID from a developer console
- **User identity is a URL** — The `auth.uid` field contains the user's canonical URL
- **Endpoints are per-user** — Each user may have different authorization/token endpoints
- **Discovery required** — Call `discover()` before starting the auth flow

## Target

Erlang (BEAM) runtime only — discovery requires HTTP requests.
