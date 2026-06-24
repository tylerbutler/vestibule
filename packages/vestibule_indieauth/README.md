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
import gleam/option
import vestibule
import vestibule/authorization_request
import vestibule/config
import vestibule_indieauth

// Phase 0: Discover the user's IndieAuth endpoints
// (The user provides their URL, e.g. "https://user.example.com")
let assert Ok(strategy) = vestibule_indieauth.discover("https://user.example.com")

// Configure your app — client_id is your app's URL, no client_secret needed
let cfg =
  config.new(
    client_id: "https://myapp.example.com/",
    redirect_uri: "https://myapp.example.com/auth/indieauth/callback",
    auth: config.PublicClient,
  )
let options =
  config.authorize_options()
  |> config.with_scopes(["profile", "email"])

// Phase 1: Generate authorization URL and redirect user
let assert Ok(auth_request) =
  vestibule.create_authorization_request(
    strategy,
    cfg: cfg,
    options: options,
  )
// Store authorization_request.state(auth_request) and
// authorization_request.code_verifier(auth_request) in session
// Redirect user to authorization_request.url(auth_request)

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
    expected_nonce: option.None,
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

- **No client secret** — IndieAuth clients are public; use `config.PublicClient`
- **client_id is your app's URL** — Not an opaque ID from a developer console
- **User identity is a URL** — The `auth.uid` field contains the user's canonical URL
- **Endpoints are per-user** — Each user may have different authorization/token endpoints
- **Discovery required** — Call `discover()` before starting the auth flow

## Resuming a flow across request and callback

Because endpoints are discovered per-user at request time, a web app needs the
same endpoints again in the callback phase. Rather than re-running discovery (a
second network round-trip), discover once and persist the result — for example
in a signed cookie or server-side session — then rebuild the strategy on the way
back:

```gleam
// Request phase: discover once, keep the endpoints + canonical `me`.
let assert Ok(#(endpoints, me)) =
  vestibule_indieauth.discover_endpoints_with_me("https://user.example.com")
let strategy = vestibule_indieauth.strategy(endpoints, me)
// ...start the authorization flow, and stash this for the callback:
let stashed = vestibule_indieauth.serialize_endpoints(endpoints, me)

// Callback phase: restore and rebuild — no second discovery.
let assert Ok(#(endpoints, me)) = vestibule_indieauth.parse_endpoints(stashed)
let strategy = vestibule_indieauth.strategy(endpoints, me)
```

`discover_endpoints_with_me` validates, canonicalizes, and discovers in one call,
returning both the endpoints and the canonical `me` URL (unlike `discover`, which
returns only a `Strategy`, or `discover_endpoints`, which returns only the
endpoints).

## Target

Erlang (BEAM) runtime only — discovery requires HTTP requests.
