# E2E Example App Design

## Goal

A polished Wisp web app in `example/` that demonstrates the full GitHub OAuth flow using vestibule's current API. Proves the library works end-to-end with a real GitHub OAuth app.

## Structure

```
example/
├── gleam.toml          # path dep on vestibule, plus wisp, mist, envoy
├── src/
│   ├── app.gleam       # main() — server startup, config from env
│   ├── router.gleam    # route dispatch + auth handlers
│   ├── session.gleam   # ETS-backed session store for CSRF state
│   ├── session_ffi.erl # Erlang FFI for direct ETS access
│   └── pages.gleam     # HTML responses (landing, success, error)
├── test/
│   ├── vestibule_example_test.gleam  # startest entry point
│   └── session_test.gleam            # session store tests
└── README.md           # Setup: env vars, GitHub OAuth app config
```

## Dependencies

- `vestibule` (path: "..")
- `wisp` >= 2.2.0
- `mist` >= 4.0.0
- `gleam_erlang` >= 1.0.0 (for process.sleep_forever)
- `gleam_crypto` >= 1.5.0 (for session ID generation)
- `envoy` >= 1.1.0 (environment variables)

> **Note:** The original plan included `carpenter` for ETS bindings, but carpenter 0.3.1
> (and `bravo` 4.0.1) both require `gleam_erlang < 1.0.0`, which is incompatible with
> vestibule's `gleam_erlang 1.3.0`. Session storage uses a small Erlang FFI wrapper
> (`session_ffi.erl`) for direct ETS access instead.

## Routes

| Route | Method | Behavior |
|-------|--------|----------|
| `/` | GET | Landing page with "Sign in with GitHub" link |
| `/auth/github` | GET | Generate auth URL, store state, redirect to GitHub |
| `/auth/github/callback` | GET | Validate state, exchange code, fetch user, show profile |
| `*` | * | 404 |

## Session Flow

1. `/auth/github`: Generate session ID (random), store `session_id -> csrf_state` in ETS, set session ID as signed cookie, redirect to GitHub authorize URL.
2. `/auth/github/callback`: Read session ID from signed cookie, look up CSRF state in ETS, call `vestibule.handle_callback(...)`, delete entry from ETS, render success page with user info.

## Config

Read from environment variables via envoy:
- `GITHUB_CLIENT_ID` (required)
- `GITHUB_CLIENT_SECRET` (required)
- `PORT` (optional, default 8000)
- `SECRET_KEY_BASE` (optional, auto-generated if missing)

## Pages

Simple inline HTML. No templates, no CSS framework — just readable markup.

- **Landing**: "Vestibule Demo" heading, "Sign in with GitHub" link to `/auth/github`
- **Success**: Shows uid, name, email, avatar (as img tag), nickname, provider
- **Error**: Shows error type and message

## Modules

### app.gleam
- `main()`: read env vars, validate required ones present, create ETS table, configure Wisp logger, start mist server
- Build vestibule Config and Strategy, pass through router context

### router.gleam
- `handle_request(req, ctx)`: pattern match on `wisp.path_segments(req)`
- `/auth/github`: call `vestibule.authorize_url`, store state via session module, redirect
- `/auth/github/callback`: read query params via `wisp.get_query`, look up state, call `vestibule.handle_callback`, render success or error page

### session.gleam
- `create_table()`: create named ETS table (idempotent)
- `store_state(state)`: generate session ID via `gleam/crypto`, insert into ETS, return session ID
- `get_state(session_id)`: look up and delete state from ETS (one-time use)
- Uses Erlang FFI (`session_ffi.erl`) for ETS operations — table name passed as string, converted to atom in Erlang

### pages.gleam
- `landing()`: returns HTML response for the landing page
- `success(auth)`: returns HTML response showing Auth result fields
- `error(err)`: returns HTML response showing the error
- Note: `wisp.html_response` takes `String`, not `StringTree`
