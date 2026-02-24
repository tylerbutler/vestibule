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
│   └── pages.gleam     # HTML responses (landing, success, error)
└── README.md           # Setup: env vars, GitHub OAuth app config
```

## Dependencies

- `vestibule` (path: "..")
- `wisp` >= 1.8.0
- `mist` >= 4.0.0
- `gleam_erlang` (for process.sleep_forever)
- `envoy` (environment variables)

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
- `create_table()`: create named ETS table
- `store_state(state)`: generate session ID, insert into ETS, return session ID
- `get_state(session_id)`: look up and delete state from ETS (one-time use)
- Uses `gleam_erlang` for ETS operations, or raw Erlang FFI if needed

### pages.gleam
- `landing()`: returns HTML response for the landing page
- `success(auth)`: returns HTML response showing Auth result fields
- `error(err)`: returns HTML response showing the error
