# Vestibule Example — GitHub OAuth

A minimal Wisp web app demonstrating vestibule's GitHub OAuth flow.

## Prerequisites

- Gleam 1.14+
- Erlang 27+
- A [GitHub OAuth App](https://github.com/settings/developers)
  - Set the callback URL to `http://localhost:8000/auth/github/callback`

## Setup

```bash
cd example
gleam deps download
```

Set your GitHub OAuth credentials:

```bash
export GITHUB_CLIENT_ID="your_client_id"
export GITHUB_CLIENT_SECRET="your_client_secret"
```

## Run

```bash
gleam run
```

Open http://localhost:8000 and click "Sign in with GitHub".

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_CLIENT_ID` | Yes | — | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | Yes | — | GitHub OAuth App client secret |
| `PORT` | No | 8000 | HTTP server port |
| `SECRET_KEY_BASE` | No | Auto-generated | Secret for signing cookies |
