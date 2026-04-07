# Vestibule Example — Multi-Provider OAuth

A minimal Wisp web app demonstrating vestibule with GitHub, Microsoft, and
Google providers.

## Prerequisites

- Gleam 1.14+
- Erlang 27+
- At least one configured OAuth provider:
  - GitHub OAuth App: `http://localhost:8000/auth/github/callback`
  - Microsoft App Registration: `http://localhost:8000/auth/microsoft/callback`
  - Google OAuth Client: `http://localhost:8000/auth/google/callback`

## Setup

```bash
cp example/.env.example example/.env
# Fill in at least one provider in example/.env
just deps
```

Set credentials for any provider you want to try:

```bash
export GITHUB_CLIENT_ID="your_github_client_id"
export GITHUB_CLIENT_SECRET="your_github_client_secret"
export MICROSOFT_CLIENT_ID="your_microsoft_client_id"
export MICROSOFT_CLIENT_SECRET="your_microsoft_client_secret"
export GOOGLE_CLIENT_ID="your_google_client_id"
export GOOGLE_CLIENT_SECRET="your_google_client_secret"
```

## Run

```bash
just serve
```

Open http://localhost:8000 and sign in with any configured provider.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_CLIENT_ID` | No | — | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | No | — | GitHub OAuth App client secret |
| `MICROSOFT_CLIENT_ID` | No | — | Microsoft App Registration client ID |
| `MICROSOFT_CLIENT_SECRET` | No | — | Microsoft App Registration client secret |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth client secret |
| `PORT` | No | 8000 | HTTP server port |
| `SECRET_KEY_BASE` | No | Development fallback | Secret for signing cookies |

If `SECRET_KEY_BASE` is not set, the example uses a fixed development fallback.
Set a real secret before deploying anything beyond local testing.
