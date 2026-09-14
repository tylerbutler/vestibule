# Example application threat model

The example is demo and prototype code. It has not been security audited and is
not production-ready.

## Assets and trust boundaries

- Provider client secrets and OAuth tokens are sensitive. Tokens exist only in
  memory during the callback. The example does not store or display them.
- The signed `vestibule_session` cookie identifies one in-flight OAuth flow. It
  is `HttpOnly`, `SameSite=Lax`, limited to `/`, and expires after 10 minutes.
- The browser, OAuth providers, provider profile data, callback parameters, URL
  paths, and HTTP requests are untrusted.
- The registry and environment are operator-controlled. Provider responses
  cross a trust boundary before the example renders profile data.

## Controls

- OAuth state is stored server-side, bound to the provider and signed cookie,
  and consumed once. Missing, invalid, expired, wrong-provider, and replayed
  callbacks fail. Success and terminal failure expire the browser cookie;
  malformed or wrong-state callbacks preserve it because the valid server-side
  flow remains usable.
- Profile text and provider labels are HTML-escaped. Provider route segments are
  percent-encoded. Avatar URLs must use `https`; other schemes are omitted.
- Callback failures use a generic page. Provider error text and tokens are not
  returned to the browser.
- Redirect URIs are built from the configured localhost port, not from the
  request `Host` header. The server explicitly binds to localhost.
- Authorization-flow admission is keyed by the direct socket peer IP. The
  example does not trust `Forwarded` or `X-Forwarded-For` headers.
- The demo uses an unprefixed cookie because its documented origin is plain
  `http://localhost`. A real HTTPS application should use the middleware's
  default `SecureOnly` host-bound cookie.

## Deliberate omissions

The example creates no application login session, stores no users, has no
logout, performs no account linking, and has no state-changing routes after the
OAuth callback. Session rotation, logout invalidation, non-callback CSRF, and
identity-linking policy therefore do not exist here. An application that adds
them must rotate the application session after login, enforce idle and absolute
expiry, invalidate logout server-side, protect every state-changing request
against CSRF, and key identities by trusted provider namespace plus provider
user ID. Email alone is not an account-linking key.

Without `SECRET_KEY_BASE`, each process generates a fresh cryptographic key;
restarts then invalidate in-flight OAuth cookies. Plain HTTP, localhost redirect
URIs, and the proxy-unaware setup are for local demonstration only. Do not
expose this server or copy these defaults into a deployed service.
