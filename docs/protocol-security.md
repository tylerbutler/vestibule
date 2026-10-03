# OAuth callback boundaries

Vestibule is for demos and prototypes. It has not been security audited and is
not for production use.

## Core caller responsibilities

`create_authorization_request` generates state, an S256 PKCE verifier, and an
OIDC nonce when the strategy requires one. Keep the returned verifier and
nonce on the server. Bind them to the selected provider and the browser
session.

Before calling `handle_callback`:

1. Reject repeated callback parameters before converting them to a dictionary.
2. Check the stored flow's provider, state, and expiration.
3. Atomically consume the stored flow. Do not restore it when exchange fails.
4. Pass the original client configuration, redirect URI, verifier, and nonce.

The core function takes a dictionary, so it cannot detect duplicates that a
caller already discarded. It does not store or consume state itself. Use the
Wisp or Mist integration to manage stored flows.

The provider must bind the authorization code to the client, exact redirect
URI, and S256 challenge. Vestibule sends the stored verifier; it cannot make a
provider enforce PKCE. An OIDC strategy must verify the ID-token signature and
claims before returning an exchange result. The core nonce comparison only
binds that token to the stored request.

If the provider requires an authorization-response issuer, set
`strategy.with_callback_issuer` to the validated metadata issuer. The core then
requires an exact, nonempty `iss` match before it sends the code to the token
endpoint. Do not enable this requirement for a provider that does not send
`iss`.

Requested scopes are not granted permissions. Read the granted scopes from
the returned credentials and apply the application's authorization policy.
Do not grant an application role because its name appeared in an
authorization request.

## Regression coverage

Run `gleam test` at the repository root.

| Boundary | Coverage |
| --- | --- |
| State and selected provider | `transport_flow_test.gleam`: a callback for another provider cannot use the stored flow |
| Authorization-response issuer | `protocol_abuse_test.gleam`: a required `iss` cannot be absent, empty, or replaced with another path or host |
| S256 and code injection | `protocol_abuse_test.gleam`: an authorization code bound to another flow fails |
| Code replay | `protocol_abuse_test.gleam`: both successful and failed exchanges consume the flow |
| Missing or substituted verifier | `protocol_abuse_test.gleam`: callback fails without returning an identity |
| Redirect URI byte equality | `protocol_abuse_test.gleam`: a percent-encoding change fails the test issuer's code binding |
| OIDC nonce substitution | `protocol_abuse_test.gleam`: a nonce from another generated request fails before user lookup |
| Mixed success and error parameters | `protocol_abuse_test.gleam`: an error response cannot produce an identity, even with a valid code |
| Authorization parameter replacement | `protocol_abuse_test.gleam`: reserved state, nonce, PKCE, client, redirect, response, and scope parameters cannot be set as extras |
| Scope replacement and grants | `protocol_abuse_test.gleam`: request options replace defaults but do not become granted scopes |

These core tests use a small test issuer that enforces code and redirect
binding. They do not prove a real provider's server behavior. The nonce test
isolates flow binding and does not test a signature. Signed-token evidence,
HTTP response handling, and browser cookie behavior require their separate
provider and transport coverage.

## Browser cookie matrix

Run `python3 test/browser_cookie_matrix.py` with Chromium, OpenSSL, and the
Python `websocket-client` package installed. The real-browser matrix verifies
that:

- a sibling subdomain cannot set a `__Host-` cookie for the application;
- a parent-domain cookie cannot shadow the host-bound session cookie;
- `SameSite=Lax` cookies are absent from a cross-site POST;
- a `Secure`, host-bound `SameSite=None` cookie is present for an Apple-style
  cross-site POST; and
- expiry removes the host-bound session cookie.

Wisp and Mist derive admission identity from the direct socket peer. They do
not trust `Forwarded` or `X-Forwarded-*` headers. A deployment behind a proxy
must accept traffic only from that trusted proxy and enforce its per-client
rate policy there; do not pass unvalidated forwarded identity into
`request_phase_for_client`.
