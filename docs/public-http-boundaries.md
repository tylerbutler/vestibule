# Public HTTP boundaries

Vestibule's secure public HTTP path is for demo and prototype OAuth flows. It
has not had a production security audit. Applications must still apply
rate limits before authorization, callback, discovery, token, JWKS, and
UserInfo work starts.

## Inbound authentication limits

The adapter limits below apply before provider network work starts:

| Resource | Limit |
| --- | ---: |
| Live authorization state per store | 4,096 |
| Live authorization state per direct client | 8 |
| Authorization state lifetime | 10 minutes |
| Wisp callback body | 65,536 bytes |
| Mist callback body | 65,536 bytes |
| Callback body read chunk | 8,192 bytes |

Wisp and Mist verify the session cookie before they read a POST callback body.
Malformed callback parameters do not consume valid state. The adapters do not
own the HTTP listener, so inbound URL, header, connection, request-rate,
request-timeout, and callback-concurrency limits must be set in the server or
reverse proxy.

## Destination policy

`provider_support.send_public` accepts HTTPS requests only. It resolves the
original host once, rejects the full answer set if any IPv4 or IPv6 address is
not globally routable, and gives only those validated addresses to the socket
connector. The connector uses the original host for the `Host` header, TLS
SNI, and certificate hostname checks. It uses the Erlang/OTP system CA set.
HTTP proxy environment variables are ignored because this path opens its own
TCP or TLS socket. Redirects are returned to the caller and are not followed.

## Fixed limits

The limits below apply per BEAM node:

| Resource | Limit |
| --- | ---: |
| Concurrent public HTTP sends | 64 |
| URL | 8,192 bytes |
| Request headers, including generated framing headers and delimiters | 65,536 bytes |
| Request body | 1,048,576 bytes |
| Response headers, interim responses, chunk lines, and trailers combined | 65,536 bytes |
| Entire operation, including DNS and address retries | 30 seconds |

The response body limit depends on the endpoint class:

| Endpoint class | Limit |
| --- | ---: |
| Profile HTML | 1,048,576 bytes |
| Discovery metadata and JWKS | 262,144 bytes |
| Token response | 65,536 bytes |
| UserInfo response | 262,144 bytes |

Admission happens before DNS lookup or request worker creation. A full node
rejects the request instead of creating a queue. Caller termination and
deadlines stop the request worker and release the slot.

## Framing and coding policy

The client accepts HTTP/1.0 and HTTP/1.1 responses. It accepts one
`Transfer-Encoding: chunked` coding, one consistent `Content-Length`, or a
close-delimited body. It rejects responses that contain both transfer encoding
and content length. It also rejects transfer-coding chains and all content
codings except `identity`; compressed bytes are never returned as if they were
decoded.

## Deployment limits

These are client-side resource ceilings, not a full denial-of-service defense.
At minimum, configure hard per-IP request-rate and concurrent-connection limits
for authorization starts and callbacks. A conservative starting point for a
demo is a burst of 8 authorization starts with a refill of 1 per minute, plus a
burst of 16 callbacks with a refill of 1 per second. Keep callback request
bodies at or below 65,536 bytes, set a request-header limit, and set listener
timeouts no longer than the application's authentication timeout. Tune these
values for expected demo traffic; Vestibule does not make them production-safe.

Also rate-limit outbound discovery, token, JWKS, and UserInfo work below each
provider's published quota. Honor `Retry-After`. A provider-specific quota can
be lower than Vestibule's node-wide concurrency ceiling, so the 64-request
transport limit is not an outbound rate limit.

Tests cover admission saturation and reuse, caller cancellation, deadlines,
request and response limits, DNS answer rejection and connector pinning, proxy
isolation, TLS option construction, and response framing. A local memory-only
CA fixture also performs real loopback TLS handshakes for original-host SNI and
hostname verification, and verifies rejection of untrusted, expired,
wrong-DNS-name, and DNS-only certificates used with an IP host. These tests do
not certify all operating systems, trust stores, OTP releases, or provider load
limits.

The Wisp and Mist adapter suites send 100 rejected authorization starts through
each public request-phase entry point after one client reaches its limit. Every
excess request returns 429, and the accepted flow remains in the state store.
The core transport suite covers slow responses, concurrent oversized responses,
chunked and close-delimited overflow, compressed responses, cumulative interim
response headers, DNS rejection, request-worker admission, cancellation, and
deadline cleanup. Public parser suites cover malformed OAuth JSON, discovery
JSON, JWKS JSON, and JWTs without retaining callback state.

Run these repeatable checks:

```sh
just test-pkg .
just test-pkg vestibule_wisp
just test-pkg vestibule_mist
just test-pkg vestibule_oidc
just test-pkg vestibule_apple
```
