# BEAM logging for Vestibule

## Goal

Vestibule will emit structured OAuth lifecycle logs through Erlang/OTP Logger. Host applications will keep normal BEAM control over log levels, handlers, formatters, and filters. Logging will never change an authentication result.

## Non-goals

Vestibule will not add its own logging framework, require application-level logger callbacks, or expose secrets for debugging. It will not configure global Logger settings; applications already own those settings.

## Approach

Add a small internal logger wrapper in the core package. The wrapper will call OTP `logger` through FFI and accept a level plus a structured report. Public authentication APIs will keep their current signatures and return types.

Use structured reports instead of string messages. Every report will include stable fields:

- `event`: a namespaced event name, such as `vestibule.callback.start`
- `phase`: `request`, `callback`, `refresh`, or `provider_request`
- `provider`: the provider name when available
- `outcome`: `start`, `success`, or `failure`

Transport adapters may add `transport = "wisp"` or `transport = "mist"`. Provider packages may add `endpoint = "authorize"`, `"token"`, `"user_info"`, or `"jwks"`.

## Levels

Use `debug` for detailed step tracing. These events cover OAuth boundaries and internal flow transitions, including authorization request creation, callback parsing, state validation, state-store access, code exchange, user-info fetch, and token refresh.

Use `info` for successful lifecycle milestones. These events mark completed authorization request creation, callback authentication, refresh completion, and middleware request redirects.

Use `warning` for expected authentication failures. These include unknown providers, missing or invalid callback parameters, provider-declared OAuth errors, state mismatches, missing session cookies, and expired or consumed session state.

Use `error` for infrastructure and provider integration failures. These include state-store write failures, network failures, malformed provider responses, decode failures, unsupported token types, and non-success provider HTTP responses.

## Redaction

Vestibule will never log access tokens, refresh tokens, client secrets, authorization codes, PKCE code verifiers, raw callback parameters, session IDs, cookie values, raw response bodies, or signed payloads.

Reports may include safe context such as provider name, transport name, endpoint kind, HTTP status code, error category, configured scope count, and whether optional values were present. They must not include user-controlled raw values unless those values are already safe enum-like categories chosen by Vestibule.

## Flow coverage

Core `vestibule` will log:

- `create_authorization_request` start and success or failure
- `handle_callback` start, state validation result, provider error detection, code exchange result, user-info result, and final success or failure
- `refresh_token` start and success or failure
- `transport_flow` provider lookup, state-store write, state peek, state validation, state consume, and final callback result

`vestibule_wisp` and `vestibule_mist` will log:

- request-phase entry, redirect success, unknown provider, auth failure, and store failure
- callback entry, parameter extraction failure, cookie/session failure, structured auth failure, and success
- transport name, provider name, and callback error category

Provider packages will log:

- token endpoint request attempt and response outcome
- refresh endpoint request attempt and response outcome
- user-info endpoint request attempt and response outcome
- JWKS fetch and validation outcome where relevant

Provider logs will record endpoint kind and HTTP status, not request bodies, response bodies, tokens, or headers that may contain credentials.

## Testing

Keep the logger FFI thin and isolate most behavior in pure event builders. Unit tests will cover event classification, required fields, level selection, and redaction. Flow tests do not need to capture OTP Logger output.

Add explicit tests that build representative failure events and assert that sensitive field names and values are absent. Provider package tests will cover network and decode event classification without logging token or body data.

## Compatibility

The change is additive. Existing public functions keep their return types. Existing applications that do not configure Logger will still use the BEAM's default logger behavior. Applications can suppress Vestibule logs with normal Logger level or metadata filters.

The internal wrapper should remain private until there is a clear public use case. If users later need custom event hooks, Vestibule can add them separately without replacing BEAM-native logging.
