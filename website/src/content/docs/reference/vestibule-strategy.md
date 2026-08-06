---
title: "vestibule/strategy"
description: "Provider-strategy interface. A `Strategy(e)` is an opaque record bundling the provider-specific functions an OAuth/OIDC provider implements: build authorize URL, exchange code, fetch user, and an optional refresh token."
nav:
  group: Reference
  groupOrder: 20
  order: 21
  label: "vestibule/strategy"
toc:
  - href: "#types"
    label: "Types"
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule/strategy
---

# `vestibule/strategy`

Provider-strategy interface. A `Strategy(e)` is an opaque record
bundling the provider-specific functions an OAuth/OIDC provider
implements: build authorize URL, exchange code, fetch user, and an
optional refresh token.

Provider packages (`vestibule_google`, `vestibule_apple`, ...) build
these with `strategy.new`, which takes the three required capabilities
directly, plus the optional `with_refresh` and `with_nonce` builders;
the core library invokes them through the exposed accessors.

## Types

### `ExchangeResult`

The result of exchanging an authorization code.

`credentials` contains the standard OAuth credentials. `artifacts` contains
provider-specific token response data that may be needed while resolving the
user, such as an OpenID Connect `id_token`.

Opaque to keep provider-specific artifacts evolution-safe.

```gleam
pub type ExchangeResult
```

### `Strategy`

A strategy is the bundle of provider-specific functions needed to
authenticate with a single OAuth/OIDC provider.

The type parameter `e` corresponds to the custom error type in
`AuthError(e)`. Built-in strategies are polymorphic in `e`.

Opaque so that vestibule can add optional capabilities without breaking
provider packages. Construct with `new`, which requires the three core
capabilities (`authorize_url`, `exchange_code`, `fetch_user`) so that a
strategy unable to complete an authentication flow cannot be built.
Attach optional capabilities with the `with_refresh` and `with_nonce`
builders. Invoke through the `build_authorize_url`, `exchange_code`,
`refresh_token`, and `fetch_user` helpers.

`refresh_token` is optional: a strategy built without `with_refresh` fails
`refresh_token` with an AuthError of kind `RefreshUnsupportedKind`.

```gleam
pub type Strategy(a)
```

### `UserResult`

Normalized user details returned by a strategy.

Opaque so that new fields can be added without breaking strategy
implementations. Construct with `user_result` and read with the
`user_result_uid`, `user_result_info`, and `user_result_extra` accessors.

```gleam
pub type UserResult
```

## Functions

### `append_code_verifier`

Append a PKCE code_verifier to a form-encoded request body when present.

Strategy implementations should call this after building the token
exchange request to include the PKCE verifier parameter.

```gleam
pub fn append_code_verifier(
  request.Request(String),
  option.Option(String)
) -> request.Request(String)
```

### `authorization_header`

Build the Authorization header value from credentials.

Uses the `token_type` from the credentials (e.g., "Bearer", "bearer").
Strategy implementations should use this instead of hardcoding `"Bearer "`.

Returns `Error` if the token type is not "bearer" (case-insensitive),
as vestibule only supports Bearer token authentication.

```gleam
pub fn authorization_header(credentials: credentials.Credentials) -> Result(String, error.AuthError(a))
```

### `build_authorize_url`

Build the provider's authorization URL.

```gleam
pub fn build_authorize_url(
  Strategy(a),
  config: config.ClientConfig,
  options: config.AuthorizeOptions,
  scopes: List(String),
  state: String
) -> Result(String, error.AuthError(a))
```

### `default_scopes`

Return the strategy's default scopes, used when the caller's
`AuthorizeOptions` does not specify any.

```gleam
pub fn default_scopes(Strategy(a)) -> List(String)
```

### `exchange_artifacts`

Return provider-specific artifacts produced by the exchange
(e.g., an OpenID Connect `id_token`).

```gleam
pub fn exchange_artifacts(ExchangeResult) -> dict.Dict(String, dynamic.Dynamic)
```

### `exchange_code`

Exchange an authorization code for credentials and any provider-specific
artifacts. Pass the PKCE `code_verifier` if one was generated for the
authorization request.

```gleam
pub fn exchange_code(
  Strategy(a),
  config: config.ClientConfig,
  code: String,
  code_verifier: option.Option(String)
) -> Result(ExchangeResult, error.AuthError(a))
```

### `exchange_credentials`

Return the OAuth credentials produced by the exchange.

```gleam
pub fn exchange_credentials(ExchangeResult) -> credentials.Credentials
```

### `exchange_result`

Build an exchange result for providers with no provider-specific artifacts.

```gleam
pub fn exchange_result(credentials.Credentials) -> ExchangeResult
```

### `exchange_result_with_artifacts`

Build an exchange result with provider-specific artifacts.

```gleam
pub fn exchange_result_with_artifacts(
  credentials.Credentials,
  dict.Dict(String, dynamic.Dynamic)
) -> ExchangeResult
```

### `fetch_user`

Fetch user info using the obtained exchange result.

```gleam
pub fn fetch_user(
  Strategy(a),
  config: config.ClientConfig,
  exchange: ExchangeResult
) -> Result(UserResult, error.AuthError(a))
```

### `new`

Build a `Strategy` for `provider`.

`default_scopes` is used when the caller's `AuthorizeOptions` does not
specify any scopes. The three core capabilities are required:

- `authorize_url` builds the provider-specific authorization URL from the
  config, options, scopes, and state.
- `exchange_code` exchanges an authorization code for credentials and
  optional provider-specific artifacts; the third parameter is the PKCE
  `code_verifier` if one was generated.
- `fetch_user` resolves the authenticated user from the exchange result.

Attach optional capabilities with the `with_*` builders:

```gleam
strategy.new(
  provider: "github",
  default_scopes: ["user:email"],
  authorize_url: do_authorize_url,
  exchange_code: do_exchange_code,
  fetch_user: do_fetch_user,
)
|> strategy.with_refresh(do_refresh_token)
```

```gleam
pub fn new(
  provider: String,
  default_scopes: List(String),
  authorize_url: fn(config.ClientConfig, config.AuthorizeOptions, List(String), String) -> Result(String, error.AuthError(a)),
  exchange_code: fn(config.ClientConfig, String, option.Option(String)) -> Result(ExchangeResult, error.AuthError(a)),
  fetch_user: fn(config.ClientConfig, ExchangeResult) -> Result(UserResult, error.AuthError(a))
) -> Strategy(a)
```

### `provider`

Return the human-readable provider name (e.g., `"github"`, `"google"`).

```gleam
pub fn provider(Strategy(a)) -> String
```

### `refresh_token`

Refresh credentials using a refresh token.

Returns an AuthError of kind `RefreshUnsupportedKind` if the strategy was
built without `with_refresh`.

```gleam
pub fn refresh_token(
  Strategy(a),
  config: config.ClientConfig,
  refresh_token: String
) -> Result(credentials.Credentials, error.AuthError(a))
```

### `user_result`

Build a `UserResult`.

```gleam
pub fn user_result(
  uid: String,
  info: user_info.UserInfo,
  extra: dict.Dict(String, dynamic.Dynamic)
) -> UserResult
```

### `user_result_extra`

Return provider-specific extra fields associated with the user.

```gleam
pub fn user_result_extra(UserResult) -> dict.Dict(String, dynamic.Dynamic)
```

### `user_result_info`

Return the normalized user info.

```gleam
pub fn user_result_info(UserResult) -> user_info.UserInfo
```

### `user_result_uid`

Return the provider's unique user id.

```gleam
pub fn user_result_uid(UserResult) -> String
```

### `uses_nonce`

Whether this strategy uses the OIDC `nonce` (generate + validate).

```gleam
pub fn uses_nonce(Strategy(a)) -> Bool
```

### `with_nonce`

Mark this strategy as using the OIDC `nonce`. The core will then generate
an OIDC `nonce`, emit it on the authorize URL, and validate it against the
`id_token` on callback. Plain OAuth2 strategies should omit this.

```gleam
pub fn with_nonce(Strategy(a)) -> Strategy(a)
```

### `with_refresh`

Attach an optional token-refresh capability. `refresh_token` swaps a
refresh token for fresh credentials. Strategies built without this fail
`refresh_token` with an AuthError of kind `RefreshUnsupportedKind`.

```gleam
pub fn with_refresh(
  Strategy(a),
  fn(config.ClientConfig, String) -> Result(credentials.Credentials, error.AuthError(a))
) -> Strategy(a)
```
