# Writing a Custom Strategy

This guide walks through building a vestibule strategy from scratch. By the end, you will have a working OAuth2 provider integration that plugs into vestibule's two-phase authentication flow.

## Overview

### What is a strategy?

A strategy is a Gleam record containing three functions and some metadata. There are no behaviours, traits, or interfaces involved -- just a value of type `Strategy(e)` that you construct and pass to vestibule's core functions.

Each strategy tells vestibule how to talk to a specific OAuth2 provider: how to build the authorization URL, how to exchange an authorization code for tokens, and how to fetch user information.

### The two-phase flow

Vestibule authenticates users in two phases:

1. **Request phase** -- Your application calls `vestibule.authorize_url(strategy, config)`. Vestibule generates a CSRF state token and PKCE code verifier, calls your strategy's `authorize_url` function to build the provider-specific URL, then appends the PKCE `code_challenge` parameter. You get back an `AuthorizationRequest` containing the URL, state, and code verifier. Store the state and code verifier in the user's session, then redirect them to the URL.

2. **Callback phase** -- The provider redirects the user back to your application with a `code` and `state` parameter. Your application calls `vestibule.handle_callback(strategy, config, params, expected_state, code_verifier)`. Vestibule validates the CSRF state, calls your strategy's `exchange_code` function (passing the PKCE code verifier), then calls your strategy's `fetch_user` function. You get back an `Auth` record with the user's UID, normalized info, and OAuth credentials.

### What the core library handles for you

You do not need to implement any of the following -- vestibule's core takes care of them:

- **CSRF state generation and validation** -- Random state tokens are generated with `crypto.strong_random_bytes` and validated with constant-time comparison.
- **PKCE (Proof Key for Code Exchange)** -- The code verifier, code challenge, and S256 challenge method are all managed by the core. Your `exchange_code` function receives the code verifier as an `Option(String)` and just needs to include it in the token request.
- **URL assembly** -- The core appends `code_challenge` and `code_challenge_method=S256` to whatever authorization URL your strategy returns.
- **Scope resolution** -- If the user provides custom scopes via `Config`, those are used. Otherwise, your strategy's `default_scopes` are passed through.
- **Token refresh** -- The core's `vestibule.refresh_token` function handles refresh requests using the `token_url` from your strategy. No strategy function is involved.

Your strategy is responsible for:

- Building the provider's authorization URL (with scopes, state, redirect URI, and client ID)
- POSTing to the provider's token endpoint and parsing the response into `Credentials`
- Fetching user info from the provider's API and normalizing it into `UserInfo`

## The Strategy Type

Here is the full type definition from `vestibule/strategy.gleam`:

```gleam
pub type Strategy(e) {
  Strategy(
    /// Human-readable provider name (e.g., "github", "google").
    provider: String,
    /// Default scopes for this provider.
    default_scopes: List(String),
    /// The provider's token endpoint URL, used for code exchange and token refresh.
    token_url: String,
    /// Build the authorization URL to redirect the user to.
    /// Parameters: config, scopes, state.
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError(e)),
    /// Exchange an authorization code for credentials.
    /// The third parameter is an optional PKCE code verifier.
    exchange_code: fn(Config, String, Option(String)) ->
      Result(Credentials, AuthError(e)),
    /// Fetch user info using the obtained credentials.
    /// Returns #(uid, user_info).
    fetch_user: fn(Credentials) -> Result(#(String, UserInfo), AuthError(e)),
  )
}
```

### Field-by-field breakdown

**`provider: String`** -- A lowercase identifier for this provider. This ends up in the `Auth` record's `provider` field, so your application can distinguish which provider authenticated the user. Use a simple name like `"twitch"`, `"github"`, or `"discord"`.

**`default_scopes: List(String)`** -- The scopes to request when the user has not configured custom scopes. These should be the minimum scopes needed to fetch basic user information. For example, GitHub uses `["user:email"]` and Google uses `["openid", "profile", "email"]`.

**`token_url: String`** -- The full URL of the provider's token endpoint. This is used in two places: by your `exchange_code` function during the callback phase, and by vestibule's built-in `refresh_token` function. Storing it as a field keeps both in sync.

**`authorize_url: fn(Config, List(String), String) -> Result(String, AuthError(e))`** -- Given the application config, resolved scopes, and CSRF state string, return the full authorization URL. Vestibule will append the PKCE parameters after your function returns. You must include `response_type=code`, `client_id`, `redirect_uri`, `scope`, and `state` in the URL.

**`exchange_code: fn(Config, String, Option(String)) -> Result(Credentials, AuthError(e))`** -- Given the config, authorization code, and optional PKCE code verifier, POST to the token endpoint and return parsed `Credentials`. The code verifier will be `Some(verifier)` when PKCE is in use (which is always, in the current implementation).

**`fetch_user: fn(Credentials) -> Result(#(String, UserInfo), AuthError(e))`** -- Given valid credentials, fetch the provider's user info API and return a tuple of `(uid, UserInfo)`. The UID should be the provider's stable unique identifier for the user (e.g., a numeric ID or a `sub` claim).

### The generic error type

`Strategy(e)` is parameterized over `e`, which flows into `AuthError(e)` through the `Custom(e)` variant:

```gleam
pub type AuthError(e) {
  StateMismatch
  CodeExchangeFailed(reason: String)
  UserInfoFailed(reason: String)
  ProviderError(code: String, description: String)
  NetworkError(reason: String)
  ConfigError(reason: String)
  Custom(e)
}
```

Most strategies only use the built-in variants (`CodeExchangeFailed`, `NetworkError`, etc.) and never construct a `Custom` value. In that case, the strategy is polymorphic in `e` -- meaning it works with any error type the caller chooses. This is how all the built-in strategies work: their `strategy()` functions return `Strategy(e)` with a free type variable.

If your provider has domain-specific error conditions that do not fit the built-in variants, you can define your own error type and wrap it with `Custom`:

```gleam
pub type TwitchError {
  ChannelBanned
  InvalidSubscription(tier: String)
}

/// This strategy is no longer polymorphic -- it requires AuthError(TwitchError).
pub fn strategy() -> Strategy(TwitchError) {
  // ...
}
```

The `error.map_custom` function can convert between custom error types if you need to unify strategies with different error types.

## Step-by-Step: Building a Strategy

Let us build a complete Twitch OAuth2 strategy. Twitch uses standard OAuth2 with a few specifics: the authorization and token endpoints live on `id.twitch.tv`, the user info API is on `api.twitch.tv/helix`, and it requires a `Client-Id` header alongside the Bearer token.

### 1. Create the package

Create a new Gleam package:

```bash
mkdir vestibule_twitch
cd vestibule_twitch
gleam new . --name vestibule_twitch
```

Set up `gleam.toml`:

```toml
name = "vestibule_twitch"
version = "0.1.0"
description = "Twitch OAuth strategy for vestibule"
licences = ["MIT"]
gleam = ">= 1.7.0"

[dependencies]
vestibule = ">= 0.1.0 and < 1.0.0"
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_http = ">= 4.3.0 and < 5.0.0"
gleam_httpc = ">= 5.0.0 and < 6.0.0"
gleam_json = ">= 3.1.0 and < 4.0.0"
glow_auth = ">= 1.0.1 and < 2.0.0"

[dev-dependencies]
startest = ">= 0.8.0 and < 1.0.0"
```

Create `src/vestibule_twitch.gleam` -- this single module will hold the entire strategy.

### 2. Implement authorize_url

The `authorize_url` function builds the URL that the user's browser will be redirected to. Twitch's authorization endpoint is `https://id.twitch.tv/oauth2/authorize`.

```gleam
import gleam/option.{type Option, None, Some}
import gleam/string
import gleam/uri

import gleam/http/request
import gleam/httpc

import glow_auth
import glow_auth/authorize_uri
import glow_auth/token_request
import glow_auth/uri/uri_builder

import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials, Credentials}
import vestibule/error.{type AuthError}
import vestibule/strategy.{type Strategy, Strategy}
import vestibule/user_info.{type UserInfo}

fn do_authorize_url(
  config: Config,
  scopes: List(String),
  state: String,
) -> Result(String, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://id.twitch.tv")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
      site: site,
    )
  let url =
    authorize_uri.build(
      client,
      uri_builder.RelativePath("/oauth2/authorize"),
      redirect,
    )
    |> authorize_uri.set_scope(string.join(scopes, " "))
    |> authorize_uri.set_state(state)
    |> authorize_uri.to_code_authorization_uri()
    |> uri.to_string()
  Ok(url)
}
```

Key points:

- Use `glow_auth` to build the URL. It handles `response_type=code`, `client_id`, and `redirect_uri` for you.
- Scopes are space-separated for Twitch (check your provider's documentation).
- The function receives the already-resolved scopes from vestibule, so you do not need to handle the "custom vs default" logic.
- Return `Ok(url)`. Vestibule will append the PKCE `code_challenge` parameters after this.

### 3. Implement exchange_code

The `exchange_code` function POSTs the authorization code to the provider's token endpoint and parses the response into `Credentials`.

```gleam
import gleam/dynamic/decode
import gleam/json

fn do_exchange_code(
  config: Config,
  code: String,
  code_verifier: Option(String),
) -> Result(Credentials, AuthError(e)) {
  let assert Ok(site) = uri.parse("https://id.twitch.tv")
  let assert Ok(redirect) = uri.parse(config.redirect_uri)
  let client =
    glow_auth.Client(
      id: config.client_id,
      secret: config.client_secret,
      site: site,
    )
  let req =
    token_request.authorization_code(
      client,
      uri_builder.RelativePath("/oauth2/token"),
      code,
      redirect,
    )
    |> request.set_header("accept", "application/json")
  let req = append_code_verifier(req, code_verifier)
  case httpc.send(req) {
    Ok(response) -> parse_token_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Twitch token endpoint",
      ))
  }
}

/// Append code_verifier to the form-encoded request body when present.
fn append_code_verifier(
  req: request.Request(String),
  code_verifier: Option(String),
) -> request.Request(String) {
  case code_verifier {
    Some(verifier) -> {
      let body = case req.body {
        "" -> "code_verifier=" <> uri.percent_encode(verifier)
        existing ->
          existing <> "&code_verifier=" <> uri.percent_encode(verifier)
      }
      request.set_body(req, body)
    }
    None -> req
  }
}
```

The PKCE code verifier is appended to the form body. Every existing vestibule strategy uses this same `append_code_verifier` helper pattern.

Now the token response parser:

```gleam
/// Parse a Twitch token exchange response into Credentials.
/// Exported for testing.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  // Check for error response first
  let error_decoder = {
    use error_code <- decode.field("error", decode.string)
    use description <- decode.field("message", decode.string)
    decode.success(#(error_code, description))
  }
  case json.parse(body, error_decoder) {
    Ok(#(code, description)) ->
      Error(error.ProviderError(code: code, description: description))
    _ -> parse_success_token(body)
  }
}

fn parse_success_token(body: String) -> Result(Credentials, AuthError(e)) {
  let decoder = {
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use expires_in <- decode.optional_field(
      "expires_in",
      None,
      decode.optional(decode.int),
    )
    use refresh_token <- decode.optional_field(
      "refresh_token",
      None,
      decode.optional(decode.string),
    )
    use scope <- decode.optional_field("scope", [], decode.list(decode.string))
    decode.success(Credentials(
      token: access_token,
      refresh_token: refresh_token,
      token_type: token_type,
      expires_at: expires_in,
      scopes: scope,
    ))
  }
  case json.parse(body, decoder) {
    Ok(creds) -> Ok(creds)
    _ ->
      Error(error.CodeExchangeFailed(
        reason: "Failed to parse Twitch token response",
      ))
  }
}
```

Note how the error response is checked first. This is a pattern used by every vestibule strategy: try to decode an error object, and only if that fails, try to decode a success object. This avoids ambiguity when the HTTP status is 200 but the body contains an error (which some providers do).

Also note: Twitch returns scopes as a JSON array rather than a space-separated string. This is a provider quirk -- adjust your decoder accordingly.

### 4. Implement fetch_user

The `fetch_user` function calls the provider's user info endpoint and normalizes the response into vestibule's `UserInfo` type.

Twitch's Helix API returns user data at `https://api.twitch.tv/helix/users` and requires both an `Authorization` header and a `Client-Id` header. Since `fetch_user` only receives `Credentials` (not the config), we will need to capture the client ID in a closure. We will handle that in the wiring step.

```gleam
import gleam/dict
import gleam/int
import gleam/list

fn do_fetch_user(
  client_id: String,
  creds: Credentials,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let assert Ok(user_req) = request.to("https://api.twitch.tv/helix/users")
  let user_req =
    user_req
    |> request.set_header("authorization", "Bearer " <> creds.token)
    |> request.set_header("client-id", client_id)
    |> request.set_header("accept", "application/json")
  case httpc.send(user_req) {
    Ok(response) -> parse_user_response(response.body)
    Error(_) ->
      Error(error.NetworkError(
        reason: "Failed to connect to Twitch Helix API",
      ))
  }
}

/// Parse a Twitch /helix/users response into a uid and UserInfo.
/// Exported for testing.
pub fn parse_user_response(
  body: String,
) -> Result(#(String, UserInfo), AuthError(e)) {
  let user_decoder = {
    use id <- decode.field("id", decode.string)
    use login <- decode.field("login", decode.string)
    use display_name <- decode.optional_field(
      "display_name",
      None,
      decode.optional(decode.string),
    )
    use profile_image_url <- decode.optional_field(
      "profile_image_url",
      None,
      decode.optional(decode.string),
    )
    use description <- decode.optional_field(
      "description",
      None,
      decode.optional(decode.string),
    )
    use email <- decode.optional_field(
      "email",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(
      id,
      UserInfo(
        name: display_name,
        email: email,
        nickname: Some(login),
        image: profile_image_url,
        description: description,
        urls: dict.from_list([
          #("twitch_url", "https://twitch.tv/" <> login),
        ]),
      ),
    ))
  }
  let decoder = {
    use users <- decode.field("data", decode.list(user_decoder))
    case users {
      [first, ..] -> decode.success(first)
      [] ->
        decode.success(#(
          "",
          UserInfo(
            name: None,
            email: None,
            nickname: None,
            image: None,
            description: None,
            urls: dict.new(),
          ),
        ))
    }
  }
  case json.parse(body, decoder) {
    Ok(result) -> Ok(result)
    _ ->
      Error(error.UserInfoFailed(
        reason: "Failed to parse Twitch user response",
      ))
  }
}
```

Twitch wraps its response in a `"data"` array, so the decoder must unwrap that first. This kind of response envelope is common across APIs -- adjust your decoder to match your provider's format.

### 5. Wire it all together

Now create the public `strategy()` constructor that assembles all the pieces. Since Twitch's user endpoint requires the client ID, we capture it in the `fetch_user` closure:

```gleam
/// Create a Twitch authentication strategy.
///
/// The `client_id` parameter is needed because Twitch's Helix API
/// requires a Client-Id header alongside the Bearer token.
pub fn strategy(client_id: String) -> Strategy(e) {
  Strategy(
    provider: "twitch",
    default_scopes: ["user:read:email"],
    token_url: "https://id.twitch.tv/oauth2/token",
    authorize_url: do_authorize_url,
    exchange_code: do_exchange_code,
    fetch_user: fn(creds) { do_fetch_user(client_id, creds) },
  )
}
```

Usage from an application:

```gleam
import vestibule
import vestibule/config
import vestibule_twitch

pub fn start_auth() {
  let twitch_config =
    config.new(
      client_id: "your_client_id",
      client_secret: "your_client_secret",
      redirect_uri: "http://localhost:8080/auth/twitch/callback",
    )
  let strategy = vestibule_twitch.strategy(twitch_config.client_id)
  let assert Ok(auth_request) = vestibule.authorize_url(strategy, twitch_config)
  // Store auth_request.state and auth_request.code_verifier in session
  // Redirect user to auth_request.url
}
```

Most strategies do not need extra parameters in their constructor. GitHub, Google, and Microsoft all have simple `strategy()` functions with no arguments because the Bearer token is sufficient for their user info APIs. Twitch is an example of when you need to close over additional data.

## Common Patterns

### Parsing JSON responses with gleam/dynamic/decode

Every strategy parses JSON at two points: the token response and the user info response. The pattern is consistent across all vestibule strategies:

```gleam
let decoder = {
  use field_a <- decode.field("json_key", decode.string)
  use field_b <- decode.optional_field(
    "optional_key",
    None,
    decode.optional(decode.string),
  )
  decode.success(SomeType(a: field_a, b: field_b))
}
case json.parse(body, decoder) {
  Ok(value) -> Ok(value)
  _ -> Error(error.SomeVariant(reason: "Failed to parse response"))
}
```

Use `decode.field` for required fields and `decode.optional_field` for fields that may be absent. The second argument to `decode.optional_field` is the default value when the field is missing.

### Handling provider-specific error responses

Always check for error responses before trying to parse a success response. Providers return errors in different formats:

```gleam
// Standard OAuth2 error format (GitHub, Google, Microsoft)
// {"error": "invalid_grant", "error_description": "Code expired"}
let error_decoder = {
  use error_code <- decode.field("error", decode.string)
  use description <- decode.field("error_description", decode.string)
  decode.success(#(error_code, description))
}

// Some providers use different field names
// Twitch: {"error": "Unauthorized", "message": "Invalid token"}
let error_decoder = {
  use error_code <- decode.field("error", decode.string)
  use description <- decode.field("message", decode.string)
  decode.success(#(error_code, description))
}
```

Map these into `error.ProviderError(code: code, description: description)`.

### Fetching extra data

Some providers require multiple API calls to get complete user information. GitHub is the canonical example -- the `/user` endpoint does not include the user's email, so the GitHub strategy makes a second request to `/user/emails`:

```gleam
fn do_fetch_user(creds: Credentials) -> Result(#(String, UserInfo), AuthError(e)) {
  // Primary request
  use resp <- result.try(fetch_profile(creds))
  use #(uid, info) <- result.try(parse_user_response(resp.body))

  // Secondary request (best-effort -- don't fail if this errors)
  let email = case fetch_emails(creds) {
    Ok(response) -> parse_primary_email(response.body)
    Error(_) -> None
  }

  let final_info = case email {
    Some(_) -> UserInfo(..info, email: email)
    None -> info
  }

  Ok(#(uid, final_info))
}
```

The secondary request is best-effort: if it fails, the strategy still returns the user info without the email. This is the recommended pattern for supplementary data.

### Scope formatting

Providers disagree on how scopes are formatted:

- **Space-separated** (OAuth2 standard): Google, Microsoft, most OIDC providers
- **Comma-separated**: GitHub (in responses only -- authorization URLs use spaces)
- **JSON array**: Twitch (in token responses)

Handle this in your token response parser:

```gleam
// Space-separated (standard)
scopes: string.split(scope_string, " ")

// Comma-separated (GitHub)
scopes: string.split(scope_string, ",")

// JSON array (Twitch)
use scope <- decode.optional_field("scope", [], decode.list(decode.string))
```

When building the authorization URL, most providers expect space-separated scopes in the query string. Use `string.join(scopes, " ")`.

### Token response parsing

The `Credentials` type has five fields. Map your provider's token response to them:

| Credentials field | Typical JSON key | Notes |
|---|---|---|
| `token` | `access_token` | Always present |
| `refresh_token` | `refresh_token` | Optional -- some providers never return one |
| `token_type` | `token_type` | Usually `"bearer"` or `"Bearer"` |
| `expires_at` | `expires_in` | Seconds until expiry, or `None` |
| `scopes` | `scope` | Parse according to the provider's format |

Note that `expires_at` in the `Credentials` type actually stores the `expires_in` value (seconds from now), not an absolute timestamp. This matches what providers return.

## Publishing as a Hex Package

### Naming convention

Strategy packages follow the naming pattern `vestibule_{provider}`:

- `vestibule_google`
- `vestibule_microsoft`
- `vestibule_twitch`

The main module should also be named `vestibule_{provider}` (e.g., `src/vestibule_twitch.gleam`) so that users import it with:

```gleam
import vestibule_twitch
```

### Dependencies

Your package should depend on `vestibule` for the core types (`Strategy`, `Config`, `Credentials`, `AuthError`, `UserInfo`) plus the HTTP and JSON libraries you need. Do not re-export or duplicate vestibule's types.

A typical dependency set:

```toml
[dependencies]
vestibule = ">= 0.1.0 and < 1.0.0"
gleam_stdlib = ">= 0.48.0 and < 2.0.0"
gleam_http = ">= 4.3.0 and < 5.0.0"
gleam_httpc = ">= 5.0.0 and < 6.0.0"
gleam_json = ">= 3.1.0 and < 4.0.0"
glow_auth = ">= 1.0.1 and < 2.0.0"
```

### Development with a path dependency

While developing, use a path dependency so you can test against the local vestibule source:

```toml
[dependencies]
vestibule = { path = "../vestibule" }
```

Switch to a version constraint before publishing:

```toml
[dependencies]
vestibule = ">= 0.1.0 and < 1.0.0"
```

### gleam.toml setup

```toml
name = "vestibule_twitch"
version = "0.1.0"
description = "Twitch OAuth strategy for vestibule"
licences = ["MIT"]
repository = { type = "github", user = "yourname", repo = "vestibule_twitch" }
gleam = ">= 1.7.0"
```

If you are developing inside the vestibule monorepo (in `packages/`), set the repository path:

```toml
repository = { type = "github", user = "tylerbutler", repo = "vestibule", path = "packages/vestibule_twitch" }
```

### Export parser functions for testing

Make your JSON parsing functions public so they can be unit-tested with mock data. This is the most important testing pattern in vestibule -- every built-in strategy does it:

```gleam
/// Parse a Twitch token exchange response into Credentials.
/// Exported for testing.
pub fn parse_token_response(body: String) -> Result(Credentials, AuthError(e)) {
  // ...
}

/// Parse a Twitch /helix/users response into a uid and UserInfo.
/// Exported for testing.
pub fn parse_user_response(body: String) -> Result(#(String, UserInfo), AuthError(e)) {
  // ...
}
```

## Testing Your Strategy

### Unit testing with mock JSON

The primary testing strategy for vestibule providers is parsing mock JSON responses. Since the HTTP calls cannot be easily mocked in Gleam's Erlang runtime, export your parsing functions and test them directly.

Here is a complete test file for the Twitch strategy:

```gleam
import gleam/dict
import gleam/option.{None, Some}
import startest
import startest/expect
import vestibule/credentials.{Credentials}
import vestibule_twitch

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"access_token\":\"cfabdegwdoklmawdzdo98xt2fo512y\",\"expires_in\":14346,\"refresh_token\":\"eyJfMzUtNDU0OC04MWYwLTQ5MDY5ODY4NGNlMSJ9\",\"scope\":[\"user:read:email\"],\"token_type\":\"bearer\"}"
  vestibule_twitch.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "cfabdegwdoklmawdzdo98xt2fo512y",
      refresh_token: Some("eyJfMzUtNDU0OC04MWYwLTQ5MDY5ODY4NGNlMSJ9"),
      token_type: "bearer",
      expires_at: Some(14346),
      scopes: ["user:read:email"],
    ),
  )
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"Unauthorized\",\"message\":\"Invalid authorization code\"}"
  let _ =
    vestibule_twitch.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn parse_user_response_full_test() {
  let body =
    "{\"data\":[{\"id\":\"44322889\",\"login\":\"dallas\",\"display_name\":\"dallas\",\"profile_image_url\":\"https://static-cdn.jtvnw.net/jtv_user_pictures/dallas-profile.png\",\"description\":\"Just a chill streamer\",\"email\":\"dallas@example.com\"}]}"
  let assert Ok(#(uid, info)) = vestibule_twitch.parse_user_response(body)
  uid |> expect.to_equal("44322889")
  info.name |> expect.to_equal(Some("dallas"))
  info.nickname |> expect.to_equal(Some("dallas"))
  info.email |> expect.to_equal(Some("dallas@example.com"))
  info.image
  |> expect.to_equal(
    Some("https://static-cdn.jtvnw.net/jtv_user_pictures/dallas-profile.png"),
  )
  info.description |> expect.to_equal(Some("Just a chill streamer"))
  info.urls
  |> expect.to_equal(dict.from_list([#("twitch_url", "https://twitch.tv/dallas")]))
}

pub fn parse_user_response_minimal_test() {
  let body =
    "{\"data\":[{\"id\":\"12345\",\"login\":\"testuser\"}]}"
  let assert Ok(#(uid, info)) = vestibule_twitch.parse_user_response(body)
  uid |> expect.to_equal("12345")
  info.name |> expect.to_equal(None)
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(Some("testuser"))
}
```

Test patterns to cover:

- **Token success** with all fields populated
- **Token error** from the provider
- **User info with full data** -- verify all `UserInfo` fields map correctly
- **User info with minimal data** -- verify optional fields default to `None`
- **Malformed JSON** -- verify you get an appropriate error variant back

### Manual testing with the example app

The vestibule repository includes an example wisp application in the `example/` directory. To test your strategy end-to-end:

1. Register an OAuth application with your provider and get a client ID and secret.
2. Add your strategy package as a dependency in `example/gleam.toml`.
3. Add your provider's configuration and strategy to the example app's setup.
4. Run the example app and walk through the full OAuth flow in a browser.

This is the only way to verify that the full redirect-callback cycle works correctly, including PKCE, state validation, and real provider responses.

## Reference: Provider Quirks

A brief catalog of differences across providers that may inform your implementation.

### GitHub

- **Scope separator**: Scopes in token responses are comma-separated (`"user:email,read:org"`), unlike the OAuth2 standard of space-separated. Authorization URL scopes use spaces.
- **Email endpoint**: The `/user` endpoint does not include the user's email. You must make a separate `GET /user/emails` request and find the entry where `primary` and `verified` are both `true`.
- **Refresh tokens**: OAuth Apps do not issue refresh tokens. GitHub Apps do, but they are less common for authentication flows.
- **Token prefix**: Access tokens are prefixed with `gho_` (OAuth) or `ghu_` (user-to-server).

### Google

- **Scope separator**: Space-separated (standard OAuth2). Scopes are full URLs like `https://www.googleapis.com/auth/userinfo.email`.
- **OIDC-compliant**: Supports OpenID Connect discovery, so you can also use vestibule's `oidc.discover("https://accounts.google.com")` instead of the dedicated strategy.
- **Refresh tokens**: Only returned on the first authorization. Subsequent authorizations return only an access token unless you pass `prompt=consent` and `access_type=offline` as extra params.
- **Email verification**: The userinfo response includes `email_verified` as a boolean. The Google strategy only populates `UserInfo.email` when this is `true`.

### Microsoft

- **Multi-tenant**: Uses the `/common` tenant path (`login.microsoftonline.com/common/oauth2/v2.0`) to accept any Microsoft account. Replace `common` with a specific tenant ID to restrict to a single organization.
- **User info API**: Uses the Microsoft Graph API (`graph.microsoft.com/v1.0/me`) rather than a standard OIDC userinfo endpoint. Field names are camelCase (`displayName`, `userPrincipalName`).
- **Avatar fallback**: The Microsoft strategy uses Gravatar hashes as a fallback for profile images since Graph API photo access requires additional permissions.
- **Scope format**: Space-separated, but scopes are permission-style names like `User.Read` rather than URLs.

### Apple

- **JWT client secret**: Apple requires the client secret to be a signed JWT, generated from a private key, team ID, and key ID. This requires additional setup beyond a simple string secret.
- **Response mode**: Uses `response_mode=form_post` -- the callback comes as a POST request with form-encoded body rather than query parameters.
- **Identity token**: Returns user info in a signed JWT identity token rather than providing a userinfo endpoint. You need to decode and verify the JWT to extract user claims.
- **User info on first auth only**: The user's name and email are only included in the first authorization response. Subsequent authorizations only return the `sub` claim.
