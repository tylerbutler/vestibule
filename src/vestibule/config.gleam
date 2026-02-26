import gleam/dict.{type Dict}
import gleam/result
import vestibule/error.{type AuthError}
import vestibule/url

/// Provider configuration.
pub type Config {
  Config(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: List(String),
    extra_params: Dict(String, String),
  )
}

/// Create a new config with the required fields and empty defaults.
///
/// Validates that `redirect_uri` uses HTTPS (or HTTP with localhost
/// for development). Returns `Error(ConfigError(...))` if the URL
/// scheme is not acceptable.
pub fn new(
  client_id: String,
  client_secret: String,
  redirect_uri: String,
) -> Result(Config, AuthError(e)) {
  use _ <- result.try(
    url.validate_https_url(redirect_uri)
    |> result.map_error(fn(reason) { error.ConfigError(reason: reason) }),
  )
  Ok(Config(
    client_id: client_id,
    client_secret: client_secret,
    redirect_uri: redirect_uri,
    scopes: [],
    extra_params: dict.new(),
  ))
}

/// Set custom scopes, replacing any defaults.
pub fn with_scopes(config: Config, scopes: List(String)) -> Config {
  Config(..config, scopes: scopes)
}

/// Add extra query parameters to the authorization URL.
pub fn with_extra_params(
  config: Config,
  params: List(#(String, String)),
) -> Config {
  Config(..config, extra_params: dict.from_list(params))
}
