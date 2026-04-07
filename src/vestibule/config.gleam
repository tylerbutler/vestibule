import gleam/dict.{type Dict}

/// Provider configuration.
pub opaque type Config {
  Config(
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: List(String),
    extra_params: Dict(String, String),
  )
}

/// Create a new config with the required fields and empty defaults.
pub fn new(
  client_id: String,
  client_secret: String,
  redirect_uri: String,
) -> Config {
  Config(
    client_id: client_id,
    client_secret: client_secret,
    redirect_uri: redirect_uri,
    scopes: [],
    extra_params: dict.new(),
  )
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

/// Return the configured OAuth client ID.
pub fn client_id(config: Config) -> String {
  config.client_id
}

/// Return the configured OAuth client secret.
pub fn client_secret(config: Config) -> String {
  config.client_secret
}

/// Return the redirect URI registered with the provider.
pub fn redirect_uri(config: Config) -> String {
  config.redirect_uri
}

/// Return the configured scopes (empty list means use strategy defaults).
pub fn scopes(config: Config) -> List(String) {
  config.scopes
}

/// Return extra authorization query params that should be appended as-is.
pub fn extra_params(config: Config) -> Dict(String, String) {
  config.extra_params
}
