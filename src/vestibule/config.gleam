import gleam/dict.{type Dict}

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
