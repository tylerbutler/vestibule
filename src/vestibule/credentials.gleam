import gleam/option.{type Option}

/// OAuth credentials from the provider.
pub type Credentials {
  Credentials(
    token: String,
    refresh_token: Option(String),
    token_type: String,
    expires_at: Option(Int),
    scopes: List(String),
  )
}
